use super::consts::T1;
use super::key::TsxKey;
use super::{ClientTsx, TsxRegistration, TsxResponse};
use crate::Result;
use crate::error::Error;
use crate::transport::{OutgoingParts, OutgoingRequest, TargetTransportInfo};
use crate::{Endpoint, Request};
use bytes::Bytes;
use sip_types::header::HeaderError;
use sip_types::header::typed::{CSeq, MaxForwards, Via};
use sip_types::msg::RequestLine;
use sip_types::{CodeKind, Headers, Method, Name};
use std::io;
use std::time::{Duration, Instant};
use tokio::time::{timeout, timeout_at};

/// Client INVITE transaction. Used to receives responses to a INVITE request.
///
/// Dropping it prematurely may result in an invalid transaction and it cannot be guaranteed
/// that the peer has received the request, as the transaction is also responsible
/// for retransmitting the original request until a response is received or the
/// timeout is triggered.
// TODO REMOVE TIMEOUT WHEN a provisional response has been received
#[must_use]
#[derive(Debug)]
pub struct ClientInvTsx {
    registration: Option<TsxRegistration>,
    request: OutgoingRequest,
    timeout: Instant,
    state: State,
    cancel_attempted: bool,
}

#[derive(Debug)]
enum State {
    Init,
    Proceeding,
    Accepted,
    Completed,
    Terminated,
}

impl ClientInvTsx {
    /// Internal: Used by [Endpoint::send_invite]
    #[tracing::instrument(
        name = "tsx_inv_send",
        level = "debug",
        skip(endpoint, request, target), fields(%request)
    )]
    pub(crate) async fn send(
        endpoint: Endpoint,
        request: Request,
        target: &mut TargetTransportInfo,
    ) -> Result<Self> {
        assert_eq!(
            request.line.method,
            Method::INVITE,
            "tried to create client invite transaction from {} request",
            request.line.method
        );

        let mut request = endpoint.create_outgoing(request, target).await?;

        let registration = TsxRegistration::create(endpoint, TsxKey::client(&Method::INVITE));

        let via = registration.endpoint.create_via(
            &request.parts.transport,
            &registration.tsx_key,
            target.via_host_port.clone(),
        );

        request.msg.headers.insert_named_front(&via);
        registration
            .endpoint
            .send_outgoing_request(&mut request)
            .await?;

        let timeout = Instant::now() + T1 * 64;

        Ok(Self {
            registration: Some(registration),
            request,
            timeout,
            state: State::Init,
            cancel_attempted: false,
        })
    }

    /// Returns the request the transaction was created from
    pub fn request(&self) -> &OutgoingRequest {
        &self.request
    }

    /// Send a CANCEL for this INVITE transaction.
    ///
    /// RFC 3261 requires CANCEL to retain the INVITE's top Via branch. Reusing
    /// the original outgoing request also preserves its route and transport.
    /// A provisional response (including 100 Trying) must first be processed by
    /// [`Self::receive`], and the INVITE must still be active and unexpired.
    /// Continue receiving INVITE responses independently and drive the returned
    /// [`ClientTsx`] to a final response or error.
    pub async fn cancel(&mut self) -> Result<ClientTsx> {
        if self.cancel_attempted {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "CANCEL already attempted for this INVITE",
            )
            .into());
        }
        if !matches!(self.state, State::Proceeding) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "CANCEL requires a processed provisional response and no final INVITE response",
            )
            .into());
        }
        let registration = self.registration.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "CANCEL requires an active INVITE registration",
            )
        })?;
        if Instant::now() >= self.timeout {
            return Err(Error::RequestTimedOut);
        }
        let request = cancel_request(&self.request.msg)?;

        let mut parts = self.request.parts.clone();
        parts.buffer = Bytes::new();
        let request = OutgoingRequest {
            msg: request,
            parts,
        };
        let endpoint = registration.endpoint.clone();
        let tsx_key = registration.tsx_key.client_with_method(&Method::CANCEL);
        self.cancel_attempted = true;
        ClientTsx::send_with_transaction_key(endpoint, request, tsx_key).await
    }

    /// Receive one or more responses.
    ///
    /// The return type differs from [`ClientTsx::receive`](super::ClientTsx::receive)
    /// as this transaction can return multiple final responses (2XX in this case), due
    /// to INVITE forking. Only once `None` is returned, due to the timeout, is the
    /// INVITE transaction terminated and will no longer be able to receive any responses.
    ///
    /// This behavior SHOULD only apply if an INVITE is sent outside a dialog.
    #[tracing::instrument(name = "tsx_inv_receive", level = "debug", skip(self))]
    pub async fn receive(&mut self) -> Result<Option<TsxResponse>> {
        let registration = match &mut self.registration {
            Some(registration) => registration,
            None => return Ok(None),
        };

        match self.state {
            State::Init if !self.request.parts.transport.is_reliable() => {
                let mut n = T1;

                loop {
                    let receive = timeout(n, registration.receive_response());

                    match timeout_at(self.timeout.into(), receive).await {
                        Ok(Ok(msg)) => return self.handle_msg(msg).await,
                        Ok(Err(_)) => {
                            // retransmit
                            registration
                                .endpoint
                                .send_outgoing_request(&mut self.request)
                                .await?;

                            n *= 2;
                        }
                        Err(_) => return Err(Error::RequestTimedOut),
                    }
                }
            }
            State::Init | State::Proceeding => {
                match timeout_at(self.timeout.into(), registration.receive_response()).await {
                    Ok(msg) => self.handle_msg(msg).await,
                    Err(_) => Err(Error::RequestTimedOut),
                }
            }
            State::Accepted => {
                match timeout_at(self.timeout.into(), registration.receive_response()).await {
                    Ok(msg) => Ok(Some(msg)),
                    Err(_) => {
                        self.state = State::Terminated;
                        Ok(None)
                    }
                }
            }
            State::Completed | State::Terminated => Ok(None),
        }
    }

    async fn handle_msg(&mut self, msg: TsxResponse) -> Result<Option<TsxResponse>> {
        match msg.line.code.kind() {
            CodeKind::Provisional => {
                self.timeout = Instant::now() + T1 * 240; // 2 minutes
                self.state = State::Proceeding;
            }
            CodeKind::Success => {
                self.timeout = Instant::now() + T1 * 64;
                self.state = State::Accepted;
            }
            _ => {
                let mut registration = self.registration.take().expect("already checked");

                let mut ack = create_ack(&self.request, &msg)?;

                registration
                    .endpoint
                    .send_outgoing_request(&mut ack)
                    .await?;

                if self.request.parts.transport.is_reliable() {
                    self.state = State::Terminated;
                } else {
                    self.state = State::Completed;

                    tokio::spawn(async move {
                        let timeout = Instant::now() + Duration::from_secs(32);

                        while timeout_at(timeout.into(), registration.receive())
                            .await
                            .is_ok()
                        {
                            registration
                                .endpoint
                                .send_outgoing_request(&mut ack)
                                .await
                                .ok();
                        }
                    });
                }
            }
        }

        Ok(Some(msg))
    }
}

fn cancel_request(invite: &Request) -> Result<Request> {
    let mut request = invite.clone();
    let invite_cseq = request.headers.get_named::<CSeq>()?;
    // Single-value decoding reads the first raw line and parses its first Via,
    // including when that line contains a comma-separated list.
    let top_via = request.headers.get_named::<Via>()?;

    request.line.method = Method::CANCEL;
    request.body = Bytes::new();
    request.headers.remove(&Name::VIA);
    request.headers.insert_named_front(&top_via);
    request.headers.remove(&Name::CSEQ);
    request.headers.remove(&Name::CONTENT_LENGTH);
    request.headers.remove(&Name::CONTENT_TYPE);
    request.headers.remove(&Name::PROXY_REQUIRE);
    request.headers.remove(&Name::REQUIRE);
    request.headers.insert_named(&CSeq {
        cseq: invite_cseq.cseq,
        method: Method::CANCEL,
    });

    Ok(request)
}

fn create_ack(
    request: &OutgoingRequest,
    response: &TsxResponse,
) -> Result<OutgoingRequest, HeaderError> {
    let mut headers = Headers::with_capacity(5);

    request.msg.headers.clone_into(&mut headers, Name::VIA)?;
    request.msg.headers.clone_into(&mut headers, Name::FROM)?;
    response.headers.clone_into(&mut headers, Name::TO)?;
    request
        .msg
        .headers
        .clone_into(&mut headers, Name::CALL_ID)?;
    headers.insert_named(&MaxForwards(70));

    let cseq = request.msg.headers.get_named::<CSeq>()?;

    headers.insert_named(&CSeq {
        cseq: cseq.cseq,
        method: Method::ACK,
    });

    Ok(OutgoingRequest {
        msg: Request {
            line: RequestLine {
                method: Method::ACK,
                uri: request.msg.line.uri.clone(),
            },
            headers,
            body: Bytes::new(),
        },
        parts: OutgoingParts {
            transport: request.parts.transport.clone(),
            destination: request.parts.destination,
            buffer: Default::default(),
        },
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use sip_types::header::typed::Via;
    use sip_types::host::HostPort;
    use std::net::SocketAddr;
    use tokio::net::UdpSocket;
    use tokio::time::{Duration, timeout};

    #[test]
    fn cancel_retains_the_invite_transaction_identity() {
        let mut invite = Request::new(Method::INVITE, "sip:bob@example.com".parse().unwrap());
        invite.headers.insert_named(&Via::new(
            "UDP",
            "client.example.com:5060".parse::<HostPort>().unwrap(),
            "z9hG4bK-invite-branch",
        ));
        invite.headers.insert_named(&CSeq::new(42, Method::INVITE));
        invite
            .headers
            .insert(Name::ROUTE, "<sip:proxy.example.com;lr>");
        invite.headers.insert(Name::CONTENT_TYPE, "application/sdp");
        invite.headers.insert(Name::REQUIRE, "100rel");
        invite.body = Bytes::from_static(b"v=0\r\n");

        let cancel = cancel_request(&invite).unwrap();
        let cseq = cancel.headers.get_named::<CSeq>().unwrap();

        assert_eq!(cancel.line.method, Method::CANCEL);
        assert_eq!(
            format!("{:?}", cancel.line.uri),
            format!("{:?}", invite.line.uri)
        );
        assert_eq!(cancel.body, Bytes::new());
        assert_eq!(
            cancel.headers.get_raw(&Name::VIA).next().unwrap().as_str(),
            invite.headers.get_raw(&Name::VIA).next().unwrap().as_str()
        );
        assert_eq!(cseq.cseq, 42);
        assert_eq!(cseq.method, Method::CANCEL);
        assert!(cancel.headers.contains(&Name::ROUTE));
        assert!(!cancel.headers.contains(&Name::CONTENT_TYPE));
        assert!(!cancel.headers.contains(&Name::REQUIRE));
    }

    #[test]
    fn cancel_keeps_only_the_first_via() {
        for first in [
            "SIP/2.0/UDP first.example.com;branch=z9hG4bK-first",
            "SIP/2.0/UDP first.example.com;branch=z9hG4bK-first, SIP/2.0/TCP second.example.com;branch=z9hG4bK-second",
        ] {
            let mut invite = Request::new(Method::INVITE, "sip:bob@example.com".parse().unwrap());
            invite.headers.insert(Name::VIA, first);
            invite.headers.insert(
                Name::VIA,
                "SIP/2.0/UDP last.example.com;branch=z9hG4bK-last",
            );
            invite.headers.insert_named(&CSeq::new(42, Method::INVITE));
            let cancel = cancel_request(&invite).unwrap();
            let values = cancel.headers.get_raw(&Name::VIA).collect::<Vec<_>>();
            assert_eq!(values.len(), 1);
            assert_eq!(
                values[0].as_str(),
                "SIP/2.0/UDP first.example.com;branch=z9hG4bK-first"
            );
            assert_eq!(invite.headers.get_raw(&Name::VIA).count(), 2);
        }
    }

    #[tokio::test]
    async fn cancel_completes_after_a_provisional_invite_response() {
        timeout(Duration::from_secs(5), async {
            cancel_scenario("SIP/2.0 180 Ringing", false).await;
            cancel_scenario("SIP/2.0 100 Trying", true).await;
        })
        .await
        .unwrap();
    }

    async fn cancel_scenario(provisional: &str, invite_final_first: bool) {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();

        let mut builder = Endpoint::builder();
        builder
            .bind_udp("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let endpoint = builder.build();
        let target = format!("sip:bob@127.0.0.1:{};transport=udp", peer_addr.port())
            .parse()
            .unwrap();
        let mut target_transport = TargetTransportInfo::default();
        let mut request = Request::new(Method::INVITE, target);
        request
            .headers
            .insert(Name::FROM, "<sip:alice@example.com>;tag=client");
        request.headers.insert(Name::TO, "<sip:bob@example.com>");
        request.headers.insert(Name::CALL_ID, "call-id");
        request.headers.insert(Name::CSEQ, "42 INVITE");
        request
            .headers
            .insert(Name::ROUTE, "<sip:proxy.example.com;lr>");
        request
            .headers
            .insert(Name::CONTENT_TYPE, "application/sdp");
        request.headers.insert(Name::REQUIRE, "100rel");
        request.headers.insert(Name::PROXY_REQUIRE, "extension");
        request
            .headers
            .insert(Name::AUTHORIZATION, "Bearer retained-extension");
        request.body = Bytes::from_static(b"v=0\r\n");

        let mut invite = endpoint
            .send_invite(request, &mut target_transport)
            .await
            .unwrap();
        let (invite_message, client_addr) = receive_message(&peer).await;
        let original_buffer = invite.request.parts.buffer.clone();
        assert_invalid(invite.cancel().await);
        assert!(!invite.cancel_attempted);
        assert_no_message(&peer).await;

        peer.send_to(
            response_for(provisional, &invite_message).as_bytes(),
            client_addr,
        )
        .await
        .unwrap();
        // Merely arriving on the socket is insufficient; receive must process it.
        assert_invalid(invite.cancel().await);
        assert_eq!(
            invite
                .receive()
                .await
                .unwrap()
                .unwrap()
                .line
                .code
                .into_u16(),
            if invite_final_first { 100 } else { 180 }
        );

        // Expiry and construction failure both precede the send-attempt boundary.
        let deadline = invite.timeout;
        invite.timeout = Instant::now() - Duration::from_secs(1);
        assert!(matches!(invite.cancel().await, Err(Error::RequestTimedOut)));
        assert!(!invite.cancel_attempted);
        invite.timeout = deadline;
        invite.request.msg.headers.remove(&Name::CSEQ);
        assert!(invite.cancel().await.is_err());
        assert!(!invite.cancel_attempted);
        invite
            .request
            .msg
            .headers
            .insert_named(&CSeq::new(42, Method::INVITE));
        assert_no_message(&peer).await;

        let original_request = format!("{:?}", invite.request);
        let mut cancel = invite.cancel().await.unwrap();
        let (cancel_message, cancel_source) = receive_message(&peer).await;
        assert_eq!(cancel_source, client_addr);
        assert!(cancel_message.starts_with("CANCEL "));
        assert_eq!(
            header_value(&cancel_message, "Via"),
            header_value(&invite_message, "Via")
        );
        assert_eq!(header_value(&cancel_message, "CSeq"), "42 CANCEL");
        assert_eq!(
            cancel_message
                .lines()
                .next()
                .unwrap()
                .replacen("CANCEL", "INVITE", 1),
            invite_message.lines().next().unwrap()
        );
        for name in ["From", "To", "Call-ID", "Route", "Authorization"] {
            assert_eq!(
                header_value(&cancel_message, name),
                header_value(&invite_message, name)
            );
        }
        assert_eq!(
            cancel_message
                .split("\r\n")
                .filter(|line| line.starts_with("Via:"))
                .count(),
            1
        );
        assert_eq!(header_value(&cancel_message, "Content-Length"), "0");
        assert!(cancel_message.ends_with("\r\n\r\n"));
        for name in ["Require", "Proxy-Require", "Content-Type"] {
            assert!(
                !cancel_message
                    .to_ascii_lowercase()
                    .contains(&format!("\r\n{}:", name.to_ascii_lowercase()))
            );
        }
        assert_eq!(
            cancel.request().parts.destination,
            invite.request.parts.destination
        );
        assert_eq!(invite.request.parts.buffer, original_buffer);
        assert_eq!(format!("{:?}", invite.request), original_request);
        assert_eq!(invite.request.msg.body, Bytes::from_static(b"v=0\r\n"));
        assert_eq!(invite.request.msg.line.method, Method::INVITE);
        assert!(matches!(invite.state, State::Proceeding));
        assert_invalid(invite.cancel().await);
        assert_no_message(&peer).await;

        if invite_final_first {
            finish_invite(&peer, client_addr, &invite_message, &mut invite).await;
            assert_invalid(invite.cancel().await);
        }

        peer.send_to(
            response_for("SIP/2.0 200 OK", &cancel_message).as_bytes(),
            client_addr,
        )
        .await
        .unwrap();
        assert_eq!(
            cancel.receive_final().await.unwrap().line.code.into_u16(),
            200
        );
        assert_invalid(invite.cancel().await);
        drop(cancel);
        assert_invalid(invite.cancel().await);

        if !invite_final_first {
            finish_invite(&peer, client_addr, &invite_message, &mut invite).await;
        }
        assert_invalid(invite.cancel().await);
        assert!(invite.receive().await.unwrap().is_none());
    }

    async fn finish_invite(
        peer: &UdpSocket,
        client_addr: SocketAddr,
        invite_message: &str,
        invite: &mut ClientInvTsx,
    ) {
        peer.send_to(
            response_for("SIP/2.0 487 Request Terminated", invite_message).as_bytes(),
            client_addr,
        )
        .await
        .unwrap();
        assert_eq!(
            invite
                .receive()
                .await
                .unwrap()
                .unwrap()
                .line
                .code
                .into_u16(),
            487
        );

        let (ack_message, _) = receive_message(peer).await;
        assert!(ack_message.starts_with("ACK "));
        assert_eq!(
            header_value(&ack_message, "CSeq"),
            header_value(invite_message, "CSeq").replace("INVITE", "ACK")
        );
    }

    fn assert_invalid(result: Result<ClientTsx>) {
        match result {
            Err(Error::Io(error)) => assert_eq!(error.kind(), io::ErrorKind::InvalidInput),
            other => panic!("expected invalid-input error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn cancel_rejects_terminal_invites_and_dropped_cancel_transactions() {
        timeout(Duration::from_secs(5), async {
            for status in ["SIP/2.0 200 OK", "SIP/2.0 486 Busy Here", "drop-cancel"] {
                let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
                let mut builder = Endpoint::builder();
                builder
                    .bind_udp("127.0.0.1:0".parse().unwrap())
                    .await
                    .unwrap();
                let endpoint = builder.build();
                let mut request = Request::new(
                    Method::INVITE,
                    format!(
                        "sip:bob@127.0.0.1:{};transport=udp",
                        peer.local_addr().unwrap().port()
                    )
                    .parse()
                    .unwrap(),
                );
                request
                    .headers
                    .insert(Name::FROM, "<sip:alice@example.com>;tag=client");
                request.headers.insert(Name::TO, "<sip:bob@example.com>");
                request.headers.insert(Name::CALL_ID, "terminal-call");
                request.headers.insert_named(&CSeq::new(1, Method::INVITE));
                let mut invite = endpoint
                    .send_invite(request, &mut TargetTransportInfo::default())
                    .await
                    .unwrap();
                let (message, client_addr) = receive_message(&peer).await;
                if status == "drop-cancel" {
                    peer.send_to(
                        response_for("SIP/2.0 100 Trying", &message).as_bytes(),
                        client_addr,
                    )
                    .await
                    .unwrap();
                    invite.receive().await.unwrap().unwrap();
                    // Also exercise an inactive registration without consuming the attempt.
                    let registration = invite.registration.take();
                    assert_invalid(invite.cancel().await);
                    assert!(!invite.cancel_attempted);
                    invite.registration = registration;
                    let cancel = invite.cancel().await.unwrap();
                    receive_message(&peer).await;
                    drop(cancel);
                    assert_invalid(invite.cancel().await);
                    assert_no_message(&peer).await;
                    finish_invite(&peer, client_addr, &message, &mut invite).await;
                } else {
                    peer.send_to(response_for(status, &message).as_bytes(), client_addr)
                        .await
                        .unwrap();
                    invite.receive().await.unwrap().unwrap();
                    if status.contains("486") {
                        let (ack, _) = receive_message(&peer).await;
                        assert!(ack.starts_with("ACK "));
                    }
                    assert_invalid(invite.cancel().await);
                    assert!(!invite.cancel_attempted);
                    assert_no_message(&peer).await;
                    if status.contains("200") {
                        invite.timeout = Instant::now() - Duration::from_secs(1);
                    }
                    assert!(invite.receive().await.unwrap().is_none());
                }
                assert_invalid(invite.cancel().await);
            }
        })
        .await
        .unwrap();
    }

    async fn assert_no_message(peer: &UdpSocket) {
        let mut buffer = [0; 4096];
        assert!(
            timeout(Duration::from_millis(20), peer.recv_from(&mut buffer))
                .await
                .is_err()
        );
    }

    async fn receive_message(socket: &UdpSocket) -> (String, SocketAddr) {
        let mut buffer = [0; 4096];
        let (length, source) = timeout(Duration::from_secs(1), socket.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();

        (
            String::from_utf8(buffer[..length].to_vec()).unwrap(),
            source,
        )
    }

    fn response_for(status_line: &str, request: &str) -> String {
        let transaction_headers = request
            .split("\r\n")
            .skip(1)
            .filter(|line| {
                ["via:", "from:", "to:", "call-id:", "cseq:"]
                    .iter()
                    .any(|name| line.to_ascii_lowercase().starts_with(name))
            })
            .collect::<Vec<_>>()
            .join("\r\n");

        format!("{status_line}\r\n{transaction_headers}\r\nContent-Length: 0\r\n\r\n")
    }

    fn header_value<'a>(message: &'a str, name: &str) -> &'a str {
        message
            .split("\r\n")
            .find_map(|line| {
                let (header, value) = line.split_once(':')?;
                header.eq_ignore_ascii_case(name).then_some(value.trim())
            })
            .unwrap()
    }
}
