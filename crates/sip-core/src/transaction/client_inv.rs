use super::consts::T1;
use super::key::TsxKey;
use super::{TsxRegistration, TsxResponse};
use crate::error::Error;
use crate::transport::{OutgoingParts, OutgoingRequest, TargetTransportInfo};
use crate::Result;
use crate::{Endpoint, Request};
use bytes::Bytes;
use sip_types::header::typed::CSeq;
use sip_types::header::HeaderError;
use sip_types::msg::RequestLine;
use sip_types::{CodeKind, Headers, Method, Name};
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
        })
    }

    pub async fn cancel(&self, request: Request, target: &mut TargetTransportInfo) {
        let registration = self.registration.as_ref().unwrap();
        let mut request = registration
            .endpoint
            .create_outgoing(request, target)
            .await
            .unwrap();

        let via = registration.endpoint.create_via(
            &request.parts.transport,
            &registration.tsx_key,
            target.via_host_port.clone(),
        );

        request.msg.headers.insert_named_front(&via);
        registration
            .endpoint
            .send_outgoing_request(&mut request)
            .await
            .unwrap();
    }

    /// Returns the request the transaction was created from
    pub fn request(&self) -> &OutgoingRequest {
        &self.request
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
            State::Init if !self.request.parts.transport.reliable() => {
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

                if self.request.parts.transport.reliable() {
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
