use super::consts::{T1, T2};
use super::key::TsxKey;
use super::{TsxRegistration, TsxResponse};
use crate::transaction::consts::T4;
use crate::transport::{OutgoingRequest, TpHandle};
use crate::{Endpoint, Request, Result};
use sip_types::host::HostPort;
use sip_types::{Code, CodeKind, Method};
use std::time::Instant;
use tokio::time::{timeout, timeout_at};

#[derive(Debug)]
struct ClientTsxInner {
    registration: TsxRegistration,
    request: OutgoingRequest,
}

/// Client non-INVITE transaction. Used to receive responses to a sent request.
///
/// Dropping it prematurely may result in an invalid transaction and it cannot be guaranteed
/// that the peer has received the request, as the transaction is also responsible
/// for retransmitting the original request until a response is received or the
/// timeout is triggered.
#[must_use]
#[derive(Debug)]
pub struct ClientTsx {
    inner: Option<ClientTsxInner>,
    timeout: Instant,
    state: State,
}

#[derive(Debug)]
enum State {
    Init,
    Proceeding,
    Completed,
    Terminated,
}

impl ClientTsx {
    /// Internal: Used by [Endpoint::send_request]
    pub(crate) async fn send(
        endpoint: Endpoint,
        request: Request,
        transport: Option<TpHandle>,
        via_host_port: Option<HostPort>,
    ) -> Result<Self> {
        let method = request.line.method.clone();

        assert!(
            !matches!(method, Method::INVITE | Method::ACK),
            "tried to create client transaction from {} request",
            method
        );

        let mut request = endpoint.create_outgoing(request, transport).await?;

        let registration = TsxRegistration::create(endpoint, TsxKey::client(&method));

        let via = registration.endpoint.create_via(
            &request.parts.transport,
            &registration.tsx_key,
            via_host_port,
        );

        request.msg.headers.insert_named_front(&via);
        registration
            .endpoint
            .send_outgoing_request(&mut request)
            .await?;

        let timeout = Instant::now() + T1 * 64;

        Ok(Self {
            inner: Some(ClientTsxInner {
                registration,
                request,
            }),
            timeout,
            state: State::Init,
        })
    }

    /// Receive one or more responses
    ///
    /// Must be called until a final response or error is returned.
    ///
    /// # Panics
    /// After receiving the final response this function will panic if called again.
    /// This is due to it needing to move out some internal state to a new task.
    pub async fn receive(&mut self) -> Result<TsxResponse> {
        let inner = if let Some(inner) = &mut self.inner {
            inner
        } else {
            // TODO: This is not a nice API :/
            panic!("transaction already received a final response");
        };

        let registration = &mut inner.registration;

        match self.state {
            State::Init if !inner.request.parts.transport.reliable() => {
                loop {
                    let receive = timeout(T2, registration.receive_response());

                    match timeout_at(self.timeout.into(), receive).await {
                        Ok(Ok(msg)) => return self.handle_msg(msg),
                        Ok(Err(_)) => {
                            // retransmit
                            registration
                                .endpoint
                                .send_outgoing_request(&mut inner.request)
                                .await?;
                        }
                        Err(_) => bail_status!(Code::REQUEST_TIMEOUT),
                    }
                }
            }
            State::Init | State::Proceeding => {
                match timeout_at(self.timeout.into(), registration.receive_response()).await {
                    Ok(msg) => self.handle_msg(msg),
                    Err(_) => bail_status!(Code::REQUEST_TIMEOUT),
                }
            }
            State::Completed | State::Terminated => {
                panic!("transaction already received a final response");
            }
        }
    }

    /// Calls [`ClientTsx::receive`] and discards all provisional responses
    /// until it receives the final one, returning it.
    pub async fn receive_final(mut self) -> Result<TsxResponse> {
        loop {
            let response = self.receive().await?;

            if let CodeKind::Provisional = response.line.code.kind() {
                // ignore
                continue;
            }

            return Ok(response);
        }
    }

    fn handle_msg(&mut self, response: TsxResponse) -> Result<TsxResponse> {
        match response.line.code.kind() {
            CodeKind::Provisional => {
                self.state = State::Proceeding;
            }
            _ => {
                let mut inner = self.inner.take().expect("already checked");

                if inner.request.parts.transport.reliable() {
                    self.state = State::Terminated;
                } else {
                    self.state = State::Completed;

                    // TODO can this be handled via tsx-registration instead of spawning a new task
                    tokio::spawn(async move {
                        let timeout = Instant::now() + T4;

                        while timeout_at(timeout.into(), inner.registration.receive())
                            .await
                            .is_ok()
                        {
                            // toss incoming messages, just keep registration alive
                        }
                    });
                }
            }
        }

        Ok(response)
    }
}
