use super::consts::T1;
use super::key::TsxKey;
use super::{TsxRegistration, TsxResponse};
use crate::transport::{OutgoingParts, OutgoingRequest};
use crate::Result;
use crate::{Endpoint, Request};
use bytes::Bytes;
use sip_types::header::typed::CSeq;
use sip_types::header::HeaderError;
use sip_types::msg::RequestLine;
use sip_types::{Code, CodeKind, Headers, Method, Name};
use std::time::{Duration, Instant};
use tokio::time::{timeout, timeout_at};

#[derive(Debug)]
struct ClientInvTsxInner {
    registration: TsxRegistration,
    request: OutgoingRequest,
}

// TODO REMOVE TIMEOUT WHEN a provisional response has been received
#[must_use]
#[derive(Debug)]
pub struct ClientInvTsx {
    inner: Option<ClientInvTsxInner>,
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
    #[tracing::instrument(
        name = "tsx_inv_send",
        level = "debug",
        skip(endpoint, request), fields(%request)
    )]
    pub(crate) async fn send(endpoint: Endpoint, request: Request) -> Result<Self> {
        assert_eq!(
            request.line.method,
            Method::INVITE,
            "tried to create client invite transaction from {} request",
            request.line.method
        );

        let mut request = endpoint.create_outgoing(request).await?;

        let registration = TsxRegistration::create(endpoint, TsxKey::client(&Method::INVITE));

        let via = registration
            .endpoint
            .create_via(&request.parts.transport, &registration.tsx_key);

        request.msg.headers.insert_type_front(&via);
        registration
            .endpoint
            .send_outgoing_request(&mut request)
            .await?;

        let timeout = Instant::now() + T1 * 64;

        Ok(Self {
            inner: Some(ClientInvTsxInner {
                registration,
                request,
            }),
            timeout,
            state: State::Init,
        })
    }

    #[tracing::instrument(name = "tsx_inv_receive", level = "debug", skip(self))]
    pub async fn receive(&mut self) -> Result<Option<TsxResponse>> {
        let inner = if let Some(inner) = &mut self.inner {
            inner
        } else {
            return Ok(None);
        };

        match self.state {
            State::Init if !inner.request.parts.transport.reliable() => {
                let mut n = T1;

                loop {
                    let receive = timeout(n, inner.registration.receive_response());

                    match timeout_at(self.timeout.into(), receive).await {
                        Ok(Ok(msg)) => return self.handle_msg(msg).await,
                        Ok(Err(_)) => {
                            // retransmit
                            inner
                                .registration
                                .endpoint
                                .send_outgoing_request(&mut inner.request)
                                .await?;

                            n *= 2;
                        }
                        Err(_) => bail_status!(Code::REQUEST_TIMEOUT),
                    }
                }
            }
            State::Init | State::Proceeding => {
                match timeout_at(self.timeout.into(), inner.registration.receive_response()).await {
                    Ok(msg) => self.handle_msg(msg).await,
                    Err(_) => bail_status!(Code::REQUEST_TIMEOUT),
                }
            }
            State::Accepted => {
                match timeout_at(self.timeout.into(), inner.registration.receive_response()).await {
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
                let mut inner = self.inner.take().expect("already checked");

                let mut ack = create_ack(&inner.request, &msg)?;

                inner
                    .registration
                    .endpoint
                    .send_outgoing_request(&mut ack)
                    .await?;

                if inner.request.parts.transport.reliable() {
                    self.state = State::Terminated;
                } else {
                    self.state = State::Completed;

                    tokio::spawn(async move {
                        let timeout = Instant::now() + Duration::from_secs(32);

                        while timeout_at(timeout.into(), inner.registration.receive())
                            .await
                            .is_ok()
                        {
                            inner
                                .registration
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

    let cseq = request.msg.headers.get::<CSeq>()?;

    headers.insert_type(&CSeq {
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
            destination: request.parts.destination.clone(),
            buffer: Default::default(),
        },
    })
}
