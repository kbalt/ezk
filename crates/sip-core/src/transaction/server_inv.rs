use crate::transaction::consts::{T1, T2};
use crate::transaction::TsxRegistration;
use crate::transport::OutgoingResponse;
use crate::{Endpoint, IncomingRequest, Result};
use sip_types::msg::MessageLine;
use sip_types::{Code, CodeKind, Method};
use std::io;
use std::time::Instant;
use tokio::time::timeout_at;

#[derive(Debug)]
pub struct ServerInvTsx {
    registration: TsxRegistration,
}

impl ServerInvTsx {
    pub(crate) fn new(endpoint: Endpoint, request: &IncomingRequest) -> Self {
        assert_eq!(
            request.line.method,
            Method::INVITE,
            "tried to create invite transaction from {} request",
            request.line.method
        );

        let registration = TsxRegistration::create(endpoint, request.tsx_key.clone());

        Self { registration }
    }

    pub async fn respond_provisional(&mut self, response: &mut OutgoingResponse) -> Result<()> {
        assert_eq!(response.msg.line.code.kind(), CodeKind::Provisional);

        self.registration
            .endpoint
            .send_outgoing_response(response)
            .await?;

        Ok(())
    }

    pub async fn respond_success(self, mut response: OutgoingResponse) -> Result<Accepted> {
        assert_eq!(response.msg.line.code.kind(), CodeKind::Success);

        self.registration
            .endpoint
            .send_outgoing_response(&mut response)
            .await?;

        Ok(Accepted {
            registration: self.registration,
            response,
        })
    }

    pub async fn respond_failure(mut self, mut response: OutgoingResponse) -> Result<()> {
        assert!(!matches!(
            response.msg.line.code.kind(),
            CodeKind::Provisional | CodeKind::Success
        ));

        // after this instant is over the tsx will time out
        let abandon_retransmit = Instant::now() + T1 * 64;

        // the duration to wait until next retransmit
        let mut retransmit_delta = T1;

        // timestamp for next retransmit
        let mut retransmit = Instant::now() + retransmit_delta;

        // wait for ack and retransmit if necessary
        loop {
            match timeout_at(retransmit.into(), self.registration.receive()).await {
                Ok(inc_msg) => {
                    // two things are allowed to happen here
                    // 1 - the transaction receives a retransmission of the initial invite
                    // 2 - it receives an ACK request which completes the transaction
                    match &inc_msg.line {
                        MessageLine::Request(line) if line.method == Method::INVITE => {
                            // in case of a retransmission,
                            // retransmits the response
                            self.registration
                                .endpoint
                                .send_outgoing_response(&mut response)
                                .await?;
                        }
                        MessageLine::Request(line) if line.method == Method::ACK => {
                            // in case of an ACK the transaction is completed
                            return Ok(());
                        }
                        _ => {
                            // everything else gets ignored
                        }
                    }
                }
                Err(_) => {
                    // retransmit timeout triggered

                    if Instant::now() > abandon_retransmit {
                        bail_status!(Code::REQUEST_TIMEOUT)
                    }

                    // do the retransmit
                    self.registration
                        .endpoint
                        .send_outgoing_response(&mut response)
                        .await?;

                    // increase the wait time until next retransmit
                    retransmit_delta = (retransmit_delta * 2).min(T2);

                    // set next timestamp
                    retransmit = Instant::now() + retransmit_delta;
                }
            }
        }
    }
}

#[must_use]
pub struct Accepted {
    registration: TsxRegistration,
    response: OutgoingResponse,
}

impl Accepted {
    pub async fn retransmit(&mut self) -> io::Result<()> {
        self.registration
            .endpoint
            .send_outgoing_response(&mut self.response)
            .await
    }
}
