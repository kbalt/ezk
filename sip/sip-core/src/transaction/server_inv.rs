use crate::error::Error;
use crate::transaction::consts::{T1, T2};
use crate::transaction::TsxRegistration;
use crate::transport::OutgoingResponse;
use crate::{IncomingRequest, Result};
use sip_types::msg::MessageLine;
use sip_types::{CodeKind, Method};
use std::io;
use std::time::Instant;
use tokio::time::timeout_at;

/// Server INVITE transaction. Used to respond to the incoming request.
///
/// Note that the correct functions must be used to send different kinds
/// of responses, as provisional, success and error responses all need
/// different handling.
///
/// Dropping the transaction prematurely can lead to weird/unexpected behavior.
#[derive(Debug)]
pub struct ServerInvTsx {
    registration: TsxRegistration,
}

impl ServerInvTsx {
    /// Internal: Used by [Endpoint::create_server_inv_tsx]
    pub(crate) fn new(request: &mut IncomingRequest) -> Self {
        assert_eq!(
            request.line.method,
            Method::INVITE,
            "tried to create invite transaction from {} request",
            request.line.method
        );

        Self {
            registration: request.take_tsx_registration(),
        }
    }

    /// Respond with a provisional response (1XX)
    ///
    /// # Panics
    /// Panics if the given response is not a provisional response
    pub async fn respond_provisional(&mut self, response: &mut OutgoingResponse) -> Result<()> {
        assert_eq!(response.msg.line.code.kind(), CodeKind::Provisional);

        self.registration
            .endpoint
            .send_outgoing_response(response)
            .await?;

        Ok(())
    }

    /// Respond with a success response (2XX)
    ///
    /// # Returns
    /// The [`Accepted`] struct represents the `Accepted` state of the transactions.
    /// TU is responsible for retransmits of the final success response since TU is the
    /// one receiving the ACK request and not the transaction.
    ///
    /// # Panics
    /// Panics if the given response is not a success response
    pub async fn respond_success(self, mut response: OutgoingResponse) -> Result<Accepted> {
        assert_eq!(response.msg.line.code.kind(), CodeKind::Success);

        // Responding with a success message!
        // Add filter to reject any ACK messages as some implementations seem to re-use the transaction-id for the ACK
        // sent by the UAC.
        self.registration.add_filter(|tsx_msg| !matches!(&tsx_msg.line, MessageLine::Request(line) if line.method == Method::ACK));

        self.registration
            .endpoint
            .send_outgoing_response(&mut response)
            .await?;

        Ok(Accepted {
            registration: self.registration,
            response,
        })
    }

    /// Respond with a failure response (3XX-6XX)
    ///
    /// # Panics
    /// Panics if the given response is not a error response
    pub async fn respond_failure(mut self, mut response: OutgoingResponse) -> Result<()> {
        assert!(!matches!(
            response.msg.line.code.kind(),
            CodeKind::Provisional | CodeKind::Success
        ));

        self.registration
            .endpoint
            .send_outgoing_response(&mut response)
            .await?;

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
                        return Err(Error::RequestTimedOut);
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

/// Represents the `Accepted` state of a transaction. Its used to retransmit the
/// final success response to eventually receive the ACK request from the peer.
#[must_use]
pub struct Accepted {
    registration: TsxRegistration,
    response: OutgoingResponse,
}

impl Accepted {
    /// Retransmit the final response
    pub async fn retransmit(&mut self) -> io::Result<()> {
        self.registration
            .endpoint
            .send_outgoing_response(&mut self.response)
            .await
    }
}
