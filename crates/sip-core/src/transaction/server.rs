use super::consts::T1;
use super::TsxRegistration;
use crate::transport::OutgoingResponse;
use crate::{Endpoint, IncomingRequest, Result};
use sip_types::{CodeKind, Method};
use std::time::Instant;
use tokio::time::timeout_at;

/// Server transaction. Used to respond to the incoming request.
///
/// Note that the correct functions must be used to send different kinds
/// of responses, as provisional and final responses need different handling.
///
/// Dropping the transaction prematurely can lead to weird/unexpected behavior.
#[derive(Debug)]
pub struct ServerTsx {
    registration: TsxRegistration,
}

impl ServerTsx {
    /// Internal: Used by [Endpoint::create_server_tsx]
    pub(crate) fn new(endpoint: Endpoint, request: &IncomingRequest) -> Self {
        assert!(
            !matches!(request.line.method, Method::INVITE | Method::ACK),
            "tried to create server transaction from {} request",
            request.line.method
        );

        let registration = TsxRegistration::create(endpoint, request.tsx_key.clone());

        Self { registration }
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

    /// Respond with a final response (2XX-6XX)
    ///
    /// # Panics
    /// `response` must contain a final status code.
    /// For provisional responses [`ServerTsx::respond_provisional`] must be used.
    pub async fn respond(mut self, mut response: OutgoingResponse) -> Result<()> {
        assert_ne!(
            response.msg.line.code.kind(),
            CodeKind::Provisional,
            "ServerTsx::respond must only be used for final responses, use ServerTsx::respond_provisional instead"
        );

        self.registration
            .endpoint
            .send_outgoing_response(&mut response)
            .await?;

        if response.parts.transport.reliable() {
            return Ok(());
        }

        let abandon = Instant::now() + T1 * 64;

        tokio::spawn(async move {
            while let Ok(msg) = timeout_at(abandon.into(), self.registration.receive()).await {
                if msg.line.is_request() {
                    if let Err(e) = self
                        .registration
                        .endpoint
                        .send_outgoing_response(&mut response)
                        .await
                    {
                        log::warn!("Failed to retransmit message, {}", e);
                    }
                }
            }
        });

        Ok(())
    }
}
