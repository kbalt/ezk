use super::consts::T1;
use super::TsxRegistration;
use crate::transport::OutgoingResponse;
use crate::{Endpoint, IncomingRequest, Result};
use sip_types::{CodeKind, Method};
use std::time::Instant;
use tokio::time::timeout_at;

#[derive(Debug)]
pub struct ServerTsx {
    registration: TsxRegistration,
}

impl ServerTsx {
    pub(crate) fn new(endpoint: Endpoint, request: &IncomingRequest) -> Self {
        assert!(
            !matches!(request.line.method, Method::INVITE | Method::ACK),
            "tried to create server transaction from {} request",
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

    pub async fn respond(mut self, mut response: OutgoingResponse) -> Result<()> {
        assert_ne!(response.msg.line.code.kind(), CodeKind::Provisional);

        self.registration
            .endpoint
            .send_outgoing_response(&mut response)
            .await?;

        if response.msg.line.code.kind() == CodeKind::Provisional {
            Ok(())
        } else {
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
}
