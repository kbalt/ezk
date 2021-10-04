use super::InviteUsage;
use sip_core::{Endpoint, IncomingRequest, MayTake, Result};
use sip_types::header::typed::RAck;
use sip_types::Code;
use tokio::sync::oneshot;

#[derive(Debug)]
pub struct AwaitedPrack {
    /// Channel to send the PRack request to the acceptor
    pub prack_sender: oneshot::Sender<IncomingRequest>,

    /// CSeq of the request the the provisional response belongs to
    pub cseq: u32,

    /// The RAck number expected in the incoming PRACK request
    pub rack: u32,
}

impl InviteUsage {
    pub(super) async fn handle_prack(
        &self,
        endpoint: &Endpoint,
        request: MayTake<'_, IncomingRequest>,
    ) -> Result<()> {
        let (prack, awaited_prack) = {
            let mut awaited_prack_opt = self.inner.awaited_prack.lock();
            if let Some(awaited_prack) = awaited_prack_opt.take() {
                let rack = request.headers.get::<RAck>()?;

                if awaited_prack.rack == rack.rack && awaited_prack.cseq == rack.cseq {
                    (request.take(), awaited_prack)
                } else {
                    *awaited_prack_opt = Some(awaited_prack);
                    return Ok(());
                }
            } else {
                return Ok(());
            }
        };

        let prack_tsx = endpoint.create_server_tsx(&prack);

        let response = endpoint.create_response(&prack, Code::OK, None).await?;

        if awaited_prack.prack_sender.send(prack).is_err() {
            log::error!("prack receiver dropped prematurely");
        }

        prack_tsx.respond(response).await
    }
}
