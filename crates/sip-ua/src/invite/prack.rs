use super::InviteUsage;
use crate::dialog::Dialog;
use sip_core::transaction::TsxResponse;
use sip_core::{Endpoint, IncomingRequest, MayTake, Request, Result};
use sip_types::header::typed::{RAck, RSeq, Require};
use sip_types::{Code, Method};
use tokio::sync::oneshot;

#[derive(Debug)]
pub(super) struct AwaitedPrack {
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
                let rack = request.headers.get_named::<RAck>()?;

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

        let response = endpoint.create_response(&prack, Code::OK, None);

        if awaited_prack.prack_sender.send(prack).is_err() {
            log::error!("prack receiver dropped prematurely");
        }

        prack_tsx.respond(response).await
    }
}

pub fn get_rseq(response: &TsxResponse) -> Option<RSeq> {
    if let Some(Ok(requires)) = response.headers.try_get_named::<Vec<Require>>() {
        if requires.iter().any(|r| r.0 == "100rel") {
            return response.headers.get_named().ok();
        }
    }

    None
}

pub fn create_prack(dialog: &Dialog, response: &mut TsxResponse, rack: u32) -> Request {
    let mut request = dialog.create_request(Method::PRACK);

    request.headers.insert_named(&RAck {
        rack,
        cseq: response.base_headers.cseq.cseq,
        method: Method::INVITE,
    });

    request
}

pub async fn send_prack(dialog: &Dialog, request: Request) -> Result<TsxResponse, sip_core::Error> {
    let mut target_tp_info = dialog.target_tp_info.lock().await;

    let mut transaction = dialog
        .endpoint
        .send_request(request, &mut target_tp_info)
        .await?;

    drop(target_tp_info);

    transaction.receive_final().await
}
