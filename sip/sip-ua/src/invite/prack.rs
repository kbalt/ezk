use super::InviteUsage;
use crate::dialog::Dialog;
use sip_core::transaction::TsxResponse;
use sip_core::{Endpoint, IncomingRequest, MayTake, Request, Result};
use sip_types::header::typed::{RAck, RSeq, Require};
use sip_types::{Method, StatusCode};
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
        let (mut prack, awaited_prack) = {
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

        let prack_tsx = endpoint.create_server_tsx(&mut prack);

        let response = endpoint.create_response(&prack, StatusCode::OK, None);

        if awaited_prack.prack_sender.send(prack).is_err() {
            log::error!("prack receiver dropped prematurely");
        }

        prack_tsx.respond(response).await
    }
}

pub fn get_rseq(response: &TsxResponse) -> Option<RSeq> {
    if let Some(Ok(requires)) = response.headers.try_get_named::<Vec<Require>>()
        && requires.iter().any(|r| r.0 == "100rel")
    {
        return response.headers.get_named().ok();
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
