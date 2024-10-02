// TODO: remove clippy allow
#![allow(clippy::large_enum_variant)]

use super::prack::get_rseq;
use super::session::{Role, Session};
use super::timer::InitiatorTimerConfig;
use super::{Inner, InviteLayer, InviteSessionState, InviteUsage};
use crate::dialog::{ClientDialogBuilder, Dialog, DialogLayer};
use bytesstr::BytesStr;
use parking_lot as pl;
use sip_core::transaction::{ClientInvTsx, TsxResponse};
use sip_core::{Endpoint, Error, LayerKey, Request};
use sip_types::header::typed::{Contact, RSeq, Refresher, Supported};
use sip_types::header::HeaderError;
use sip_types::uri::{NameAddr, Uri};
use sip_types::{Method, Name};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

#[derive(Debug)]
pub enum Response {
    Provisional(TsxResponse),
    Failure(TsxResponse),
    Early(Early, TsxResponse, Option<RSeq>),
    Session(Session, TsxResponse),
    Finished,
}

#[derive(Debug)]
pub struct Initiator {
    dialog_builder: ClientDialogBuilder,

    transaction: Option<ClientInvTsx>,

    /// Mapping of to-tags to early dialogs created
    ///
    /// Early dialogs are created by provisional responses with a to-tag.
    /// They still need to be able to receive their respective responses
    /// from the main INVITE transaction. Responses inside an early dialog
    /// will be forwarded using the channel.
    early_list: Vec<(BytesStr, mpsc::Sender<EarlyEvent>)>,

    pub support_timer: bool,
    pub support_100rel: bool,

    pub timer_config: InitiatorTimerConfig,

    invite_layer: LayerKey<InviteLayer>,
}

impl Initiator {
    pub fn new(
        endpoint: Endpoint,
        dialog_layer: LayerKey<DialogLayer>,
        invite_layer: LayerKey<InviteLayer>,
        local_addr: NameAddr,
        local_contact: Contact,
        target: Box<dyn Uri>,
    ) -> Self {
        let dialog =
            ClientDialogBuilder::new(endpoint, dialog_layer, local_addr, local_contact, target);

        Self {
            dialog_builder: dialog,
            transaction: None,
            early_list: vec![],
            support_timer: true,
            support_100rel: true,
            timer_config: InitiatorTimerConfig {
                expires_secs: None,
                refresher: Refresher::Unspecified,
                expires_secs_min: 90,
            },
            invite_layer,
        }
    }

    pub fn create_invite(&mut self) -> Request {
        let mut request = self.dialog_builder.create_request(Method::INVITE);

        if self.support_100rel {
            let prov_rel_str = BytesStr::from_static("100rel");
            request.headers.insert_named(&Supported(prov_rel_str));
        }

        if self.support_timer {
            let timer_str = BytesStr::from_static("timer");
            request.headers.insert_named(&Supported(timer_str));

            self.timer_config.populate_request(&mut request);
        }

        request
    }

    pub fn create_cancel(&mut self) -> Request {
        let mut request = self.dialog_builder.create_request(Method::CANCEL);

        if self.support_100rel {
            let prov_rel_str = BytesStr::from_static("100rel");
            request.headers.insert_named(&Supported(prov_rel_str));
        }

        if self.support_timer {
            let timer_str = BytesStr::from_static("timer");
            request.headers.insert_named(&Supported(timer_str));

            self.timer_config.populate_request(&mut request);
        }

        request
    }

    pub async fn send_invite(&mut self, request: Request) -> Result<(), sip_core::Error> {
        let transaction = self
            .dialog_builder
            .endpoint
            .send_invite(request, &mut self.dialog_builder.target_tp_info)
            .await?;

        self.transaction = Some(transaction);

        Ok(())
    }

    pub async fn send_cancel(&mut self, request: Request) -> Result<(), sip_core::Error> {
        self.transaction
            .as_ref()
            .expect("must send cancel after create transaction")
            .cancel(request, &mut self.dialog_builder.target_tp_info)
            .await;
        Ok(())
    }

    pub fn transaction(&self) -> Option<&ClientInvTsx> {
        self.transaction.as_ref()
    }

    pub async fn receive(&mut self) -> Result<Response, Error> {
        let transaction = self
            .transaction
            .as_mut()
            .expect("must send invite before calling receive");

        loop {
            let response = match transaction.receive().await? {
                Some(response) => response,
                None => return Ok(Response::Finished),
            };

            let code = response.line.code.into_u16();

            if code <= 100 {
                // 100 Trying, cannot create dialog - just return
                return Ok(Response::Provisional(response));
            }

            if code >= 300 {
                for (_, early) in self.early_list.drain(..) {
                    if early.send(EarlyEvent::Terminate).await.is_err() {
                        log::warn!(
                            "failed to forward termination event, receiver of early dropped"
                        );
                    }
                }

                return Ok(Response::Failure(response));
            }

            // Verify that there's a to-tag set
            let Some(to_tag) = response.base_headers.to.tag.as_ref() else {
                log::warn!("Cannot handle success response without To-tag, ignoring");
                continue;
            };

            // Check if the response is part of any early dialog
            if let Some((_, tx)) = self.early_list.iter().find(|(tag, _)| tag == to_tag) {
                // Found a early dialog for the tag, forward
                tx.send(EarlyEvent::Response(response))
                    .await
                    .expect("failed to forward response, early dropped");

                continue;
            }

            match code {
                101..=199 => {
                    if !response.headers.contains(&Name::CONTACT) {
                        // Cannot create an early dialog when the contact is missing
                        return Ok(Response::Provisional(response));
                    }

                    let early = self.create_early_dialog(&response)?;

                    let rseq = get_rseq(&response);

                    return Ok(Response::Early(early, response, rseq));
                }
                200..=299 => {
                    let session = self.create_session(&response)?;

                    return Ok(Response::Session(session, response));
                }
                _ => unreachable!(),
            }
        }
    }

    fn create_early_dialog(&mut self, response: &TsxResponse) -> Result<Early, HeaderError> {
        let dialog = self.dialog_builder.create_dialog_from_response(response)?;

        let to_tag = dialog.peer_fromto.tag.clone().unwrap();

        let (tx, response_rx) = mpsc::channel(4);

        self.early_list.push((to_tag, tx));

        Ok(Early {
            endpoint: self.dialog_builder.endpoint.clone(),
            dialog: Some(dialog),
            response_rx,
            timer_config: self.timer_config,
            invite_layer: self.invite_layer,
        })
    }

    fn create_session(&mut self, response: &TsxResponse) -> Result<Session, HeaderError> {
        let dialog = self.dialog_builder.create_dialog_from_response(response)?;

        let (evt_sink, usage_events) = mpsc::channel(4);

        let supported = response
            .headers
            .get_named::<Vec<Supported>>()
            .unwrap_or_default();

        let peer_supports_timer = supported.iter().any(|ext| ext.0 == "timer");
        let peer_supports_100rel = supported.iter().any(|ext| ext.0 == "100rel");

        let inner = Arc::new(Inner {
            invite_layer: self.invite_layer,
            state: Mutex::new(InviteSessionState::Established { evt_sink }),
            peer_supports_timer,
            peer_supports_100rel,
            awaited_ack: pl::Mutex::new(None),
            awaited_prack: pl::Mutex::new(None),
        });

        let usage_guard = dialog.register_usage(InviteUsage {
            inner: inner.clone(),
        });

        let session_timer = self.timer_config.create_timer_from_response(response)?;

        Ok(Session::new(
            self.dialog_builder.endpoint.clone(),
            inner,
            Role::Uac,
            usage_events,
            session_timer,
            usage_guard,
            dialog,
        ))
    }
}

#[derive(Debug)]
enum EarlyEvent {
    Response(TsxResponse),
    Terminate,
}

#[derive(Debug)]
pub struct Early {
    endpoint: Endpoint,
    dialog: Option<Dialog>,

    response_rx: mpsc::Receiver<EarlyEvent>,

    timer_config: InitiatorTimerConfig,

    invite_layer: LayerKey<InviteLayer>,
}

#[derive(Debug)]
pub enum EarlyResponse {
    Provisional(TsxResponse, Option<RSeq>),
    Success(Session, TsxResponse),
    Terminated,
}

impl Early {
    pub async fn receive(&mut self) -> Result<EarlyResponse, Error> {
        let dialog = self.dialog.as_mut().unwrap();

        match self.response_rx.recv().await.expect("dropped initiator") {
            EarlyEvent::Response(response) => match response.line.code.into_u16() {
                101..=199 => {
                    let rseq = get_rseq(&response);

                    Ok(EarlyResponse::Provisional(response, rseq))
                }
                200..=299 => {
                    let (evt_sink, usage_events) = mpsc::channel(4);

                    let supported = response
                        .headers
                        .get_named::<Vec<Supported>>()
                        .unwrap_or_default();

                    let peer_supports_timer = supported.iter().any(|ext| ext.0 == "timer");
                    let peer_supports_100rel = supported.iter().any(|ext| ext.0 == "100rel");

                    let inner = Arc::new(Inner {
                        invite_layer: self.invite_layer,
                        state: Mutex::new(InviteSessionState::Established { evt_sink }),
                        peer_supports_timer,
                        peer_supports_100rel,
                        awaited_ack: pl::Mutex::new(None),
                        awaited_prack: pl::Mutex::new(None),
                    });

                    let usage_guard = dialog.register_usage(InviteUsage {
                        inner: inner.clone(),
                    });

                    let session_timer = self.timer_config.create_timer_from_response(&response)?;

                    let session = Session::new(
                        self.endpoint.clone(),
                        inner,
                        Role::Uac,
                        usage_events,
                        session_timer,
                        usage_guard,
                        self.dialog.take().unwrap(),
                    );

                    Ok(EarlyResponse::Success(session, response))
                }
                _ => unreachable!("initiator only forwards messages with 101..=299 status"),
            },
            EarlyEvent::Terminate => Ok(EarlyResponse::Terminated),
        }
    }
}
