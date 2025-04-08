// TODO: remove clippy allow
#![allow(clippy::large_enum_variant)]

use super::prack::get_rseq;
use super::session::{InviteSession, Role};
use super::timer::InitiatorTimerConfig;
use super::{Inner, InviteSessionState, InviteUsage};
use crate::dialog::{ClientDialogBuilder, Dialog};
use bytesstr::BytesStr;
use parking_lot as pl;
use sip_core::transaction::{ClientInvTsx, TsxResponse};
use sip_core::transport::OutgoingRequest;
use sip_core::{Endpoint, Error, Request};
use sip_types::header::typed::{Contact, RSeq, Refresher, Supported};
use sip_types::header::HeaderError;
use sip_types::uri::{NameAddr, SipUri};
use sip_types::{Method, Name, StatusCode};
use std::collections::HashMap;
use std::future::poll_fn;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use tokio::sync::{mpsc, Mutex};

#[derive(Debug)]
pub enum Response {
    Provisional(TsxResponse),
    Failure(TsxResponse),
    Early(Early, TsxResponse, Option<RSeq>),
    Session(InviteSession, TsxResponse),
    EarlyEvent,
    Finished,
}

#[derive(Debug)]
pub struct InviteInitiator {
    dialog_builder: ClientDialogBuilder,

    transaction: Option<ClientInvTsx>,

    /// Mapping of to-tags to early dialogs created
    ///
    /// Early dialogs are created by provisional responses with a to-tag.
    /// They still need to be able to receive their respective responses
    /// from the main INVITE transaction. Responses inside an early dialog
    /// will be forwarded using the channel.
    early_list: Vec<(BytesStr, mpsc::Sender<EarlyEvent>)>,

    /// Map of crated sessions and the ACK reques for retransmits if another 200 OK is received
    created_sessions: HashMap<BytesStr, OutgoingRequest>,

    pub support_timer: bool,
    pub support_100rel: bool,

    pub timer_config: InitiatorTimerConfig,
}

impl InviteInitiator {
    pub fn new(
        endpoint: Endpoint,
        local_addr: NameAddr,
        local_contact: Contact,
        target: SipUri,
    ) -> Self {
        let dialog = ClientDialogBuilder::new(endpoint, local_addr, local_contact, target);

        Self {
            dialog_builder: dialog,
            transaction: None,
            early_list: vec![],
            created_sessions: HashMap::new(),
            support_timer: true,
            support_100rel: true,
            timer_config: InitiatorTimerConfig {
                expires_secs: None,
                refresher: Refresher::Unspecified,
                expires_secs_min: 90,
            },
        }
    }

    pub fn create_invite(&mut self) -> Request {
        let mut request = self.dialog_builder.create_request(Method::INVITE);

        if self.support_100rel {
            let prov_rel_str = BytesStr::from_static("100rel");
            request.headers.insert_named(&Supported(prov_rel_str));
        }

        if self.support_timer {
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

    pub async fn cancel(mut self) -> Result<(), sip_core::Error> {
        let request = self.dialog_builder.create_request(Method::CANCEL);

        self.dialog_builder
            .endpoint
            .send_request(request, &mut self.dialog_builder.target_tp_info)
            .await?
            .receive_final()
            .await?;

        loop {
            match self.receive().await? {
                Response::Provisional(_) => {}
                Response::Failure(..) => return Ok(()),
                Response::Early(early, ..) => {
                    early.cancel().await?;
                }
                Response::Session(mut session, ..) => {
                    session.terminate().await?;
                }
                Response::EarlyEvent => {}
                Response::Finished => return Ok(()),
            }
        }
    }

    pub fn transaction(&self) -> Option<&ClientInvTsx> {
        self.transaction.as_ref()
    }

    /// Set the ACK request for a session this initiator returned. This ACK will be retransmitted if a response is received again for the session
    pub fn set_acknowledge(&mut self, session: &InviteSession, ack: OutgoingRequest) {
        self.created_sessions.insert(
            session
                .dialog
                .peer_fromto
                .tag
                .clone()
                .expect("peer From/To header has to have a tag"),
            ack,
        );
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

            // Retransmit ACK if we already created a session with that to-tag
            if let Some(ack) = self.created_sessions.get_mut(to_tag) {
                self.dialog_builder
                    .endpoint
                    .send_outgoing_request(ack)
                    .await?;
                continue;
            }

            // Check if the response is part of any early dialog
            if let Some((_, early)) = self.early_list.iter().find(|(tag, _)| tag == to_tag) {
                // Found a early dialog for the tag, forward
                if early.send(EarlyEvent::Response(response)).await.is_err() {
                    log::warn!("failed to response event, receiver of early dropped");
                }

                return Ok(Response::EarlyEvent);
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
        })
    }

    fn create_session(&mut self, response: &TsxResponse) -> Result<InviteSession, HeaderError> {
        let dialog = self.dialog_builder.create_dialog_from_response(response)?;

        let (evt_sink, usage_events) = mpsc::channel(4);

        let supported = response
            .headers
            .get_named::<Vec<Supported>>()
            .unwrap_or_default();

        let peer_supports_timer = supported.iter().any(|ext| ext.0 == "timer");
        let peer_supports_100rel = supported.iter().any(|ext| ext.0 == "100rel");

        let inner = Arc::new(Inner {
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

        Ok(InviteSession::new(
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
}

#[derive(Debug)]
pub enum EarlyResponse {
    Provisional(TsxResponse, Option<RSeq>),
    Success(InviteSession, TsxResponse),
    Terminated,
}

impl Early {
    pub fn poll_receive(&mut self, cx: &mut Context<'_>) -> Poll<Result<EarlyResponse, Error>> {
        let dialog = self.dialog.as_mut().unwrap();

        match ready!(self.response_rx.poll_recv(cx)).expect("dropped initiator") {
            EarlyEvent::Response(response) => match response.line.code.into_u16() {
                101..=199 => {
                    let rseq = get_rseq(&response);

                    Poll::Ready(Ok(EarlyResponse::Provisional(response, rseq)))
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

                    let session = InviteSession::new(
                        self.endpoint.clone(),
                        inner,
                        Role::Uac,
                        usage_events,
                        session_timer,
                        usage_guard,
                        self.dialog.take().unwrap(),
                    );

                    Poll::Ready(Ok(EarlyResponse::Success(session, response)))
                }
                _ => unreachable!("initiator only forwards messages with 101..=299 status"),
            },
            EarlyEvent::Terminate => Poll::Ready(Ok(EarlyResponse::Terminated)),
        }
    }

    pub async fn receive(&mut self) -> Result<EarlyResponse, Error> {
        poll_fn(|cx| self.poll_receive(cx)).await
    }

    pub async fn cancel(mut self) -> Result<(), Error> {
        let dialog = self.dialog.as_mut().unwrap();

        let request = dialog.create_request(Method::CANCEL);

        let mut target_tp_info = dialog.target_tp_info.lock().await;

        let mut tsx = self
            .endpoint
            .send_request(request, &mut target_tp_info)
            .await?;

        drop(target_tp_info);

        tsx.receive_final().await?;

        loop {
            match self.response_rx.recv().await {
                Some(EarlyEvent::Response(response)) => {
                    if response.line.code == StatusCode::REQUEST_TERMINATED {
                        return Ok(());
                    }
                }
                Some(EarlyEvent::Terminate) => return Ok(()),
                None => return Ok(()),
            }
        }
    }
}
