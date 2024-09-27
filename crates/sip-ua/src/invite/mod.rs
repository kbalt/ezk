use crate::dialog::{Dialog, Usage};
use acceptor::CancellableKey;
use parking_lot as pl;
use prack::AwaitedPrack;
use session::UsageEvent;
use sip_core::transaction::consts::{T1, T2};
use sip_core::transaction::{Accepted, ServerInvTsx, TsxKey};
use sip_core::transport::OutgoingRequest;
use sip_core::{
    Endpoint, EndpointBuilder, Error, IncomingRequest, Layer, LayerKey, MayTake, Result,
};
use sip_types::header::typed::CSeq;
use sip_types::{Code, Method};
use std::collections::HashMap;
use std::fmt;
use std::mem::replace;
use std::sync::Arc;
use tokio::sync::mpsc::error::SendError;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::timeout;

pub mod acceptor;
pub mod initiator;
pub mod prack;
pub mod session;
mod timer;

#[derive(Debug)]
struct AwaitedAck {
    cseq: u32,
    ack_sender: oneshot::Sender<IncomingRequest>,
}

/// The shared state which is used by all
/// INVITE objects and usage.
#[derive(Debug)]
struct Inner {
    invite_layer: LayerKey<InviteLayer>,
    state: Mutex<InviteSessionState>,

    peer_supports_timer: bool,
    peer_supports_100rel: bool,

    awaited_ack: pl::Mutex<Option<AwaitedAck>>,
    awaited_prack: pl::Mutex<Option<AwaitedPrack>>,
}

#[allow(clippy::large_enum_variant)]
enum InviteSessionState {
    /// Provisional state before a final response was sent
    UasProvisional {
        dialog: Dialog,
        tsx: ServerInvTsx,
        invite: IncomingRequest,
        on_cancel: Option<Box<dyn FnOnce() + Send + 'static>>,
    },

    /// Cancelled: A CANCEL Request for the invite has been received
    /// aborting the invite-transaction.
    Cancelled,

    /// The session has been established from our point of view. This state holds
    /// a Sender which is used to send requests received inside the
    /// invite-usage to the session-object.
    Established {
        evt_sink: mpsc::Sender<session::UsageEvent>,
    },

    /// The session has received a BYE request and thus can no
    /// longer receive any events
    Terminated,
}

impl fmt::Debug for InviteSessionState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UasProvisional {
                dialog,
                tsx,
                invite,
                on_cancel: _,
            } => f
                .debug_struct("UasProvisional")
                .field("dialog", dialog)
                .field("tsx", tsx)
                .field("invite", invite)
                .finish(),
            Self::Cancelled => write!(f, "Cancelled"),
            Self::Established { evt_sink: _ } => f.debug_struct("Established").finish(),
            Self::Terminated => write!(f, "Terminated"),
        }
    }
}

impl InviteSessionState {
    /// Set the state to Cancelled and return the pending transaction, if the current state is Provisional
    fn set_cancelled(&mut self) -> Option<(Dialog, ServerInvTsx, IncomingRequest)> {
        if matches!(self, InviteSessionState::UasProvisional { .. }) {
            if let InviteSessionState::UasProvisional {
                dialog,
                tsx,
                invite,
                on_cancel,
            } = replace(self, InviteSessionState::Cancelled)
            {
                if let Some(on_cancel) = on_cancel {
                    on_cancel();
                }

                Some((dialog, tsx, invite))
            } else {
                unreachable!()
            }
        } else {
            None
        }
    }

    /// Set the state to Established and return the pending transaction, dialog and initial INVITE,
    /// if the current state is Provisional
    fn set_established(
        &mut self,
        evt_sink: mpsc::Sender<session::UsageEvent>,
    ) -> Option<(Dialog, ServerInvTsx, IncomingRequest)> {
        if matches!(self, InviteSessionState::UasProvisional { .. }) {
            if let InviteSessionState::UasProvisional {
                dialog,
                tsx,
                invite,
                on_cancel: _,
            } = replace(self, InviteSessionState::Established { evt_sink })
            {
                Some((dialog, tsx, invite))
            } else {
                unreachable!()
            }
        } else {
            None
        }
    }

    /// Set the state to Terminated and return last state
    fn set_terminated(&mut self) -> Self {
        replace(self, Self::Terminated)
    }
}

#[derive(Default)]
pub struct InviteLayer {
    cancellables: pl::Mutex<HashMap<CancellableKey, Arc<Inner>>>,
}

#[async_trait::async_trait]
impl Layer for InviteLayer {
    fn name(&self) -> &'static str {
        "invite"
    }

    fn init(&mut self, endpoint: &mut EndpointBuilder) {
        endpoint.add_allow(Method::INVITE);
        endpoint.add_allow(Method::UPDATE);
        endpoint.add_allow(Method::BYE);
        endpoint.add_allow(Method::ACK);
        endpoint.add_allow(Method::CANCEL);
        endpoint.add_allow(Method::PRACK);

        endpoint.add_supported("100rel");
        endpoint.add_supported("timer");
    }

    async fn receive(&self, endpoint: &Endpoint, mut request: MayTake<'_, IncomingRequest>) {
        if let Method::CANCEL = request.line.method {
            if let Err(e) = self
                .handle_cancel(endpoint, MayTake::new(request.inner()))
                .await
            {
                log::error!("Failed to handle CANCEL request {:?}", e);
            }
        }
    }
}

impl InviteLayer {
    async fn handle_cancel(
        &self,
        endpoint: &Endpoint,
        cancel: MayTake<'_, IncomingRequest>,
    ) -> Result<()> {
        let inner = {
            let branch = cancel.tsx_key.branch();

            let mut running = self.cancellables.lock();

            running.remove(&CancellableKey {
                cseq: cancel.base_headers.cseq.cseq,
                branch: branch.clone(),
            })
        };

        // Check if the any matching has been found
        // Transaction found and in progress: respond 200 to cancel and 487 to INVITE
        // Transaction found but completed: respond 200 to cancel
        // No matching transaction: don't handle it, endpoint will respond accordingly
        if let Some(inner) = inner {
            let mut cancel = cancel.take();
            let cancel_tsx = endpoint.create_server_tsx(&mut cancel);

            if let Some((dialog, invite_tsx, invite)) = inner.state.lock().await.set_cancelled() {
                let invite_response =
                    dialog.create_response(&invite, Code::REQUEST_TERMINATED, None)?;

                let cancel_response = dialog.create_response(&cancel, Code::OK, None)?;

                let (r1, r2) = tokio::join!(
                    invite_tsx.respond_failure(invite_response),
                    cancel_tsx.respond(cancel_response)
                );

                r1?;
                r2
            } else {
                // TODO this response is outside the dialog, is that ok?
                let response = endpoint.create_response(&cancel, Code::OK, None);

                cancel_tsx.respond(response).await
            }
        } else {
            Ok(())
        }
    }
}

struct InviteUsage {
    inner: Arc<Inner>,
}

#[async_trait::async_trait]
impl Usage for InviteUsage {
    fn name(&self) -> &'static str {
        "invite-usage"
    }

    async fn receive(&self, endpoint: &Endpoint, mut request: MayTake<'_, IncomingRequest>) {
        match request.line.method {
            Method::INVITE => {
                let state = self.inner.state.lock().await;

                if let InviteSessionState::Established { evt_sink } = &*state {
                    let invite = request.inner().take().unwrap();

                    if let Err(SendError(UsageEvent::ReInvite(invite))) =
                        evt_sink.send(UsageEvent::ReInvite(invite)).await
                    {
                        *request.inner() = Some(invite);
                    }
                }
            }
            Method::ACK => {
                let mut awaited_ack_opt = self.inner.awaited_ack.lock();

                if let Some(awaited_ack) = awaited_ack_opt.take() {
                    if awaited_ack.cseq == request.base_headers.cseq.cseq {
                        let ack = request.inner().take().unwrap();

                        if let Err(ack) = awaited_ack.ack_sender.send(ack) {
                            *request.inner() = Some(ack);
                        }
                    } else {
                        // ACK not expected, put awaited ack back
                        *awaited_ack_opt = Some(awaited_ack);
                    }
                }
            }
            Method::BYE => {
                // TODO respond to BYE with 200 before actually handling it
                let mut state = self.inner.state.lock().await;

                match state.set_terminated() {
                    InviteSessionState::UasProvisional {
                        dialog,
                        tsx,
                        invite,
                        on_cancel: _
                    } => {
                        if let Err(e) = self
                            .handle_bye_in_provisional_state(
                                endpoint,
                                dialog,
                                tsx,
                                invite,
                                request.take(),
                            )
                            .await
                        {
                            log::warn!(
                                "Failed to handle bye request in provisional state: {:?}",
                                e
                            );
                        }
                    }
                    InviteSessionState::Established { evt_sink } => {
                        let bye = request.inner().take().unwrap();

                        if let Err(SendError(UsageEvent::Bye(bye))) =
                            evt_sink.send(UsageEvent::Bye(bye)).await
                        {
                            *request.inner() = Some(bye);
                        }
                    }
                    InviteSessionState::Cancelled | InviteSessionState::Terminated => {
                        // These states don't need to handle BYE requests
                    }
                }
            }
            Method::PRACK if self.inner.peer_supports_100rel => {
                if let Err(e) = self
                    .handle_prack(endpoint, MayTake::new(request.inner()))
                    .await
                {
                    log::warn!("Failed to handle PRACK request {:?}", e);
                }
            }
            _ => {}
        }
    }
}

impl InviteUsage {
    async fn handle_bye_in_provisional_state(
        &self,
        endpoint: &Endpoint,
        dialog: Dialog,
        invite_tsx: ServerInvTsx,
        invite: IncomingRequest,
        mut bye: IncomingRequest,
    ) -> Result<()> {
        let bye_response = dialog.create_response(&invite, Code::OK, None)?;
        let bye_tsx = endpoint.create_server_tsx(&mut bye);

        let invite_response = dialog.create_response(&invite, Code::REQUEST_TERMINATED, None)?;

        let (r1, r2) = tokio::join!(
            invite_tsx.respond_failure(invite_response),
            bye_tsx.respond(bye_response)
        );

        r1?;
        r2
    }
}

pub async fn create_ack(dialog: &Dialog, cseq_num: u32) -> Result<OutgoingRequest> {
    let mut ack = dialog.create_request(Method::ACK);

    // Set CSeq
    ack.headers
        .edit_named(|cseq: &mut CSeq| cseq.cseq = cseq_num)?;

    let mut target_tp_info = dialog.target_tp_info.lock().await;

    let mut ack = dialog
        .endpoint
        .create_outgoing(ack, &mut target_tp_info)
        .await?;

    // Create temporary transaction key to create Via, but never register it
    // as we don't need to receive responses
    let tsx_key = TsxKey::client(&Method::ACK);
    let via = dialog.endpoint.create_via(
        // wrap
        &ack.parts.transport,
        &tsx_key,
        target_tp_info.via_host_port.clone(),
    );

    ack.msg.headers.insert_named_front(&via);

    Ok(ack)
}

/// Helper function to receive the ACK response from invite-usage
/// after sending a success-response
async fn receive_ack(
    mut accepted: Accepted,
    mut ack_recv: oneshot::Receiver<IncomingRequest>,
) -> Result<IncomingRequest> {
    let mut delta = T1;

    for _ in 1..10 {
        match timeout(delta, &mut ack_recv).await {
            Ok(res) => {
                // Unwrap should be safe as there should never be
                // multiple invite transactions
                return Ok(res.unwrap());
            }
            Err(_) => {
                // retransmit on timeout
                accepted.retransmit().await?;
                delta = (T1 * 2).min(T2);
            }
        }
    }

    Err(Error::RequestTimedOut)
}
