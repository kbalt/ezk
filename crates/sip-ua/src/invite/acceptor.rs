use super::session::Session;
use super::timer::{AcceptorTimerConfig, SessionTimer};
use super::{AwaitedAck, AwaitedPrack, Inner, InviteLayer};
use crate::dialog::{register_usage, Dialog, DialogLayer, UsageGuard};
use crate::invite::session::Role;
use crate::invite::{InviteSessionState, InviteUsage};
use crate::util::{random_sequence_number, random_string};
use anyhow::anyhow;
use bytesstr::BytesStr;
use parking_lot as pl;
use sip_core::transaction::consts::T1;
use sip_core::transport::OutgoingResponse;
use sip_core::{Endpoint, Error, IncomingRequest, LayerKey, Result, WithStatus};
use sip_types::header::typed::{Contact, RSeq, Require, Routing, Supported};
use sip_types::{Code, Method, Name};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::timeout;

#[derive(Debug, thiserror::Error)]
#[error("invite got cancelled")]
pub struct Cancelled;

pub struct Acceptor {
    endpoint: Endpoint,
    inner: Arc<Inner>,
    cancellable_key: CancellableKey,
    usage_guard: Option<UsageGuard>,

    /// Configuration for `timer` extension
    timer_config: AcceptorTimerConfig,
}

impl Drop for Acceptor {
    fn drop(&mut self) {
        self.endpoint[self.inner.invite_layer]
            .cancellables
            .lock()
            .remove(&self.cancellable_key);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) struct CancellableKey {
    pub cseq: u32,
    pub branch: BytesStr,
}

impl Acceptor {
    pub fn new(
        endpoint: Endpoint,
        dialog_layer: LayerKey<DialogLayer>,
        invite_layer: LayerKey<InviteLayer>,
        mut invite: IncomingRequest,
        local_contact: Contact,
    ) -> Result<Self> {
        assert_eq!(
            invite.line.method,
            Method::INVITE,
            "incoming request must be invite"
        );

        // ==== create dialog

        let supported = invite
            .headers
            .get_named::<Vec<Supported>>()
            .unwrap_or_default();

        let peer_supports_timer = supported.iter().any(|ext| ext.0 == "timer");
        let peer_supports_100rel = supported.iter().any(|ext| ext.0 == "100rel");

        let route_set: Vec<Routing> = invite.headers.get(Name::RECORD_ROUTE).unwrap_or_default();

        let peer_contact: Contact = invite.headers.get_named()?;

        if invite.base_headers.from.tag.is_none() {
            return Err(Error {
                status: Code::BAD_REQUEST,
                error: Some(anyhow!("Missing Tag")),
            });
        }

        invite.base_headers.to.tag = Some(random_string());

        let dialog = Dialog::new_server(
            endpoint.clone(),
            dialog_layer,
            invite.base_headers.cseq.cseq,
            invite.base_headers.from.clone(),
            invite.base_headers.to.clone(),
            local_contact,
            peer_contact,
            invite.base_headers.call_id.clone(),
            route_set,
            invite.line.uri.info().secure,
        );

        // ==== register acceptor usage to dialog

        let dialog_key = dialog.key();

        let cancellable_key = CancellableKey {
            cseq: invite.base_headers.cseq.cseq,
            branch: invite.tsx_key.branch().clone(),
        };

        // Create Inner shared state
        let tsx = endpoint.create_server_inv_tsx(&invite);
        let inner = Arc::new(Inner {
            invite_layer,
            state: Mutex::new(InviteSessionState::Provisional {
                dialog,
                tsx,
                invite,
            }),
            peer_supports_timer,
            peer_supports_100rel,
            awaited_ack: pl::Mutex::new(None),
            awaited_prack: pl::Mutex::new(None),
        });

        // Register the usage to the dialog
        let usage_guard = register_usage(
            endpoint.clone(),
            dialog_layer,
            dialog_key,
            InviteUsage {
                inner: inner.clone(),
            },
        )
        // Unwrap is safe as we still hold the dialog
        .unwrap();

        // ==== register Inner to the acceptor layer
        endpoint[invite_layer]
            .cancellables
            .lock()
            .insert(cancellable_key.clone(), inner.clone());

        Ok(Self {
            endpoint,
            inner,
            usage_guard: Some(usage_guard),
            cancellable_key,
            timer_config: AcceptorTimerConfig::default(),
        })
    }

    pub fn peer_supports_100rel(&self) -> bool {
        self.inner.peer_supports_100rel
    }

    pub fn peer_supports_timer(&self) -> bool {
        self.inner.peer_supports_timer
    }

    pub async fn create_response(
        &self,
        code: Code,
        reason: Option<BytesStr>,
    ) -> Result<OutgoingResponse> {
        let state = self.inner.state.lock().await;

        if let InviteSessionState::Provisional { dialog, invite, .. } = &*state {
            dialog.create_response(invite, code, reason).await
        } else {
            Err(Error::new(Code::REQUEST_TERMINATED))
        }
    }

    pub async fn respond_provisional(&mut self, mut response: OutgoingResponse) -> Result<()> {
        let mut state = self.inner.state.lock().await;

        if let InviteSessionState::Provisional { tsx, .. } = &mut *state {
            tsx.respond_provisional(&mut response).await
        } else {
            Err(Error::new(Code::REQUEST_TERMINATED))
        }
    }

    pub async fn respond_provisional_reliable(
        &mut self,
        mut response: OutgoingResponse,
    ) -> Result<IncomingRequest> {
        // Ensure this message can be sent reliably
        assert!(
            self.peer_supports_100rel(),
            "peer does not support provisional reliable responses"
        );

        assert!(
            matches!(response.msg.line.code.into_u16(), 101..=199),
            "response code must be provisional and not 100"
        );

        let mut state = self.inner.state.lock().await;

        if let InviteSessionState::Provisional { tsx, dialog, .. } = &mut *state {
            let rack = random_sequence_number();

            response.msg.headers.insert_named(&Require("100rel".into()));
            response.msg.headers.insert_named(&RSeq(rack));

            let (prack_sender, mut prack_recv) = oneshot::channel();

            *self.inner.awaited_prack.lock() = Some(AwaitedPrack {
                prack_sender,
                cseq: dialog.peer_cseq,
                rack,
            });

            tsx.respond_provisional(&mut response).await?;

            let mut prack = None;
            let mut delta = T1;

            for _ in 1..6 {
                match timeout(delta, &mut prack_recv).await {
                    Ok(res) => {
                        // Unwrap is safe as no other function sets `awaiting_prack`
                        // which means the channel will not be dropped
                        prack = Some(res.unwrap());
                        break;
                    }
                    Err(_) => {
                        // retransmit on timeout
                        tsx.respond_provisional(&mut response).await?;
                        delta = T1 * 2;
                    }
                }
            }

            prack.status(Code::REQUEST_TIMEOUT)
        } else {
            Err(Error::new(Code::REQUEST_TERMINATED))
        }
    }

    pub async fn respond_success(
        mut self,
        mut response: OutgoingResponse,
    ) -> Result<(Session, IncomingRequest)> {
        // Lock the state over the duration of the responding process and
        // while waiting for the ACK. This avoids handling of other
        // requests that assume a completed session.
        let mut state = self.inner.state.lock().await;

        // Set the state as established to get the current state
        let (evt_sink, events) = mpsc::channel(4);
        let res = state.set_established(evt_sink);

        if let Some((dialog, transaction, invite)) = res {
            // We are going to respond with a successful response soon, register the cseq of
            // the initial invite invite `awaited_ack` where it will be used to match the
            // incoming ACK request to this transaction.
            let (ack_sink, ack_recv) = oneshot::channel();
            *self.inner.awaited_ack.lock() = Some(AwaitedAck {
                cseq: invite.base_headers.cseq.cseq,
                ack_sender: ack_sink,
            });

            // If the timer extension support is requested initialize it with the given config
            let session_timer = if self.peer_supports_timer() {
                self.timer_config
                    .on_responding_success(&mut response, &invite)
            } else {
                SessionTimer::new_unsupported()
            };

            let accepted = transaction.respond_success(response).await?;

            let ack = super::receive_ack(accepted, ack_recv).await?;

            let session = Session::new(
                self.endpoint.clone(),
                self.inner.clone(),
                Role::Uas,
                events,
                session_timer,
                self.usage_guard.take().unwrap(),
                dialog,
            );

            Ok((session, ack))
        } else {
            Err(Error::new(Code::REQUEST_TERMINATED))
        }
    }

    pub async fn respond_failure(self, response: OutgoingResponse) -> Result<()> {
        if let Some((_, transaction, _)) = self.inner.state.lock().await.set_cancelled() {
            transaction.respond_failure(response).await
        } else {
            Err(Error::new(Code::REQUEST_TERMINATED))
        }
    }
}
