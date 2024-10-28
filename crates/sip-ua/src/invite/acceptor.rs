use super::session::Session;
use super::timer::{AcceptorTimerConfig, SessionTimer};
use super::{AwaitedAck, AwaitedPrack, Inner, InviteLayer};
use crate::dialog::{register_usage, Dialog, UsageGuard};
use crate::invite::session::Role;
use crate::invite::{InviteSessionState, InviteUsage};
use crate::util::random_sequence_number;
use bytesstr::BytesStr;
use parking_lot as pl;
use sip_core::transaction::consts::T1;
use sip_core::transport::OutgoingResponse;
use sip_core::{Endpoint, IncomingRequest, LayerKey, Result};
use sip_types::header::typed::{RSeq, Require, Supported};
use sip_types::{Code, Method};
use std::sync::Arc;
use tokio::sync::{mpsc, oneshot, Mutex};
use tokio::time::timeout;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Core(#[from] sip_core::Error),

    #[error("peer cancelled its request")]
    RequestTerminated,
}

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
        dialog: Dialog,
        invite_layer: LayerKey<InviteLayer>,
        mut invite: IncomingRequest,
        on_cancel: Option<Box<dyn FnOnce() + Send>>,
    ) -> Result<Self> {
        assert_eq!(
            invite.line.method,
            Method::INVITE,
            "incoming request must be invite"
        );

        let endpoint = dialog.endpoint.clone();

        let supported = invite
            .headers
            .get_named::<Vec<Supported>>()
            .unwrap_or_default();

        let peer_supports_timer = supported.iter().any(|ext| ext.0 == "timer");
        let peer_supports_100rel = supported.iter().any(|ext| ext.0 == "100rel");

        // ==== register acceptor usage to dialog

        let dialog_key = dialog.key();

        let cancellable_key = CancellableKey {
            cseq: invite.base_headers.cseq.cseq,
            branch: invite.tsx_key.branch().clone(),
        };

        let dialog_layer = dialog.dialog_layer;

        // Create Inner shared state
        let tsx = endpoint.create_server_inv_tsx(&mut invite);
        let inner = Arc::new(Inner {
            invite_layer,
            state: Mutex::new(InviteSessionState::UasProvisional {
                dialog,
                tsx,
                invite,
                on_cancel,
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
    ) -> Result<OutgoingResponse, Error> {
        let mut state = self.inner.state.lock().await;

        if let InviteSessionState::UasProvisional { dialog, invite, .. } = &mut *state {
            dialog
                .create_response(invite, code, reason)
                .map_err(Error::Core)
        } else {
            Err(Error::RequestTerminated)
        }
    }

    pub async fn respond_provisional(
        &mut self,
        mut response: OutgoingResponse,
    ) -> Result<(), Error> {
        let mut state = self.inner.state.lock().await;

        if let InviteSessionState::UasProvisional { tsx, .. } = &mut *state {
            tsx.respond_provisional(&mut response)
                .await
                .map_err(Error::Core)
        } else {
            Err(Error::RequestTerminated)
        }
    }

    pub async fn respond_provisional_reliable(
        &mut self,
        mut response: OutgoingResponse,
    ) -> Result<IncomingRequest, Error> {
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

        if let InviteSessionState::UasProvisional { tsx, invite, .. } = &mut *state {
            let rack = random_sequence_number();

            response.msg.headers.insert_named(&Require("100rel".into()));
            response.msg.headers.insert_named(&RSeq(rack));

            let (prack_sender, mut prack_recv) = oneshot::channel();

            *self.inner.awaited_prack.lock() = Some(AwaitedPrack {
                prack_sender,
                cseq: invite.base_headers.cseq.cseq,
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

            prack.ok_or(Error::RequestTerminated)
        } else {
            Err(Error::RequestTerminated)
        }
    }

    pub async fn respond_success(
        mut self,
        mut response: OutgoingResponse,
    ) -> Result<(Session, IncomingRequest), Error> {
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

            // Set the dialogs transport target info from the incoming ACK request
            let mut target_tp_info = dialog.target_tp_info.lock().await;
            target_tp_info.transport = Some((ack.tp_info.transport.clone(), ack.tp_info.source));
            drop(target_tp_info);

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
            Err(Error::RequestTerminated)
        }
    }

    pub async fn respond_failure(self, response: OutgoingResponse) -> Result<(), Error> {
        if let Some((_, transaction, _)) = self.inner.state.lock().await.set_cancelled() {
            transaction
                .respond_failure(response)
                .await
                .map_err(Error::Core)
        } else {
            Err(Error::RequestTerminated)
        }
    }
}
