//! # Transport Lifetime Management
//!
//! Connection based transports must be closed after some time, when not being referenced
//! anywhere, to not pool up a bunch of connections.
//!
//! When a transport is created it is stored and a reference is returned to the creator.
//! The transport is now available to the entire stack and will stay alive as long as any outside
//! references exist.
//!
//! The cleanup process must be handled by the transport implementation itself. A notifier
//! future is provided which resolves once all references to the transport handle are dropped.
//!
//! The task may now set the state to unused and register a channel
//! to notify whenever the transport was picked up again, to destroy it after some time.
//!
//! Alternatively the transport can also just instantly be destroyed.

use super::{TpHandle, Transport};
use std::future::Future;
use std::mem::replace;
use std::sync::{Arc, Weak};
use tokio::sync::{mpsc, oneshot};

#[derive(Debug, Clone)]

enum Never {}

/// Returns a tuple pair of [`RefOwner`] and its  
pub(crate) fn ref_counter() -> (RefOwner, DropNotifier) {
    let (tx, rx) = mpsc::channel(1);

    (RefOwner(Arc::new(tx)), DropNotifier(rx))
}

#[derive(Debug, Clone)]
pub(crate) struct RefOwner(Arc<mpsc::Sender<Never>>);

impl RefOwner {
    pub(crate) fn downgrade(&self) -> WeakRefOwner {
        WeakRefOwner(Arc::downgrade(&self.0))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct WeakRefOwner(Weak<mpsc::Sender<Never>>);

impl WeakRefOwner {
    pub(crate) fn upgrade(&self) -> Option<RefOwner> {
        self.0.upgrade().map(RefOwner)
    }
}

pub(crate) struct DropNotifier(mpsc::Receiver<Never>);

impl Future for DropNotifier {
    type Output = ();

    fn poll(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Self::Output> {
        self.0.poll_recv(cx).map(|_| ())
    }
}

pub(crate) enum ManagedTransportState {
    Used(WeakRefOwner),
    Unused(oneshot::Sender<DropNotifier>),
}

pub(crate) struct MangedTransport {
    pub transport: Arc<dyn Transport>,
    pub state: ManagedTransportState,
}

impl MangedTransport {
    pub(crate) fn try_get(&mut self) -> Option<TpHandle> {
        match &self.state {
            ManagedTransportState::Used(weak_tx) => {
                let owner = weak_tx.upgrade()?;

                Some(TpHandle {
                    _ref_guard: Some(owner),
                    transport: self.transport.clone(),
                })
            }
            ManagedTransportState::Unused(_) => {
                let (owner, notifier) = ref_counter();

                if let ManagedTransportState::Unused(sender) = replace(
                    &mut self.state,
                    ManagedTransportState::Used(owner.downgrade()),
                ) {
                    sender.send(notifier).ok()?;

                    Some(TpHandle {
                        _ref_guard: Some(owner),
                        transport: self.transport.clone(),
                    })
                } else {
                    unreachable!()
                }
            }
        }
    }
}
