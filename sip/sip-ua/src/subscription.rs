use std::{
    error::Error, fmt::Debug, future::pending, marker::PhantomData, pin::Pin, time::Duration,
};

use sip_core::IncomingRequest;
use sip_types::header::typed::{SubStateValue, SubscriptionState};
use tokio::{
    sync::mpsc,
    time::{Sleep, sleep},
};

pub(crate) fn pair<E: SipEvent>() -> (EventSubscriptionState<E>, EventSubscriptionReceiver<E>) {
    let (tx, rx) = mpsc::channel(8);

    (
        EventSubscriptionState {
            tx,
            state: SubStateValue::Pending,
            expiry: None,
            _m: PhantomData,
        },
        EventSubscriptionReceiver {
            rx,
            _m: PhantomData,
        },
    )
}

pub(crate) struct EventSubscriptionState<E> {
    tx: mpsc::Sender<IncomingRequest>,
    state: SubStateValue,
    expiry: Option<Pin<Box<Sleep>>>,
    _m: PhantomData<E>,
}

impl<E: SipEvent> EventSubscriptionState<E> {
    pub(crate) fn state(&self) -> SubStateValue {
        self.state
    }

    pub(crate) async fn handle_notify(&mut self, notify: IncomingRequest) {
        let Ok(state) = notify.headers.get_named::<SubscriptionState>() else {
            return;
        };

        self.state = state.state;

        if let Some(expires_secs) = state.expires {
            self.expiry = Some(Box::pin(sleep(Duration::from_secs(expires_secs.into()))));
        } else {
            self.expiry = None;
        }

        let _ = self.tx.send(notify).await;
    }

    pub(crate) async fn wait_expired(&mut self) {
        if let Some(expiry) = &mut self.expiry {
            expiry.await
        } else {
            pending().await
        }
    }
}

pub struct EventSubscriptionReceiver<E> {
    rx: mpsc::Receiver<IncomingRequest>,
    _m: PhantomData<E>,
}

impl<E: SipEvent> EventSubscriptionReceiver<E> {
    pub async fn recv(&mut self) -> Option<E> {
        while let Some(notify) = self.rx.recv().await {
            match E::from_notify(notify) {
                Ok(event) => return Some(event),
                Err(err) => {
                    log::warn!(
                        "Failed to parse notify to {}, {err:?}",
                        std::any::type_name::<E>()
                    );
                }
            }
        }

        None
    }
}

pub trait SipEvent: Sized {
    type Error: Debug + Error;

    fn from_notify(notify: IncomingRequest) -> Result<Self, Self::Error>;
}
