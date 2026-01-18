use std::{error::Error, fmt::Debug, marker::PhantomData};

use sip_core::IncomingRequest;
use sip_types::header::typed::{SubStateValue, SubscriptionState};
use tokio::sync::mpsc;

pub(crate) fn pair<E: SipEvent>() -> (EventSubscriptionState<E>, EventSubscriptionReceiver<E>) {
    let (tx, rx) = mpsc::channel(8);

    (
        EventSubscriptionState {
            tx,
            state: SubStateValue::Pending,
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

        // TODO: handle expires
        self.state = state.state;

        let _ = self.tx.send(notify).await;
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
