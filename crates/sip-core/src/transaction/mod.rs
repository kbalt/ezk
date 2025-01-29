use crate::transport::MessageTpInfo;
use crate::{BaseHeaders, Endpoint};
use bytes::Bytes;
use bytesstr::BytesStr;
use parking_lot::lock_api::MutexGuard;
use parking_lot::{MappedMutexGuard, Mutex};
use sip_types::msg::{MessageLine, StatusLine};
use sip_types::Headers;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use tokio::sync::mpsc;

mod client;
mod client_inv;
mod key;
mod registration;
mod server;
mod server_inv;

pub mod consts {
    use std::time::Duration;

    pub const T1: Duration = Duration::from_millis(500);
    pub const T2: Duration = Duration::from_secs(4);
    pub const T4: Duration = Duration::from_secs(5);

    pub const RFC3261_BRANCH_PREFIX: &str = "z9hG4bK";
}

pub use client::ClientTsx;
pub use client_inv::ClientInvTsx;
pub use key::TsxKey;
pub use server::ServerTsx;
pub use server_inv::{Accepted, ServerInvTsx};

pub(crate) use registration::TsxRegistration;

pub(crate) type TsxHandler = Box<dyn Fn(TsxMessage) -> Option<TsxMessage> + Send + Sync>;

#[derive(Default)]
pub(crate) struct Transactions {
    map: Mutex<HashMap<TsxKey, TsxHandler>>,
}

impl Transactions {
    pub(crate) fn get_handler<'a: 'k, 'k>(
        &'a self,
        endoint: &Endpoint,
        tsx_key: &TsxKey,
    ) -> Result<MappedMutexGuard<'a, TsxHandler>, TsxRegistration> {
        let map = self.map.lock();

        let mut map = match MutexGuard::try_map(map, |map| map.get_mut(tsx_key)) {
            Ok(handler) => return Ok(handler),
            Err(map) => map,
        };

        let (sender, receiver) = mpsc::unbounded_channel();

        map.insert(
            tsx_key.clone(),
            Box::new(move |msg| sender.send(msg).map_err(|e| e.0).err()),
        );

        Err(TsxRegistration {
            endpoint: endoint.clone(),
            tsx_key: tsx_key.clone(),
            receiver,
        })
    }

    pub(crate) fn register_transaction(&self, key: TsxKey, handler: TsxHandler) {
        let mut map = self.map.lock();

        match map.entry(key) {
            Entry::Occupied(e) => panic!("Tried to create a second transaction for {:?}", e.key()),
            Entry::Vacant(e) => {
                e.insert(handler);
            }
        }
    }

    pub(crate) fn remove_transaction(&self, key: &TsxKey) {
        self.map.lock().remove(key);
    }
}

/// Response received inside a transaction
#[derive(Debug)]
pub struct TsxResponse {
    pub tp_info: MessageTpInfo,

    pub line: StatusLine,
    pub base_headers: BaseHeaders,
    pub headers: Headers,
    pub body: Bytes,
}

/// Message received inside a transaction context
#[derive(Debug)]
pub struct TsxMessage {
    pub tp_info: MessageTpInfo,

    pub line: MessageLine,
    pub base_headers: BaseHeaders,
    pub headers: Headers,
    pub body: Bytes,
}

fn generate_branch() -> BytesStr {
    use rand::distr::Alphanumeric;
    use rand::{rng, Rng};

    consts::RFC3261_BRANCH_PREFIX
        .bytes()
        .chain(rng().sample_iter(Alphanumeric).take(23))
        .map(char::from)
        .collect::<String>()
        .into()
}
