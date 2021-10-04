use crate::transport::MessageTpInfo;
use crate::BaseHeaders;
use bytes::Bytes;
use bytesstr::BytesStr;
use parking_lot::RwLock;
use registration::TsxRegistration;
use sip_types::msg::{MessageLine, StatusLine};
use sip_types::Headers;
use std::collections::HashMap;
use tokio::sync::mpsc::UnboundedSender;

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

#[derive(Default)]
pub(crate) struct Transactions {
    map: RwLock<HashMap<TsxKey, UnboundedSender<TsxMessage>>>,
}

impl Transactions {
    pub fn get_tsx_handler(&self, key: &TsxKey) -> Option<UnboundedSender<TsxMessage>> {
        self.map.read().get(key).cloned()
    }

    pub fn register_transaction(&self, key: TsxKey, sender: UnboundedSender<TsxMessage>) {
        self.map.write().insert(key, sender);
    }

    pub fn remove_transaction(&self, key: &TsxKey) {
        self.map.write().remove(key);
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
    use rand::distributions::Alphanumeric;
    use rand::{thread_rng, Rng};

    consts::RFC3261_BRANCH_PREFIX
        .bytes()
        .chain(thread_rng().sample_iter(Alphanumeric).take(23))
        .map(char::from)
        .collect::<String>()
        .into()
}
