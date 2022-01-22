use crate::account::{AccountId, AccountState};
use parking_lot as pl;
use sip_core::{Endpoint, IncomingRequest, Layer, MayTake};
use slotmap::SlotMap;

#[derive(Default)]
pub struct UserAgentLayer {
    pub(crate) accounts: pl::Mutex<SlotMap<AccountId, AccountState>>,
}

#[async_trait::async_trait]
impl Layer for UserAgentLayer {
    fn name(&self) -> &'static str {
        "ua-layer"
    }

    async fn receive(&self, _endpoint: &Endpoint, _request: MayTake<'_, IncomingRequest>) {}
}
