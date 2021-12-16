use super::key::DialogKey;
use parking_lot::Mutex;
use sip_core::{Endpoint, EndpointBuilder, IncomingRequest, Layer, LayerKey, MayTake, Result};
use sip_types::{Code, Method};
use slotmap::{DefaultKey, SlotMap};
use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info_span, Instrument};

#[async_trait::async_trait]
pub trait Usage: Send + Sync + 'static {
    fn name(&self) -> &'static str;

    async fn receive(&self, endpoint: &Endpoint, request: MayTake<'_, IncomingRequest>);
}

pub(super) struct DialogEntry {
    backlog: BTreeMap<u32, IncomingRequest>,
    next_peer_cseq: u32,
    usages: SlotMap<DefaultKey, Arc<dyn Usage>>,
}

impl DialogEntry {
    pub fn new(peer_cseq: u32) -> Self {
        Self {
            backlog: Default::default(),
            next_peer_cseq: peer_cseq + 1,
            usages: Default::default(),
        }
    }
}

#[derive(Default)]
pub struct DialogLayer {
    pub(super) dialogs: Mutex<HashMap<DialogKey, DialogEntry>>,
}

#[async_trait::async_trait]
impl Layer for DialogLayer {
    fn name(&self) -> &'static str {
        "dialog"
    }

    fn init(&mut self, _: &mut EndpointBuilder) {
        // dialog layers adds no capabilities
    }

    async fn receive(&self, endpoint: &Endpoint, request: MayTake<'_, IncomingRequest>) {
        let key = match DialogKey::from_incoming(&request) {
            Some(key) => key,
            None => {
                // No dialog key, we don't care
                return;
            }
        };

        let (usages, requests) = {
            let mut dialogs = self.dialogs.lock();

            if let Some(dialog_entry) = dialogs.get_mut(&key) {
                let request_cseq = request.base_headers.cseq.cseq;

                match request_cseq.cmp(&dialog_entry.next_peer_cseq) {
                    Ordering::Less => {
                        // CSeq number is lower than expected. ACK requests have the CSeq number of the initial
                        // INVITE request they acknowledge as they are considered part of the transactions,
                        // but on the UA level and thus have their own transaction id.
                        // That is why we warn here if it's not an ACK request
                        if request.line.method != Method::ACK {
                            log::warn!("Incoming request has CSeq number lower than expected.");
                        }

                        (dialog_entry.usages.clone(), vec![request.take()])
                    }
                    Ordering::Equal => {
                        // CSeq number is correct!
                        //
                        // Clone the usage map to unlock the mutex while distributing the message
                        // to the registered usages.
                        let usages = dialog_entry.usages.clone();

                        // Then create requests vector and look if the backlog has any messages
                        // that would come after this one. If found put it in the messages vector
                        // in the correct order and distribute it to the usages as well.
                        let mut requests = vec![request.take()];

                        for next_cseq in request_cseq.. {
                            if let Some(message) = dialog_entry.backlog.remove(&next_cseq) {
                                requests.push(message);
                            } else {
                                break;
                            }
                        }

                        // set the next expected cseq to the one of last message we handle + 1
                        dialog_entry.next_peer_cseq =
                            requests.last().unwrap().base_headers.cseq.cseq + 1;

                        (usages, requests)
                    }
                    Ordering::Greater => {
                        // If its larger than the expected one store it inside the dialog's backlog and return.
                        dialog_entry.backlog.insert(request_cseq, request.take());
                        log::debug!("dialog received a message with cseq value above the expected one, saving it for later");
                        return;
                    }
                }
            } else {
                // No matching dialog entry found
                return;
            }
        };

        log::debug!("message matches {:?}", key);

        for request in requests {
            let mut request = Some(request);

            for usage in usages.values() {
                let span = info_span!("usage", name = %usage.name());

                usage
                    .receive(endpoint, MayTake::new(&mut request))
                    .instrument(span)
                    .await;

                if request.is_none() {
                    return;
                }
            }

            // Requests that not handled by any usage will be handled with some default behavior
            if let Some(request) = request {
                if let Err(e) = self.handle_unwanted_request(endpoint, request).await {
                    log::warn!("failed to respond to unwanted request, {:?}", e);
                }
            }
        }
    }
}

impl DialogLayer {
    async fn handle_unwanted_request(
        &self,
        endpoint: &Endpoint,
        request: IncomingRequest,
    ) -> Result<()> {
        if request.line.method == Method::ACK {
            // Cannot respond to unwanted request
            return Ok(());
        }

        let response = endpoint.create_response(&request, Code::NOT_FOUND, None);

        if request.line.method == Method::INVITE {
            let tsx = endpoint.create_server_inv_tsx(&request);

            tsx.respond_failure(response).await
        } else {
            let tsx = endpoint.create_server_tsx(&request);

            tsx.respond(response).await
        }
    }
}

/// The lifetime of the guard ensures the existence of the
/// usage inside a dialog. When dropped the usage will be
/// removed from the dialog.
#[derive(Debug, Clone)]
pub struct UsageGuard {
    endpoint: Endpoint,
    dialog_layer: LayerKey<DialogLayer>,
    dialog_key: DialogKey,
    usage_key: DefaultKey,
}

impl Drop for UsageGuard {
    fn drop(&mut self) {
        let mut dialogs = self.endpoint[self.dialog_layer].dialogs.lock();

        if let Some(dialog_entry) = dialogs.get_mut(&self.dialog_key) {
            dialog_entry.usages.remove(self.usage_key);
        } else {
            log::warn!("usage dropped after dialog")
        }
    }
}

/// Register the given `usage` inside the dialog with the `dialog_key`
///
/// Returns `Some(Self)` when the usage was successfully registered inside the dialog
pub fn register_usage<U>(
    endpoint: Endpoint,
    dialog_layer: LayerKey<DialogLayer>,
    dialog_key: DialogKey,
    usage: U,
) -> Option<UsageGuard>
where
    U: Usage,
{
    let mut dialogs = endpoint[dialog_layer].dialogs.lock();
    let dialog_entry = dialogs.get_mut(&dialog_key)?;

    let usage_key = dialog_entry.usages.insert(Arc::new(usage));

    drop(dialogs);

    Some(UsageGuard {
        endpoint,
        dialog_layer,
        dialog_key,
        usage_key,
    })
}
