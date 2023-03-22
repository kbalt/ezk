use core::mem::replace;

use super::TsxResponse;
use crate::transaction::key::TsxKey;
use crate::transaction::TsxMessage;
use crate::Endpoint;
use sip_types::msg::MessageLine;
use tokio::sync::mpsc;

/// Internal: Used by every transaction impl to
/// register itself inside an endpoint and receive
/// transactional messages from it
#[derive(Debug)]
pub(crate) struct TsxRegistration {
    pub endpoint: Endpoint,
    pub tsx_key: TsxKey,

    receiver: mpsc::UnboundedReceiver<TsxMessage>,
}

impl TsxRegistration {
    pub(crate) fn create(endpoint: Endpoint, tsx_key: TsxKey) -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();

        endpoint.transactions().register_transaction(
            tsx_key.clone(),
            Box::new(move |msg| sender.send(msg).map_err(|e| e.0).err()),
        );

        Self {
            endpoint,
            tsx_key,
            receiver,
        }
    }

    /// Add a filter to reject certain messages that may be received on the transaction but aren't valid and must be
    /// processed by a higher level layer.
    pub(crate) fn add_filter<F>(&self, filter: F)
    where
        F: Fn(&TsxMessage) -> bool + Send + Sync + 'static,
    {
        let transactions = self.endpoint.transactions();
        let mut tsx_map = transactions.map.write();
        let handler = tsx_map
            .get_mut(&self.tsx_key)
            .expect("registration is responsible of handler lifetime inside endpoint");

        let old_handler = replace(handler, Box::new(|_| unreachable!()));

        *handler = Box::new(move |msg| {
            if filter(&msg) {
                old_handler(msg)
            } else {
                Some(msg)
            }
        });
    }

    pub(crate) async fn receive(&mut self) -> TsxMessage {
        self.receiver
            .recv()
            .await
            .expect("registration is responsible of handler lifetime inside endpoint")
    }

    pub(crate) async fn receive_response(&mut self) -> TsxResponse {
        loop {
            match self.receive().await {
                TsxMessage {
                    line: MessageLine::Request(_),
                    ..
                } => {
                    // TODO warn?
                    continue;
                }
                TsxMessage {
                    tp_info,
                    line: MessageLine::Response(line),
                    base_headers,
                    headers,
                    body,
                } => {
                    return TsxResponse {
                        tp_info,
                        line,
                        base_headers,
                        headers,
                        body,
                    }
                }
            }
        }
    }
}

impl Drop for TsxRegistration {
    fn drop(&mut self) {
        self.endpoint
            .transactions()
            .remove_transaction(&self.tsx_key);
    }
}
