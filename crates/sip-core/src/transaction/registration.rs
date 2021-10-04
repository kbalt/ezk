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
pub struct TsxRegistration {
    pub endpoint: Endpoint,
    pub tsx_key: TsxKey,

    receiver: mpsc::UnboundedReceiver<TsxMessage>,
}

impl TsxRegistration {
    pub fn create(endpoint: Endpoint, tsx_key: TsxKey) -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();

        endpoint
            .transactions()
            .register_transaction(tsx_key.clone(), sender);

        Self {
            endpoint,
            tsx_key,
            receiver,
        }
    }

    pub async fn receive(&mut self) -> TsxMessage {
        self.receiver
            .recv()
            .await
            .expect("registration is responsible of sender lifetime inside endpoint")
    }

    pub async fn receive_response(&mut self) -> TsxResponse {
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
