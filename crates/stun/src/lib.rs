use parking_lot::Mutex;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use stun_types::parse::ParsedMessage;
use tokio::sync::oneshot;
use tokio::time::timeout;

pub mod auth;

pub trait TransportInfo {
    fn reliable(&self) -> bool;
}

pub struct Request<'r, T> {
    pub bytes: &'r [u8],
    pub tsx_id: u128,
    pub transport: &'r T,
}

pub struct IncomingMessage<T> {
    pub message: ParsedMessage,
    pub source: SocketAddr,
    pub transport: T,
}

/// Defines the "user" of a [`StunEndpoint`].
///
/// It is designed to be somewhat flexible and transport agnostic.
///
/// When using a [`StunEndpoint`] for multiple transports `UserData`
/// can be used to either pass the transport around directly or
/// have just be an identifying key.
#[async_trait::async_trait]
pub trait StunEndpointUser: Send + Sync {
    type Transport: TransportInfo + Send + Sync;

    /// Send the given `bytes` to `target` with the given `transport`.
    async fn send_to(
        &self,
        bytes: &[u8],
        target: &[SocketAddr],
        transport: &Self::Transport,
    ) -> io::Result<()>;

    /// Called by [`StunEndpoint::receive`] when it encounters a message
    /// without a matching transaction id.
    async fn receive(&self, message: IncomingMessage<Self::Transport>);
}

/// Transport agnostic endpoint. Uses [`StunEndpointUser`] to define
/// send/receive behavior.
pub struct StunEndpoint<U: StunEndpointUser> {
    user: U,
    transactions: Mutex<HashMap<u128, Transaction>>,
}

struct Transaction {
    sender: oneshot::Sender<ParsedMessage>,
}

impl<U: StunEndpointUser> StunEndpoint<U> {
    pub fn new(user: U) -> Self {
        Self {
            user,
            transactions: Default::default(),
        }
    }

    pub fn user(&self) -> &U {
        &self.user
    }

    pub fn user_mut(&mut self) -> &mut U {
        &mut self.user
    }

    pub async fn send_request(
        &self,
        request: Request<'_, U::Transport>,
        target: &[SocketAddr],
    ) -> io::Result<Option<ParsedMessage>> {
        struct DropGuard<'s, U>(&'s StunEndpoint<U>, u128)
        where
            U: StunEndpointUser;

        impl<U> Drop for DropGuard<'_, U>
        where
            U: StunEndpointUser,
        {
            fn drop(&mut self) {
                self.0.transactions.lock().remove(&self.1);
            }
        }

        let _guard = DropGuard(self, request.tsx_id);

        let (tx, mut rx) = oneshot::channel();
        self.transactions
            .lock()
            .insert(request.tsx_id, Transaction { sender: tx });

        let mut delta = Duration::from_millis(500);

        if request.transport.reliable() {
            match timeout(delta, &mut rx).await {
                Ok(Ok(response)) => Ok(Some(response)),
                Ok(Err(_)) => unreachable!(),
                Err(_) => Ok(None),
            }
        } else {
            for _ in 0..7 {
                self.user
                    .send_to(request.bytes, target, request.transport)
                    .await?;

                match timeout(delta, &mut rx).await {
                    Ok(Ok(response)) => return Ok(Some(response)),
                    Ok(Err(_)) => unreachable!(),
                    Err(_) => {
                        delta *= 2;
                    }
                }
            }

            Ok(None)
        }
    }

    /// Pass a received STUN message to the endpoint for further processing
    pub async fn receive(
        &self,
        message: ParsedMessage,
        source: SocketAddr,
        transport: U::Transport,
    ) {
        {
            let mut transactions = self.transactions.lock();
            if let Some(Transaction { sender }) = transactions.remove(&message.tsx_id) {
                let _ = sender.send(message);
                return;
            }
        }

        self.user
            .receive(IncomingMessage {
                source,
                message,
                transport,
            })
            .await;
    }
}
