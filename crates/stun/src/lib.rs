use bytes::Bytes;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use stun_types::attributes::{
    MessageIntegrity, MessageIntegrityKey, MessageIntegritySha256, Realm, Software, Username,
};
use stun_types::builder::MessageBuilder;
use stun_types::header::{Class, Method};
use stun_types::parse::ParsedMessage;
use stun_types::{transaction_id, Error};
use tokio::sync::oneshot;
use tokio::time::timeout;

pub struct IncomingMessage<T>
where
    T: Send + Sync + PartialEq,
{
    pub message: ParsedMessage,
    pub token: T,
}

#[async_trait::async_trait]
pub trait StunEndpointUser: Send + Sync {
    type Token: Clone + Send + Sync + PartialEq;

    async fn send(&self, token: &Self::Token, bytes: &[u8]) -> io::Result<()>;
    async fn receive(&self, message: IncomingMessage<Self::Token>);
}

pub struct StunEndpoint<U>
where
    U: StunEndpointUser,
{
    inner: Arc<Inner<U>>,
}

struct Inner<U>
where
    U: StunEndpointUser,
{
    user: U,
    transactions: Mutex<HashMap<u128, Transaction<U::Token>>>,
}

struct Transaction<T>
where
    T: Send + Sync + PartialEq,
{
    sender: oneshot::Sender<ParsedMessage>,
    token: T,
}

impl<U> StunEndpoint<U>
where
    U: StunEndpointUser,
{
    pub fn new(user: U) -> Self {
        Self {
            inner: Arc::new(Inner {
                user,
                transactions: Default::default(),
            }),
        }
    }

    pub fn user(&self) -> &U {
        &self.inner.user
    }

    pub async fn send_request(
        &self,
        token: U::Token,
        tsx: u128,
        bytes: &[u8],
    ) -> io::Result<Option<ParsedMessage>> {
        struct DropGuard<'s, U>(&'s StunEndpoint<U>, u128)
        where
            U: StunEndpointUser;

        impl<U> Drop for DropGuard<'_, U>
        where
            U: StunEndpointUser,
        {
            fn drop(&mut self) {
                self.0.inner.transactions.lock().remove(&self.1);
            }
        }

        let _guard = DropGuard(self, tsx);

        let (tx, mut rx) = oneshot::channel();
        self.inner.transactions.lock().insert(
            tsx,
            Transaction {
                sender: tx,
                token: token.clone(),
            },
        );

        let mut delta = Duration::from_millis(500);

        // TODO retransmit delta
        for _ in 0..7 {
            self.inner.user.send(&token, bytes).await?;

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

    pub async fn receive(&self, message: ParsedMessage, inc_token: U::Token) {
        {
            let mut transactions = self.inner.transactions.lock();
            if let Some(Transaction { sender, token }) = transactions.remove(&message.tsx_id) {
                if inc_token == token {
                    let _ = sender.send(message);
                    return;
                }
            }
        }

        self.inner
            .user
            .receive(IncomingMessage {
                message,
                token: inc_token,
            })
            .await;
    }
}

pub struct StunAuthSession {}

pub enum StunCredential {
    ShortTerm {
        username: String,
        password: String,
    },
    LongTerm {
        realm: String,
        username: String,
        password: String,
    },
}

impl StunCredential {
    fn auth_msg(&mut self, mut msg: MessageBuilder) -> Result<(), Error> {
        match &*self {
            StunCredential::ShortTerm { username, password } => {
                msg.add_attr(&Username::new(username))?;
                msg.add_attr_with(
                    &MessageIntegritySha256::default(),
                    MessageIntegrityKey::new_short_term(password),
                )?;
                msg.add_attr_with(
                    &MessageIntegrity::default(),
                    MessageIntegrityKey::new_short_term(password),
                )?;

                todo!()
            }
            StunCredential::LongTerm {
                realm,
                username,
                password,
            } => {
                msg.add_attr(&Realm::new(realm))?;
                msg.add_attr(&Username::new(username))?;

                todo!()
            }
        }
    }
}

pub struct StunServerConfig {
    addr: SocketAddr,

    credential: Option<StunCredential>,
}

impl StunServerConfig {
    pub fn new(addr: SocketAddr) -> StunServerConfig {
        Self {
            addr,
            credential: None,
        }
    }

    pub fn with_credential(self, credential: StunCredential) -> Self {
        Self {
            credential: Some(credential),
            ..self
        }
    }
}

pub struct Client {
    server: StunServerConfig,
}

impl Client {
    pub fn new(server: StunServerConfig) -> Self {
        Self { server }
    }

    fn binding_request(&self) -> Bytes {
        let mut message = MessageBuilder::new(Class::Request, Method::Binding, transaction_id());

        message.add_attr(&Software::new("ezk-stun")).unwrap();

        message.finish()
    }
}

#[cfg(test)]
mod test {

    use bytes::BytesMut;
    use stun_types::parse::ParsedMessage;
    use tokio::net::{lookup_host, UdpSocket};

    use super::*;

    #[tokio::test]
    async fn test() {
        let addr = lookup_host("stun.sipgate.net:3478")
            .await
            .unwrap()
            .next()
            .unwrap();

        let client = Client::new(StunServerConfig::new(addr));

        let binding_request = client.binding_request();
        println!("{:02X?}", &binding_request[..]);

        let udp = UdpSocket::bind("0.0.0.0:0").await.unwrap();

        udp.send_to(&binding_request, addr).await.unwrap();

        let mut buf = BytesMut::new();
        buf.resize(65535, 0);

        let (len, remote) = udp.recv_from(&mut buf).await.unwrap();

        buf.truncate(len);

        ParsedMessage::parse(buf).unwrap().unwrap();
    }
}
