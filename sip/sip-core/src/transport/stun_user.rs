use super::{TpHandle, Transports};
use crate::{Result, StunError};
use std::io;
use std::net::SocketAddr;
use stun::{IncomingMessage, StunEndpointUser};
use stun_types::attributes::{MappedAddress, Software, XorMappedAddress};
use stun_types::{Class, MessageBuilder, Method, TransactionId};

pub struct StunUser;

#[async_trait::async_trait]
impl StunEndpointUser for StunUser {
    type Transport = TpHandle;

    async fn send_to(
        &self,
        bytes: &[u8],
        target: SocketAddr,
        transport: &Self::Transport,
    ) -> io::Result<()> {
        transport.send(bytes, target).await
    }

    async fn receive(&self, _message: IncomingMessage<Self::Transport>) {
        // we ignore messages outside of transactions
    }
}

impl stun::TransportInfo for TpHandle {
    fn reliable(&self) -> bool {
        self.transport.reliable()
    }
}

impl Transports {
    pub async fn discover_public_address(
        &self,
        stun_server: SocketAddr,
        transport: &TpHandle,
    ) -> Result<SocketAddr, StunError> {
        if transport.reliable() {
            return Ok(transport.sent_by());
        }

        let tsx_id = TransactionId::random();

        let mut msg = MessageBuilder::new(Class::Request, Method::Binding, tsx_id);
        msg.add_attr(Software::new("ezk"));
        let bytes = msg.finish();

        let request = stun::Request {
            bytes: &bytes,
            tsx_id,
            transport,
        };

        let mut response = self
            .stun
            .send_request(request, stun_server)
            .await?
            .ok_or(StunError::RequestTimedOut)?;

        // TODO fix these errors
        if let Some(addr) = response.attribute::<XorMappedAddress>() {
            addr.map(|addr| addr.0)
                .map_err(StunError::MalformedResponse)
        } else if let Some(addr) = response.attribute::<MappedAddress>() {
            addr.map(|addr| addr.0)
                .map_err(StunError::MalformedResponse)
        } else {
            Err(StunError::InvalidResponse)
        }
    }
}
