use crate::transport::parse::{CompleteItem, parse_complete};
use crate::transport::{Direction, ReceivedMessage, TpHandle, Transport};
use crate::{Endpoint, EndpointBuilder, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::{fmt, io};
use tokio::net::{ToSocketAddrs, UdpSocket};
use tokio::sync::broadcast;

const UDP: &str = "UDP";
const MAX_MSG_SIZE: usize = u16::MAX as usize;

#[derive(Debug)]
struct Inner {
    bound: SocketAddr,
    socket: UdpSocket,
}

#[derive(Debug)]
pub struct Udp {
    inner: Arc<Inner>,
}

impl fmt::Display for Udp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "udp:bound={}", self.inner.bound)
    }
}

impl Udp {
    pub async fn spawn<A>(builder: &mut EndpointBuilder, addr: A) -> io::Result<TpHandle>
    where
        A: ToSocketAddrs,
    {
        let socket = UdpSocket::bind(addr).await?;
        let bound = socket.local_addr()?;

        log::info!("Bound UDP to {bound}");

        let inner = Arc::new(Inner { bound, socket });

        let handle = TpHandle::new(Udp {
            inner: inner.clone(),
        });

        tokio::spawn(receive_task(builder.subscribe(), inner, handle.clone()));

        builder.add_unmanaged_transport(handle.clone());

        Ok(handle)
    }
}

#[async_trait::async_trait]
impl Transport for Udp {
    fn name(&self) -> &'static str {
        UDP
    }

    fn secure(&self) -> bool {
        false
    }

    fn reliable(&self) -> bool {
        false
    }

    fn bound(&self) -> SocketAddr {
        self.inner.bound
    }

    fn sent_by(&self) -> SocketAddr {
        self.inner.bound
    }

    fn direction(&self) -> Direction {
        Direction::None
    }

    async fn send(&self, bytes: &[u8], target: SocketAddr) -> io::Result<()> {
        self.inner.socket.send_to(bytes, target).await.map(|_| ())
    }
}

async fn receive_task(
    mut endpoint: broadcast::Receiver<Endpoint>,
    inner: Arc<Inner>,
    handle: TpHandle,
) {
    let endpoint = match endpoint.recv().await.ok() {
        Some(endpoint) => endpoint,
        None => return,
    };

    let mut buffer = vec![0u8; MAX_MSG_SIZE];

    loop {
        let result = inner.socket.recv_from(&mut buffer).await;

        if let Err(e) = handle_msg(&endpoint, &inner, &handle, result, &buffer).await {
            log::error!("UDP recv error {e:?}");
        }
    }
}

async fn handle_msg(
    endpoint: &Endpoint,
    inner: &Inner,
    handle: &TpHandle,
    result: io::Result<(usize, SocketAddr)>,
    bytes: &[u8],
) -> Result<()> {
    let (len, remote) = result?;

    let bytes = &bytes[..len];

    match parse_complete(bytes) {
        Ok(CompleteItem::KeepAliveRequest) => {
            inner.socket.send_to(b"\r\n", remote).await?;
        }
        Ok(CompleteItem::KeepAliveResponse) => {
            // ignore for now
        }
        Ok(CompleteItem::Stun(message)) => {
            endpoint.receive_stun(message, remote, handle.clone());
        }
        Ok(CompleteItem::Sip {
            line,
            headers,
            body,
            buffer,
        }) => {
            endpoint.receive(ReceivedMessage::new(
                remote,
                buffer,
                handle.clone(),
                line,
                headers,
                body,
            ));
        }
        Err(_e) => {
            // ignore for now
        }
    };

    Ok(())
}
