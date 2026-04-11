use crate::transport::{
    ReceivedMessage, TpHandle, Transport, TransportState,
    parse::{CompleteItem, parse_complete},
};
use crate::{Endpoint, Result};
use std::sync::Arc;
use std::{io, net::SocketAddr};
use tokio::{
    net::UdpSocket,
    sync::{broadcast, watch},
};

const MAX_MSG_SIZE: usize = u16::MAX as usize;

#[derive(Clone, Debug)]
pub(super) struct UdpTransport {
    socket: Arc<UdpSocket>,
    pub(super) bound: SocketAddr,
    state: Arc<watch::Sender<TransportState>>,
}

impl UdpTransport {
    pub(super) async fn bind(
        endpoint: broadcast::Receiver<Endpoint>,
        addr: SocketAddr,
    ) -> io::Result<UdpTransport> {
        let socket = Arc::new(UdpSocket::bind(addr).await?);
        let bound = socket.local_addr()?;

        log::info!("Bound UDP to {bound}");

        let (state_tx, _) = watch::channel(TransportState::Ok);

        let transport = UdpTransport {
            socket,
            bound,
            state: Arc::new(state_tx),
        };

        tokio::spawn(receive_task(endpoint, transport.clone()));

        Ok(transport)
    }

    pub(super) async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> io::Result<()> {
        self.socket.send_to(buf, addr).await?;
        Ok(())
    }

    pub(super) fn state_receiver(&self) -> watch::Receiver<TransportState> {
        self.state.subscribe()
    }
}

async fn receive_task(mut endpoint: broadcast::Receiver<Endpoint>, transport: UdpTransport) {
    let endpoint = match endpoint.recv().await.ok() {
        Some(endpoint) => endpoint,
        None => return,
    };

    let mut buffer = vec![0u8; MAX_MSG_SIZE];

    loop {
        let result = transport.socket.recv_from(&mut buffer).await;

        if let Err(e) = handle_msg(&endpoint, &transport, result, &buffer).await {
            log::error!("UDP recv error {e:?}");
        }
    }
}

async fn handle_msg(
    endpoint: &Endpoint,
    transport: &UdpTransport,
    result: io::Result<(usize, SocketAddr)>,
    bytes: &[u8],
) -> Result<()> {
    let (len, remote) = result?;

    let bytes = &bytes[..len];

    match parse_complete(bytes) {
        Ok(CompleteItem::KeepAliveRequest) => {
            transport.socket.send_to(b"\r\n", remote).await?;
        }
        Ok(CompleteItem::KeepAliveResponse) => {
            // ignore for now
        }
        Ok(CompleteItem::Stun(message)) => {
            endpoint.receive_stun(
                message,
                remote,
                TpHandle {
                    transport: Transport::Udp(transport.clone()),
                },
            );
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
                TpHandle {
                    transport: Transport::Udp(transport.clone()),
                },
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
