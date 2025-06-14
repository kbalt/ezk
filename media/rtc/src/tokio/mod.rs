use crate::{
    rtp_transport::RtpTransportPorts,
    sdp::{SdpSession, SdpSessionEvent, TransportChange, TransportId},
};
use ice::{Component, ReceivedPkt};
use socket::Socket;
use std::{
    collections::HashMap,
    future::poll_fn,
    hash::{BuildHasher, Hasher},
    io,
    mem::MaybeUninit,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
    time::Instant,
};
use tokio::{
    io::ReadBuf,
    net::UdpSocket,
    time::{Sleep, sleep_until},
};

mod socket;

/// IO implementation to be used alongside [`SdpSession`]
pub struct TokioIoState {
    ips: Vec<IpAddr>,
    sockets: HashMap<(TransportId, Component), Socket, BuildTransportHasher>,
    timeout: Option<Pin<Box<Sleep>>>,
    buf: Vec<MaybeUninit<u8>>,
}

impl TokioIoState {
    /// Create a new state with a list of local IP addresses, which are used for ICE
    pub fn new(ips: Vec<IpAddr>) -> Self {
        Self {
            ips,
            sockets: HashMap::with_hasher(BuildTransportHasher),
            timeout: Some(Box::pin(sleep_until(Instant::now().into()))),
            buf: vec![MaybeUninit::uninit(); 65535],
        }
    }

    /// Create a new state and discover a list of local IP addresses
    pub fn new_with_local_ips() -> Result<Self, local_ip_address::Error> {
        let ips = local_ip_address::list_afinet_netifas()?
            .into_iter()
            .map(|(_, addr)| addr)
            .collect();

        Ok(Self::new(ips))
    }

    /// Handle all changes to transport resources as requested by the `SdpSession`
    ///
    /// Must always be called __before__ calling [`SdpSession::create_sdp_offer`], [`SdpSession::create_sdp_answer`]
    /// and __after__ calling [`SdpSession::receive_sdp_offer`] and [`SdpSession::receive_sdp_answer`].
    pub async fn handle_transport_changes(&mut self, session: &mut SdpSession) -> io::Result<()> {
        while let Some(change) = session.pop_transport_change() {
            match change {
                TransportChange::CreateSocket(transport_id) => {
                    let socket = UdpSocket::bind("0.0.0.0:0").await?;

                    session.set_transport_ports(
                        transport_id,
                        &self.ips,
                        RtpTransportPorts::mux(socket.local_addr()?.port()),
                    );

                    self.sockets
                        .insert((transport_id, Component::Rtp), Socket::new(socket)?);
                }
                TransportChange::CreateSocketPair(transport_id) => {
                    let rtp_socket = UdpSocket::bind("0.0.0.0:0").await?;
                    let rtcp_socket = UdpSocket::bind("0.0.0.0:0").await?;

                    session.set_transport_ports(
                        transport_id,
                        &self.ips,
                        RtpTransportPorts::new(
                            rtp_socket.local_addr()?.port(),
                            rtcp_socket.local_addr()?.port(),
                        ),
                    );

                    self.sockets
                        .insert((transport_id, Component::Rtp), Socket::new(rtp_socket)?);
                    self.sockets
                        .insert((transport_id, Component::Rtcp), Socket::new(rtcp_socket)?);
                }
                TransportChange::Remove(transport_id) => {
                    self.sockets.remove(&(transport_id, Component::Rtp));
                    self.sockets.remove(&(transport_id, Component::Rtcp));
                }
                TransportChange::RemoveRtcpSocket(transport_id) => {
                    self.sockets.remove(&(transport_id, Component::Rtcp));
                }
            }
        }

        Ok(())
    }

    /// Should be used to handle the [`SdpSessionEvent::SendData`](crate::sdp::SdpSessionEvent::SendData).
    pub fn send(
        &mut self,
        transport_id: TransportId,
        component: Component,
        data: Vec<u8>,
        source: Option<IpAddr>,
        target: SocketAddr,
    ) {
        if let Some(socket) = self.sockets.get_mut(&(transport_id, component)) {
            socket.enqueue(data, source, target);
        } else {
            log::error!(
                "Tried to send packet using a non existent socket {transport_id:?} {component:?}"
            );
        }
    }

    /// Poll the session until an event is received.
    ///
    /// This function is cancel safe.
    pub async fn poll_session(&mut self, session: &mut SdpSession) -> io::Result<SdpSessionEvent> {
        if let Some(event) = session.pop_event() {
            return Ok(event);
        }

        poll_fn(|cx| self.poll(cx, session)).await?;

        Ok(session
            .pop_event()
            .expect("poll only returns Ready when an event is available"))
    }

    /// Poll the internal IO and session.
    ///
    /// Returns `Poll::Ready` when the session has events to handle.
    pub fn poll(&mut self, cx: &mut Context<'_>, session: &mut SdpSession) -> Poll<io::Result<()>> {
        let now = Instant::now();

        for (socket_id, socket) in self.sockets.iter_mut() {
            socket.send_pending(cx);

            let mut buf = ReadBuf::uninit(&mut self.buf);

            if let Poll::Ready(result) = socket.poll_recv_from(cx, &mut buf) {
                let (dst, src) = result?;

                let pkt = ReceivedPkt {
                    data: buf.filled().to_vec(),
                    source: src,
                    destination: dst,
                    component: socket_id.1,
                };

                session.receive(now, socket_id.0, pkt);

                self.timeout = session
                    .timeout(now)
                    .map(|timeout| Box::pin(sleep_until((now + timeout).into())));
            }
        }

        if let Some(timeout) = &mut self.timeout {
            if timeout.as_mut().poll(cx).is_ready() {
                session.poll(now);

                self.timeout = session
                    .timeout(now)
                    .map(|timeout| Box::pin(sleep_until((now + timeout).into())));
            }
        }

        if session.has_events() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}

struct BuildTransportHasher;
impl BuildHasher for BuildTransportHasher {
    type Hasher = TransportHasher;

    fn build_hasher(&self) -> Self::Hasher {
        TransportHasher(0, 0)
    }
}

struct TransportHasher(u32, u8);
impl Hasher for TransportHasher {
    fn finish(&self) -> u64 {
        ((self.0 as u64) << 8) | self.1 as u64
    }

    fn write(&mut self, _bytes: &[u8]) {
        panic!()
    }

    fn write_u32(&mut self, i: u32) {
        self.0 = i;
    }

    fn write_u8(&mut self, i: u8) {
        self.1 = i;
    }
}
