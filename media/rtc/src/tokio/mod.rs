use crate::{
    rtp_transport::RtpTransportPorts,
    sdp::{SdpSession, SdpSessionEvent, TransportChange, TransportId},
};
use ice::{Component, ReceivedPkt};
use quinn_udp::{BATCH_SIZE, RecvMeta};
use socket::Socket;
use std::{
    collections::HashMap,
    future::poll_fn,
    hash::{BuildHasher, Hasher},
    io::{self, IoSliceMut},
    net::{IpAddr, SocketAddr},
    pin::Pin,
    task::{Context, Poll},
    time::{Duration, Instant},
};
use tokio::{
    net::UdpSocket,
    time::{Sleep, sleep_until},
};

mod socket;

const RECV_BUFFER_SIZE: usize = 2500;

/// IO implementation to be used alongside [`SdpSession`]
pub struct TokioIoState {
    ips: Vec<IpAddr>,
    sockets: HashMap<(TransportId, Component), Socket, BuildTransportHasher>,
    sleep: Option<Pin<Box<Sleep>>>,

    bufs: Box<[[u8; RECV_BUFFER_SIZE]; BATCH_SIZE]>,
    meta: Box<[RecvMeta; BATCH_SIZE]>,
}

impl TokioIoState {
    /// Create a new state with a list of local IP addresses, which are used for ICE
    pub fn new(ips: Vec<IpAddr>) -> Self {
        Self {
            ips,
            sockets: HashMap::with_hasher(BuildTransportHasher),
            sleep: Some(Box::pin(sleep_until(Instant::now().into()))),
            bufs: Box::new([[0u8; RECV_BUFFER_SIZE]; BATCH_SIZE]),
            meta: Box::new([RecvMeta::default(); BATCH_SIZE]),
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

    /// Should be used to handle the [`SdpSessionEvent::SendData`]
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

        let mut received = false;

        for ((transport_id, component), socket) in self.sockets.iter_mut() {
            socket.send_pending(cx);

            while let Poll::Ready(result) = {
                let mut slices = self.bufs.each_mut().map(|buf| IoSliceMut::new(buf));

                socket.poll_recv_from(cx, &mut slices, &mut *self.meta)
            } {
                let num_msg = result?;

                for i in 0..num_msg {
                    let len = self.meta[i].len;

                    let pkt = ReceivedPkt {
                        data: self.bufs[i][..len].to_vec(),
                        source: self.meta[i].addr,
                        destination: self.meta[i].dst_ip.map_or(socket.local_addr(), |ip| {
                            (ip, socket.local_addr().port()).into()
                        }),
                        component: *component,
                    };

                    session.receive(now, *transport_id, pkt);

                    received = true;
                }
            }
        }

        // Don't attempt to poll the session if theres too many outbound packets queued
        if self
            .sockets
            .iter()
            .any(|(_, socket)| socket.queue_is_full())
        {
            return Poll::Pending;
        }

        // Polled without IO being the reason, ignore sleep and poll session once
        if !received {
            session.poll(now);

            self.update_sleep(session, now);
        }

        // Poll sleep until it returns pending, to register the sleep with the context
        while let Some(sleep) = &mut self.sleep
            && sleep.as_mut().poll(cx).is_ready()
        {
            session.poll(now);

            self.update_sleep(session, now);
        }

        if session.has_events() {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }

    fn update_sleep(&mut self, session: &mut SdpSession, now: Instant) {
        match session.timeout(now) {
            Some(duration) => {
                debug_assert!(
                    duration != Duration::ZERO,
                    "SdpSession::timeout must not return Duration::ZERO after SdpSession::poll"
                );

                let deadline = tokio::time::Instant::from(now + duration);

                if let Some(sleep) = &mut self.sleep {
                    sleep.as_mut().reset(deadline);
                } else {
                    self.sleep = Some(Box::pin(sleep_until((now + duration).into())))
                }
            }
            None => self.sleep = None,
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
        (u64::from(self.0) << 8) | u64::from(self.1)
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
