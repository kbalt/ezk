use crate::state::{
    sdp::{
        Codecs, IceConnectionStateChanged, LocalMediaId, MediaAdded, MediaChanged, MediaId,
        MediaWriter, SdpError, SdpSession, SdpSessionConfig, SdpSessionEvent, TransportChange,
        TransportConnectionStateChanged, TransportId,
    },
    transport::RtpTransportPorts,
};
use ice::{Component, IceGatheringState, ReceivedPkt};
use rtp::RtpPacket;
use sdp_types::{Direction, SessionDescription};
use socket::Socket;
use std::{
    collections::{HashMap, VecDeque},
    future::{pending, poll_fn},
    io::{self},
    mem::MaybeUninit,
    net::{IpAddr, SocketAddr},
    task::Poll,
    time::Instant,
};
use tokio::{io::ReadBuf, net::UdpSocket, select, time::sleep_until};

mod socket;

/// Session event returned by [`AsyncSdpSession::run`]
#[derive(Debug)]
pub enum TokioSdpSessionEvent {
    /// See [`MediaAdded`]
    MediaAdded(MediaAdded),
    /// See [`MediaChanged`]
    MediaChanged(MediaChanged),
    /// Media was removed from the session
    MediaRemoved(MediaId),
    /// See [`IceConnectionStateChanged`]
    IceConnectionState(IceConnectionStateChanged),
    /// See [`TransportConnectionStateChanged`]
    TransportConnectionState(TransportConnectionStateChanged),

    /// Receive RTP on a media
    ReceiveRTP {
        media_id: MediaId,
        packet: RtpPacket,
    },
}

/// Async wrapper around [`SdpSession`] using the tokio runtime
pub struct TokioSdpSession {
    state: SdpSession,
    sockets: HashMap<(TransportId, Component), Socket>,
    timeout: Option<Instant>,
    ips: Vec<IpAddr>,

    buf: Vec<MaybeUninit<u8>>,

    events: VecDeque<TokioSdpSessionEvent>,
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Sdp(#[from] SdpError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

impl TokioSdpSession {
    pub fn new(address: IpAddr, options: SdpSessionConfig) -> Self {
        Self {
            state: SdpSession::new(address, options),
            sockets: HashMap::new(),
            timeout: Some(Instant::now()), // poll immediately
            ips: local_ip_address::list_afinet_netifas()
                .unwrap()
                .into_iter()
                .map(|(_, addr)| addr)
                .collect(),

            buf: vec![MaybeUninit::uninit(); 65535],

            events: VecDeque::new(),
        }
    }

    /// Add a stun server to use to setup ICE
    pub fn add_stun_server(&mut self, server: SocketAddr) {
        self.state.add_stun_server(server);
    }

    /// Returns if any media already configured
    pub fn has_media(&self) -> bool {
        self.state.has_media()
    }

    pub fn writer(&mut self, media_id: MediaId) -> Option<MediaWriter<'_>> {
        self.state.writer(media_id)
    }

    /// Register codecs for a media type with a limit of how many media session by can be created
    ///
    /// Returns `None` if no more payload type numbers are available
    pub fn add_local_media(
        &mut self,
        codecs: Codecs,
        direction: Direction,
    ) -> Option<LocalMediaId> {
        self.state.add_local_media(codecs, direction)
    }

    pub fn add_media(&mut self, local_media_id: LocalMediaId, direction: Direction) -> MediaId {
        self.state.add_media(local_media_id, direction)
    }

    pub async fn create_sdp_offer(&mut self) -> Result<SessionDescription, Error> {
        self.handle_transport_changes().await?;
        self.run_until_all_candidates_are_gathered().await?;
        Ok(self.state.create_sdp_offer())
    }

    pub async fn receive_sdp_offer(
        &mut self,
        offer: SessionDescription,
    ) -> Result<SessionDescription, Error> {
        let state = self.state.receive_sdp_offer(offer)?;

        self.handle_transport_changes().await?;
        self.run_until_all_candidates_are_gathered().await?;

        Ok(self.state.create_sdp_answer(state))
    }

    pub async fn receive_sdp_answer(&mut self, answer: SessionDescription) -> Result<(), Error> {
        self.state.receive_sdp_answer(answer)?;
        self.handle_transport_changes().await?;

        Ok(())
    }

    async fn handle_transport_changes(&mut self) -> io::Result<()> {
        while let Some(change) = self.state.pop_transport_change() {
            match change {
                TransportChange::CreateSocket(transport_id) => {
                    let socket = UdpSocket::bind("0.0.0.0:0").await?;

                    self.state.set_transport_ports(
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

                    self.state.set_transport_ports(
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

    fn handle_events(&mut self) -> Result<(), Error> {
        while let Some(event) = self.state.pop_event() {
            match event {
                SdpSessionEvent::MediaAdded(event) => self
                    .events
                    .push_back(TokioSdpSessionEvent::MediaAdded(event)),
                SdpSessionEvent::MediaChanged(event) => self
                    .events
                    .push_back(TokioSdpSessionEvent::MediaChanged(event)),
                SdpSessionEvent::MediaRemoved(id) => self
                    .events
                    .push_back(TokioSdpSessionEvent::MediaRemoved(id)),
                SdpSessionEvent::IceGatheringState(..) => {}
                SdpSessionEvent::IceConnectionState(event) => self
                    .events
                    .push_back(TokioSdpSessionEvent::IceConnectionState(event)),
                SdpSessionEvent::TransportConnectionState(event) => self
                    .events
                    .push_back(TokioSdpSessionEvent::TransportConnectionState(event)),
                SdpSessionEvent::SendData {
                    transport_id,
                    component,
                    data,
                    source,
                    target,
                } => {
                    if let Some(socket) = self.sockets.get_mut(&(transport_id, component)) {
                        socket.enqueue(data, source, target);
                    } else {
                        log::error!("SdpSession tried to send packet using a non existent socket");
                    }
                }
                SdpSessionEvent::ReceiveRTP {
                    media_id,
                    rtp_packet: packet,
                } => self
                    .events
                    .push_back(TokioSdpSessionEvent::ReceiveRTP { media_id, packet }),
            }
        }

        Ok(())
    }

    pub async fn run_until_all_candidates_are_gathered(&mut self) -> Result<(), Error> {
        while !matches!(
            self.state.ice_gathering_state(),
            None | Some(IceGatheringState::Complete)
        ) {
            self.step().await?;
            self.handle_events()?;
        }

        Ok(())
    }

    pub async fn run(&mut self) -> Result<TokioSdpSessionEvent, Error> {
        loop {
            if let Some(event) = self.events.pop_front() {
                return Ok(event);
            }

            self.step().await?;
            self.handle_events().unwrap();
        }
    }

    async fn step(&mut self) -> Result<(), Error> {
        let mut buf = ReadBuf::uninit(&mut self.buf);

        select! {
            (socket_id, result) = poll_sockets(&mut self.sockets, &mut buf) => {
                let (dst, source) = result?;

                let now = Instant::now();

                let pkt = ReceivedPkt {
                    data: buf.filled().to_vec(),
                    source,
                    destination: dst,
                    component: socket_id.1
                };

                self.state.receive(now, socket_id.0, pkt);
                self.timeout = self.state.timeout(now).map(|d| now + d);

                Ok(())
            }
            _ = timeout(&mut self.timeout) => {
                let now = Instant::now();

                self.state.poll(now);
                self.timeout = self.state.timeout(now).map(|d| now + d);

                Ok(())
            }
        }
    }
}

async fn timeout(instant: &mut Option<Instant>) {
    match *instant {
        Some(deadline) => {
            sleep_until(deadline.into()).await;
            *instant = None;
        }
        None => pending().await,
    }
}

async fn poll_sockets(
    sockets: &mut HashMap<(TransportId, Component), Socket>,
    buf: &mut ReadBuf<'_>,
) -> (
    (TransportId, Component),
    Result<(SocketAddr, SocketAddr), io::Error>,
) {
    poll_fn(|cx| {
        for (socket_id, socket) in sockets.iter_mut() {
            socket.send_pending(cx);

            if let Poll::Ready(result) = socket.poll_recv_from(cx, buf) {
                return Poll::Ready((*socket_id, result));
            }
        }

        Poll::Pending
    })
    .await
}
