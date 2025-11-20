use crate::MediaBackend;
use rtc::{
    rtp_session::SendRtpPacket,
    rtp_transport::TransportConnectionState,
    sdp::{
        Direction, MediaId, NegotiatedCodec, SdpError, SdpSession, SdpSessionEvent,
        SessionDescription, TransportId,
    },
    tokio::TokioIoState,
};
use rtp::RtpPacket;
use std::{
    borrow::Cow,
    collections::{HashMap, VecDeque},
    fmt::Debug,
    future::Future,
    io,
    ops::{Deref, DerefMut},
    pin::{Pin, pin},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, ready},
};
use tokio::sync::{
    mpsc::{self},
    watch,
};
use tokio_util::sync::PollSender;

/// Error returned by [`RtcMediaBackend::run`]
#[derive(Debug, thiserror::Error)]
pub enum RtcMediaBackendError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Sdp(#[from] SdpError),
}

/// MediaBackend using [`ezk-rtc`] which runs on the same task as the SIP call
pub struct RtcMediaBackend {
    sdp_session: SdpSession,
    io_state: TokioIoState,

    /// Channel to receive RTP packets from sender
    rx: mpsc::Receiver<(MediaId, SendRtpPacket)>,
    this_tx: mpsc::Sender<(MediaId, SendRtpPacket)>,

    /// Track the connection state of every transport in use.
    ///
    /// Used to block RTP sender while the transport is not ready
    transports: HashMap<TransportId, watch::Sender<TransportConnectionState>>,

    /// State of every media in the session
    media: HashMap<MediaId, MediaState>,

    /// Queue of events for the user
    events: VecDeque<MediaEvent>,
}

/// The negotiated codec for the sender/receiver
///
/// pt and fmtp values might differ between sender and receiver.
#[derive(Debug)]
pub struct Codec {
    pub pt: u8,
    pub name: Cow<'static, str>,
    pub clock_rate: u32,
    pub channels: Option<u32>,
    pub fmtp: Option<String>,
    pub dtmf_pt: Option<u8>,
}

struct MediaState {
    transport_id: TransportId,
    codec: NegotiatedCodec,

    /// Track if the sender is still valid
    sender: Option<Arc<AtomicBool>>,
    receiver: Option<mpsc::Sender<RtpPacket>>,
}

impl RtcMediaBackend {
    pub fn new(sdp_session: SdpSession) -> Self {
        let (this_tx, rx) = mpsc::channel(16);

        RtcMediaBackend {
            sdp_session,
            io_state: TokioIoState::new_with_local_ips().unwrap(),
            rx,
            this_tx,
            transports: HashMap::new(),
            media: HashMap::new(),
            events: VecDeque::new(),
        }
    }

    /// Give access to the underlying SDP session, allowing for modification of the session
    pub fn sdp_session(&mut self) -> &mut SdpSession {
        &mut self.sdp_session
    }
}

impl MediaBackend for RtcMediaBackend {
    type Error = RtcMediaBackendError;
    type Event = MediaEvent;

    fn has_media(&self) -> bool {
        self.sdp_session.has_media()
    }

    async fn create_sdp_offer(&mut self) -> Result<SessionDescription, Self::Error> {
        self.io_state
            .handle_transport_changes(&mut self.sdp_session)
            .await?;

        Ok(self.sdp_session.create_sdp_offer())
    }

    async fn receive_sdp_answer(&mut self, sdp: SessionDescription) -> Result<(), Self::Error> {
        self.sdp_session.receive_sdp_answer(sdp)?;

        self.io_state
            .handle_transport_changes(&mut self.sdp_session)
            .await?;

        Ok(())
    }

    async fn receive_sdp_offer(
        &mut self,
        sdp: SessionDescription,
    ) -> Result<SessionDescription, Self::Error> {
        let answer_state = self.sdp_session.receive_sdp_offer(sdp)?;

        self.io_state
            .handle_transport_changes(&mut self.sdp_session)
            .await?;

        Ok(self.sdp_session.create_sdp_answer(answer_state))
    }

    async fn run(&mut self) -> Result<Self::Event, Self::Error> {
        loop {
            if let Some(event) = self.events.pop_front() {
                return Ok(event);
            }

            let event = tokio::select! {
                Some((media_id, packet)) = self.rx.recv() => {
                    if let Some(mut writer) = self.sdp_session.outbound_media(media_id) {
                        writer.send_rtp(packet);
                    } else {
                        log::warn!("Dropping outbound RTP packet, writer is no longer available");
                    }

                    continue;
                }
                event = self.io_state.poll_session(&mut self.sdp_session) => event?,
            };

            match event {
                SdpSessionEvent::MediaAdded(event) => {
                    let (send, recv) = direction_bools(event.direction);
                    let transport_state = self
                        .transports
                        .entry(event.transport_id)
                        .or_insert_with(|| watch::channel(TransportConnectionState::New).0);

                    let mut media_state = MediaState {
                        transport_id: event.transport_id,
                        codec: event.codec,
                        sender: None,
                        receiver: None,
                    };

                    if send {
                        self.events.push_back(add_sender(
                            transport_state,
                            event.id,
                            &mut media_state,
                            self.this_tx.clone(),
                        ));
                    }

                    if recv {
                        self.events
                            .push_back(add_receiver(event.id, &mut media_state));
                    }

                    self.media.insert(event.id, media_state);
                }
                SdpSessionEvent::MediaChanged(event) => {
                    let (old_send, old_recv) = direction_bools(event.old_direction);
                    let (new_send, new_recv) = direction_bools(event.new_direction);

                    let media_state = self.media.get_mut(&event.id).unwrap();
                    let transport_state = &self.transports[&media_state.transport_id];

                    if old_send
                        && !new_send
                        && let Some(valid) = media_state.sender.take()
                    {
                        valid.store(false, Ordering::Relaxed);
                    }

                    if !old_send && new_send {
                        self.events.push_back(add_sender(
                            transport_state,
                            event.id,
                            media_state,
                            self.this_tx.clone(),
                        ));
                    }

                    if old_recv && !new_recv {
                        media_state.receiver = None;
                    }

                    if !old_recv && new_recv {
                        self.events.push_back(add_receiver(event.id, media_state));
                    }
                }
                SdpSessionEvent::MediaRemoved(media_id) => {
                    if let Some(sender) = self.media.remove(&media_id).and_then(|m| m.sender) {
                        sender.store(false, Ordering::Relaxed);
                    }
                }
                SdpSessionEvent::IceConnectionState(..) => {
                    // TODO: handle this
                }
                SdpSessionEvent::TransportConnectionState(event) => {
                    self.transports
                        .entry(event.transport_id)
                        .or_insert_with(|| watch::channel(event.new).0)
                        .send_replace(event.new);
                }
                SdpSessionEvent::ReceiveRTP {
                    media_id,
                    rtp_packet,
                } => {
                    if let Some(receiver) =
                        self.media.get(&media_id).and_then(|m| m.receiver.as_ref())
                    {
                        let _ = receiver.send(rtp_packet).await;
                    }
                }
                SdpSessionEvent::IceGatheringState(..) => {}
                SdpSessionEvent::SendData {
                    transport_id,
                    component,
                    data,
                    source,
                    target,
                } => self
                    .io_state
                    .send(transport_id, component, data, source, target),
                SdpSessionEvent::ReceivePictureLossIndication { .. } => {
                    // TODO
                }
                SdpSessionEvent::ReceiveFullIntraRefresh { .. } => {
                    // TODO
                }
            }
        }
    }
}

fn add_sender(
    transport_state: &watch::Sender<TransportConnectionState>,
    media_id: MediaId,
    media_state: &mut MediaState,
    this_tx: mpsc::Sender<(MediaId, SendRtpPacket)>,
) -> MediaEvent {
    let valid = Arc::new(AtomicBool::new(true));
    media_state.sender = Some(valid.clone());

    MediaEvent::SenderAdded {
        sender: RtpSender {
            media_id,
            state: transport_state.subscribe(),
            valid,
            tx: PollSender::new(this_tx.clone()),
        },
        codec: Codec {
            pt: media_state.codec.pt.local,
            name: media_state.codec.name.clone(),
            clock_rate: media_state.codec.clock_rate,
            channels: media_state.codec.channels,
            fmtp: media_state.codec.send_fmtp.clone(),
            dtmf_pt: media_state.codec.dtmf.as_ref().map(|dtmf| dtmf.pt.local),
        },
    }
}

fn add_receiver(media_id: MediaId, media_state: &mut MediaState) -> MediaEvent {
    let (tx, rx) = mpsc::channel(8);
    media_state.receiver = Some(tx);

    MediaEvent::ReceiverAdded {
        receiver: RtpReceiver {
            media_id,
            receiver: rx,
        },
        codec: Codec {
            pt: media_state.codec.pt.remote,
            name: media_state.codec.name.clone(),
            clock_rate: media_state.codec.clock_rate,
            channels: media_state.codec.channels,
            fmtp: media_state.codec.recv_fmtp.clone(),
            dtmf_pt: media_state.codec.dtmf.as_ref().map(|dtmf| dtmf.pt.remote),
        },
    }
}

fn direction_bools(direction: Direction) -> (bool, bool) {
    match direction {
        Direction::SendRecv => (true, true),
        Direction::RecvOnly => (false, true),
        Direction::SendOnly => (true, false),
        Direction::Inactive => (false, false),
    }
}

/// Event returned by [`RtcMediaBackend::run`]
pub enum MediaEvent {
    SenderAdded { sender: RtpSender, codec: Codec },
    ReceiverAdded { receiver: RtpReceiver, codec: Codec },
}

/// RTP sender. Name says it all. Used to send RTP packets to an active media session.
pub struct RtpSender {
    media_id: MediaId,
    state: watch::Receiver<TransportConnectionState>,
    valid: Arc<AtomicBool>,
    tx: PollSender<(MediaId, SendRtpPacket)>,
}

/// Error returned by [`RtpSender::send`]
#[derive(Debug, thiserror::Error)]
#[error("RTP sender is shut down")]
pub struct RtpSendError;

impl RtpSender {
    /// Returns the associated [`MediaId`] of the sender
    pub fn media_id(&self) -> MediaId {
        self.media_id
    }

    // Wait for the state to be connected, returns if the transceiver is still valid
    async fn wait_connected(&mut self) -> bool {
        self.state
            .wait_for(|x| *x == TransportConnectionState::Connected)
            .await
            .is_ok()
    }

    /// Send an RTP packet.
    ///
    /// Blocks until the backing transport has transitioned to the connected state.
    ///
    /// Returned errors are permanent and must be treated like the RTP sender has been destroyed
    pub async fn send(&mut self, packet: SendRtpPacket) -> Result<(), RtpSendError> {
        if !self.valid.load(Ordering::Relaxed) {
            return Err(RtpSendError);
        }

        if !self.wait_connected().await {
            return Err(RtpSendError);
        }

        if self
            .tx
            .get_ref()
            .ok_or(RtpSendError)?
            .send((self.media_id, packet))
            .await
            .is_err()
        {
            Err(RtpSendError)
        } else {
            Ok(())
        }
    }
}

impl futures_sink::Sink<SendRtpPacket> for RtpSender {
    type Error = RtpSendError;

    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if !self.valid.load(Ordering::Relaxed) {
            return Poll::Ready(Err(RtpSendError));
        }

        ready!(self.tx.poll_reserve(cx)).map_err(|_| RtpSendError)?;

        loop {
            if *self.as_mut().state.borrow_and_update() == TransportConnectionState::Connected {
                return Poll::Ready(Ok(()));
            }

            if ready!(pin!(self.state.changed()).poll(cx)).is_err() {
                return Poll::Ready(Err(RtpSendError));
            }
        }
    }

    fn start_send(mut self: Pin<&mut Self>, item: SendRtpPacket) -> Result<(), Self::Error> {
        let id = self.media_id;
        Pin::new(&mut self.tx)
            .start_send((id, item))
            .map_err(|_| RtpSendError)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.tx)
            .poll_flush(cx)
            .map_err(|_| RtpSendError)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Pin::new(&mut self.tx)
            .poll_close(cx)
            .map_err(|_| RtpSendError)
    }
}

/// RTP receiver. Exposes the inner tokio MPSC receiver for convenience.
///
/// Consider the RTP session's receiver to be closed if the MPSC receiver is closed.
pub struct RtpReceiver {
    media_id: MediaId,
    receiver: mpsc::Receiver<RtpPacket>,
}

impl RtpReceiver {
    /// Returns the associated [`MediaId`] of the receiver
    pub fn media_id(&self) -> MediaId {
        self.media_id
    }

    /// Turn the RtpReceiver into a tokio channel receiver
    pub fn into_inner(self) -> mpsc::Receiver<RtpPacket> {
        self.receiver
    }
}

impl Deref for RtpReceiver {
    type Target = mpsc::Receiver<RtpPacket>;

    fn deref(&self) -> &Self::Target {
        &self.receiver
    }
}

impl DerefMut for RtpReceiver {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.receiver
    }
}
