use rtp::RtpPacket;
use session::{
    AsyncEvent, AsyncSdpSession, Direction, MediaId, NegotiatedCodec, SessionDescription,
    TransportConnectionState, TransportId,
};
use std::{
    borrow::Cow,
    collections::{HashMap, VecDeque},
    error::Error,
    fmt::Debug,
    future::Future,
    ops::{Deref, DerefMut},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use tokio::sync::{
    mpsc::{self},
    watch,
};

/// SDP based media backend used by calls
pub trait MediaBackend {
    type Error: Debug + Error;
    type Event;

    /// Returns if any media is already configured. This information is used to determine if
    /// an SDP offer is sent or requested when sending an INVITE.
    fn has_media(&self) -> bool;

    fn create_sdp_offer(
        &mut self,
    ) -> impl Future<Output = Result<SessionDescription, Self::Error>> + Send;
    fn receive_sdp_answer(
        &mut self,
        sdp: SessionDescription,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    fn receive_sdp_offer(
        &mut self,
        sdp: SessionDescription,
    ) -> impl Future<Output = Result<SessionDescription, Self::Error>> + Send;

    /// Run until a media event is received
    fn run(&mut self) -> impl Future<Output = Result<Self::Event, Self::Error>> + Send;
}

impl MediaBackend for AsyncSdpSession {
    type Error = session::Error;
    type Event = session::AsyncEvent;

    fn has_media(&self) -> bool {
        self.has_media()
    }

    async fn create_sdp_offer(&mut self) -> Result<SessionDescription, Self::Error> {
        self.create_sdp_offer().await
    }

    async fn receive_sdp_answer(&mut self, sdp: SessionDescription) -> Result<(), Self::Error> {
        self.receive_sdp_answer(sdp).await
    }

    async fn receive_sdp_offer(
        &mut self,
        sdp: SessionDescription,
    ) -> Result<SessionDescription, Self::Error> {
        self.receive_sdp_offer(sdp).await
    }

    async fn run(&mut self) -> Result<Self::Event, Self::Error> {
        self.run().await
    }
}

pub struct MediaSession {
    inner: AsyncSdpSession,

    /// Channel to receive RTP packets from sender
    rx: mpsc::Receiver<(MediaId, RtpPacket)>,
    this_tx: mpsc::Sender<(MediaId, RtpPacket)>,

    /// Track the connection state of every transport in use.
    ///
    /// Used to block RTP sender while the transport is not ready
    transports: HashMap<TransportId, watch::Sender<TransportConnectionState>>,

    /// State of every media in the session
    media: HashMap<MediaId, MediaState>,

    events: VecDeque<MediaEvent>,
}

/// The negotiated codec for the sender/receiver
///
/// pt and fmtp values might differ between sender and receiver.
pub struct Codec {
    pub pt: u8,
    pub name: Cow<'static, str>,
    pub clock_rate: u32,
    pub channels: Option<u32>,
    pub fmtp: Option<String>,
}

struct MediaState {
    transport_id: TransportId,
    codec: NegotiatedCodec,

    /// Track if the sender is still valid
    sender: Option<Arc<AtomicBool>>,
    receiver: Option<mpsc::Sender<RtpPacket>>,
}

impl MediaSession {
    pub fn new(inner: AsyncSdpSession) -> Self {
        let (this_tx, rx) = mpsc::channel(16);

        Self {
            inner,
            rx,
            this_tx,
            transports: HashMap::new(),
            media: HashMap::new(),
            events: VecDeque::new(),
        }
    }

    pub fn inner(&mut self) -> &mut AsyncSdpSession {
        &mut self.inner
    }
}

impl MediaBackend for MediaSession {
    type Error = <AsyncSdpSession as MediaBackend>::Error;
    type Event = MediaEvent;

    fn has_media(&self) -> bool {
        self.inner.has_media()
    }

    async fn create_sdp_offer(&mut self) -> Result<SessionDescription, Self::Error> {
        self.inner.create_sdp_offer().await
    }

    async fn receive_sdp_answer(&mut self, sdp: SessionDescription) -> Result<(), Self::Error> {
        self.inner.receive_sdp_answer(sdp).await
    }

    async fn receive_sdp_offer(
        &mut self,
        sdp: SessionDescription,
    ) -> Result<SessionDescription, Self::Error> {
        self.inner.receive_sdp_offer(sdp).await
    }

    async fn run(&mut self) -> Result<Self::Event, Self::Error> {
        loop {
            if let Some(event) = self.events.pop_front() {
                return Ok(event);
            }

            let event = tokio::select! {
                Some((media_id, packet)) = self.rx.recv() => {
                    // TODO: check if media has a sender
                    self.inner.send_rtp(media_id, packet);
                    continue;
                }
                event = self.inner.run() => event?,
            };

            match event {
                AsyncEvent::MediaAdded(event) => {
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
                        self.events.push_back(add_receiver(&mut media_state));
                    }

                    self.media.insert(event.id, media_state);
                }
                AsyncEvent::MediaChanged(event) => {
                    let (old_send, old_recv) = direction_bools(event.old_direction);
                    let (new_send, new_recv) = direction_bools(event.new_direction);

                    let media_state = self.media.get_mut(&event.id).unwrap();
                    let transport_state = &self.transports[&media_state.transport_id];

                    if old_send && !new_send {
                        if let Some(valid) = media_state.sender.take() {
                            valid.store(false, Ordering::Relaxed);
                        }
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
                        self.events.push_back(add_receiver(media_state));
                    }
                }
                AsyncEvent::MediaRemoved(media_id) => {
                    if let Some(sender) = self.media.remove(&media_id).and_then(|m| m.sender) {
                        sender.store(false, Ordering::Relaxed);
                    }
                }
                AsyncEvent::IceConnectionState(..) => {
                    // TODO: handle this
                }
                AsyncEvent::TransportConnectionState(event) => {
                    self.transports
                        .entry(event.transport_id)
                        .or_insert_with(|| watch::channel(event.new).0)
                        .send_replace(event.new);
                }
                AsyncEvent::ReceiveRTP { media_id, packet } => {
                    if let Some(receiver) =
                        self.media.get(&media_id).and_then(|m| m.receiver.as_ref())
                    {
                        let _ = receiver.send(packet).await;
                    }
                }
            }
        }
    }
}

fn add_sender(
    transport_state: &watch::Sender<TransportConnectionState>,
    media_id: MediaId,
    media_state: &mut MediaState,
    this_tx: mpsc::Sender<(MediaId, RtpPacket)>,
) -> MediaEvent {
    let valid = Arc::new(AtomicBool::new(true));
    media_state.sender = Some(valid.clone());

    MediaEvent::SenderAdded {
        sender: RtpSender {
            media_id,
            state: transport_state.subscribe(),
            valid,
            tx: this_tx.clone(),
        },
        codec: Codec {
            pt: media_state.codec.send_pt,
            name: media_state.codec.name.clone(),
            clock_rate: media_state.codec.clock_rate,
            channels: media_state.codec.channels,
            fmtp: media_state.codec.send_fmtp.clone(),
        },
    }
}

fn add_receiver(media_state: &mut MediaState) -> MediaEvent {
    let (tx, rx) = mpsc::channel(8);
    media_state.receiver = Some(tx);

    MediaEvent::ReceiverAdded {
        receiver: RtpReceiver(rx),
        codec: Codec {
            pt: media_state.codec.recv_pt,
            name: media_state.codec.name.clone(),
            clock_rate: media_state.codec.clock_rate,
            channels: media_state.codec.channels,
            fmtp: media_state.codec.recv_fmtp.clone(),
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

/// Event returned by [`MediaSession::run`]
pub enum MediaEvent {
    SenderAdded { sender: RtpSender, codec: Codec },
    ReceiverAdded { receiver: RtpReceiver, codec: Codec },
}

/// RTP sender. Name says it all. Used to send RTP packets to an active media session.
pub struct RtpSender {
    media_id: MediaId,
    state: watch::Receiver<TransportConnectionState>,
    valid: Arc<AtomicBool>,
    tx: mpsc::Sender<(MediaId, RtpPacket)>,
}

/// Error returned by [`RtpSender::send`]
#[derive(Debug, thiserror::Error)]
#[error("RTP sender is shut down")]
pub struct RtpSendError;

impl RtpSender {
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
    pub async fn send(&mut self, packet: RtpPacket) -> Result<(), RtpSendError> {
        if !self.valid.load(Ordering::Relaxed) {
            return Err(RtpSendError);
        }

        if !self.wait_connected().await {
            return Err(RtpSendError);
        }

        if self.tx.send((self.media_id, packet)).await.is_err() {
            Err(RtpSendError)
        } else {
            Ok(())
        }
    }
}

/// RTP receiver. Exposes the inner tokio MPSC receiver for convenience.
///
/// Consider the RTP session's receiver to be closed if the MPSC receiver is closed.
pub struct RtpReceiver(pub mpsc::Receiver<RtpPacket>);

impl Deref for RtpReceiver {
    type Target = mpsc::Receiver<RtpPacket>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for RtpReceiver {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
