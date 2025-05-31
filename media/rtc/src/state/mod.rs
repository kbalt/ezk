use crate::{BundlePolicy, Codecs, LocalMediaId, MediaId, Options, TransportId, TransportType};
use ::rtp::{
    rtcp_types::{Compound, Packet as RtcpPacket},
    RtpPacket,
};
use ice::{Component, IceAgent, IceConnectionState, IceGatheringState, ReceivedPkt};
use local_media::LocalMedia;
use sdp_types::{Direction, MediaDescription, MediaType};
use slotmap::SlotMap;
use std::{
    cmp::min,
    collections::{BTreeSet, VecDeque},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};
use transport::{
    ReceivedPacket, SessionTransportState, Transport, TransportBuilder, TransportEvent,
};

mod events;
mod local_media;
mod media;
mod rtp;
mod sdp;
mod transport;

pub use events::{
    Event, IceConnectionStateChanged, IceGatheringStateChanged, MediaAdded, MediaChanged,
    TransportChange, TransportConnectionState, TransportConnectionStateChanged,
};

/// State of a SDP/RTP based media session
pub struct SessionState {
    options: Options,

    id: u64,
    version: u64,

    // Local ip address to use
    address: IpAddr,

    /// State shared between transports
    transport_state: SessionTransportState,

    // Local configured media codecs
    next_pt: u8,
    local_media: SlotMap<LocalMediaId, LocalMedia>,

    /// Counter for local media ids
    next_media_id: MediaId,
    /// List of all media, representing the current state
    state: Vec<media::Media>,

    // Transports
    transports: SlotMap<TransportId, TransportEntry>,

    /// Pending changes which will be (maybe partially) applied once the offer/answer exchange has been completed
    pending_changes: Vec<PendingChange>,
    transport_changes: Vec<TransportChange>,
    events: VecDeque<Event>,
}

#[allow(clippy::large_enum_variant)]
enum TransportEntry {
    Transport(Transport),
    TransportBuilder(TransportBuilder),
}

impl TransportEntry {
    fn type_(&self) -> TransportType {
        match self {
            TransportEntry::Transport(transport) => transport.type_(),
            TransportEntry::TransportBuilder(transport_builder) => transport_builder.type_(),
        }
    }

    fn populate_desc(&self, desc: &mut MediaDescription) {
        match self {
            TransportEntry::Transport(transport) => transport.populate_desc(desc),
            TransportEntry::TransportBuilder(transport_builder) => {
                transport_builder.populate_desc(desc);
            }
        }
    }

    #[track_caller]
    fn unwrap(&self) -> &Transport {
        match self {
            TransportEntry::Transport(transport) => transport,
            TransportEntry::TransportBuilder(..) => {
                panic!("Tried to access incomplete transport")
            }
        }
    }

    #[track_caller]
    fn unwrap_mut(&mut self) -> &mut Transport {
        match self {
            TransportEntry::Transport(transport) => transport,
            TransportEntry::TransportBuilder(..) => {
                panic!("Tried to access incomplete transport")
            }
        }
    }

    fn ice_agent(&self) -> Option<&IceAgent> {
        match self {
            TransportEntry::Transport(transport) => transport.ice_agent.as_ref(),
            TransportEntry::TransportBuilder(transport_builder) => {
                transport_builder.ice_agent.as_ref()
            }
        }
    }

    fn ice_agent_mut(&mut self) -> Option<&mut IceAgent> {
        match self {
            TransportEntry::Transport(transport) => transport.ice_agent.as_mut(),
            TransportEntry::TransportBuilder(transport_builder) => {
                transport_builder.ice_agent.as_mut()
            }
        }
    }
}

enum PendingChange {
    AddMedia(PendingMedia),
    RemoveMedia(MediaId),
    ChangeDirection(MediaId, Direction),
}

struct PendingMedia {
    id: MediaId,
    local_media_id: LocalMediaId,
    media_type: MediaType,
    mid: String,
    direction: Direction,
    use_avpf: bool,
    /// Transport to use when not bundling,
    /// this is discarded when the peer chooses the bundle transport
    standalone_transport: Option<TransportId>,
    /// Transport to use when bundling
    bundle_transport: TransportId,
}

impl PendingMedia {
    fn matches_answer(
        &self,
        transports: &SlotMap<TransportId, TransportEntry>,
        desc: &MediaDescription,
    ) -> bool {
        if self.media_type != desc.media.media_type {
            return false;
        }

        if let Some(answer_mid) = &desc.mid {
            return self.mid == answer_mid.as_str();
        }

        if let Some(standalone_transport) = self.standalone_transport {
            // TODO: some sip endpoints push back on the AVPF offer and set AVP in their answer so we might need to match that here as well and adjust
            if transports[standalone_transport]
                .type_()
                .sdp_type(self.use_avpf)
                == desc.media.proto
            {
                return true;
            }
        }

        transports[self.bundle_transport]
            .type_()
            .sdp_type(self.use_avpf)
            == desc.media.proto
    }
}

impl SessionState {
    /// Create a new empty session state.
    ///
    /// `address` is placed in the SDP's connection field,
    /// peers will use that address to reach this endpoint if ICE is not being used.
    pub fn new(address: IpAddr, options: Options) -> Self {
        SessionState {
            options,
            id: u64::from(rand::random::<u16>()),
            version: u64::from(rand::random::<u16>()),
            address,
            transport_state: SessionTransportState::default(),
            next_pt: 96,
            local_media: SlotMap::with_key(),
            next_media_id: MediaId(0),
            state: Vec::new(),
            transports: SlotMap::with_key(),
            pending_changes: Vec::new(),
            transport_changes: Vec::new(),
            events: VecDeque::new(),
        }
    }

    /// Add a stun server to use for ICE
    pub fn add_stun_server(&mut self, server: SocketAddr) {
        self.transport_state.add_stun_server(server);

        for transport in self.transports.values_mut() {
            match transport {
                TransportEntry::Transport(transport) => {
                    if let Some(ice_agent) = &mut transport.ice_agent {
                        ice_agent.add_stun_server(server);
                    }
                }
                TransportEntry::TransportBuilder(transport_builder) => {
                    if let Some(ice_agent) = &mut transport_builder.ice_agent {
                        ice_agent.add_stun_server(server);
                    }
                }
            }
        }
    }

    /// Returns if any media is configured or negotiated
    pub fn has_media(&self) -> bool {
        let has_pending_media = self
            .pending_changes
            .iter()
            .any(|c| matches!(c, PendingChange::AddMedia(..)));

        (!self.state.is_empty()) || has_pending_media
    }

    /// Register codecs for a media type with a limit of how many media session by can be created
    ///
    /// Returns `None` if no more payload type numbers are available
    pub fn add_local_media(
        &mut self,
        mut codecs: Codecs,
        limit: u32,
        direction: Direction,
    ) -> Option<LocalMediaId> {
        let prev_next_pt = self.next_pt;

        // Assign dynamic payload type numbers
        for codec in &mut codecs.codecs {
            if codec.pt.is_some() {
                continue;
            }

            codec.pt = Some(self.next_pt);

            self.next_pt += 1;

            if self.next_pt > 127 {
                self.next_pt = prev_next_pt;
                return None;
            }
        }

        let mut dtmf = vec![];

        if codecs.allow_dtmf {
            let clock_rates: BTreeSet<u32> =
                codecs.codecs.iter().map(|codec| codec.clock_rate).collect();

            for clock_rate in clock_rates {
                dtmf.push((self.next_pt, clock_rate));

                if self.next_pt > 127 {
                    self.next_pt = prev_next_pt;
                    return None;
                }
            }
        }

        Some(self.local_media.insert(LocalMedia {
            codecs,
            limit,
            use_count: 0,
            direction: direction.into(),
            dtmf,
        }))
    }

    /// Request a new media session to be created
    pub fn add_media(&mut self, local_media_id: LocalMediaId, direction: Direction) -> MediaId {
        let media_id = self.next_media_id.increment();

        // Find out which type of transport to use for this media
        let transport_type = self
            .transports
            .values()
            .map(|t| t.type_())
            .max()
            .unwrap_or(self.options.offer_transport);

        // Find a transport of the previously found type to bundle
        let bundle_transport_id = self
            .transports
            .iter()
            .find(|(_, t)| t.type_() == transport_type)
            .map(|(id, _)| id);

        let (standalone_transport, bundle_transport) = match self.options.bundle_policy {
            BundlePolicy::MaxCompat => {
                let standalone_transport_id = self.transports.insert_with_key(|id| {
                    TransportEntry::TransportBuilder(TransportBuilder::new(
                        id,
                        &mut self.transport_state,
                        &mut self.transport_changes,
                        transport_type,
                        self.options.rtcp_mux_policy,
                        self.options.offer_ice,
                    ))
                });

                (
                    Some(standalone_transport_id),
                    bundle_transport_id.unwrap_or(standalone_transport_id),
                )
            }
            BundlePolicy::MaxBundle => {
                // Force bundling, only create a transport if none exists yet
                let transport_id = if let Some(existing_transport) = bundle_transport_id {
                    existing_transport
                } else {
                    self.transports.insert_with_key(|id| {
                        TransportEntry::TransportBuilder(TransportBuilder::new(
                            id,
                            &mut self.transport_state,
                            &mut self.transport_changes,
                            transport_type,
                            self.options.rtcp_mux_policy,
                            self.options.offer_ice,
                        ))
                    })
                };

                (None, transport_id)
            }
        };

        self.pending_changes
            .push(PendingChange::AddMedia(PendingMedia {
                id: media_id,
                local_media_id,
                media_type: self.local_media[local_media_id].codecs.media_type,
                mid: media_id.0.to_string(),
                direction,
                use_avpf: self.options.offer_avpf,
                standalone_transport,
                bundle_transport,
            }));

        media_id
    }

    /// Mark the media as deleted
    ///
    /// The actual deletion will be performed with the next SDP exchange
    pub fn remove_media(&mut self, media_id: MediaId) {
        if self.state.iter().any(|e| e.id() == media_id) {
            self.pending_changes
                .push(PendingChange::RemoveMedia(media_id))
        }
    }

    /// Mark the media to be updated with the newly given direction
    pub fn update_media(&mut self, media_id: MediaId, new_direction: Direction) {
        if self.state.iter().any(|e| e.id() == media_id) {
            self.pending_changes
                .push(PendingChange::ChangeDirection(media_id, new_direction))
        }
    }

    /// Returns an list all pending transport changes
    pub fn transport_changes(&mut self) -> Vec<TransportChange> {
        std::mem::take(&mut self.transport_changes)
    }

    /// Set the RTP/RTCP ports of a transport
    pub fn set_transport_ports(
        &mut self,
        transport_id: TransportId,
        ip_addrs: &[IpAddr],
        rtp_port: u16,
        rtcp_port: Option<u16>,
    ) {
        let transport = &mut self.transports[transport_id];

        match transport {
            TransportEntry::Transport(transport) => {
                transport.local_rtp_port = Some(rtp_port);
                transport.local_rtcp_port = rtcp_port;
            }
            TransportEntry::TransportBuilder(transport_builder) => {
                transport_builder.local_rtp_port = Some(rtp_port);
                transport_builder.local_rtcp_port = rtcp_port;
            }
        };

        if let Some(ice_agent) = transport.ice_agent_mut() {
            for ip in ip_addrs {
                ice_agent.add_host_addr(Component::Rtp, SocketAddr::new(*ip, rtp_port));

                if let Some(rtcp_port) = rtcp_port {
                    ice_agent.add_host_addr(Component::Rtcp, SocketAddr::new(*ip, rtcp_port));
                }
            }
        }
    }

    /// Returns a duration after which [`poll`](Self::poll) must be called
    pub fn timeout(&self) -> Option<Duration> {
        let now = Instant::now();

        let mut timeout = None;

        for transport in self.transports.values() {
            match transport {
                TransportEntry::Transport(transport) => {
                    timeout = opt_min(timeout, transport.timeout(now))
                }
                TransportEntry::TransportBuilder(transport_builder) => {
                    timeout = opt_min(timeout, transport_builder.timeout(now))
                }
            }
        }

        for media in self.state.iter() {
            timeout = opt_min(timeout, media.timeout(now));
        }

        timeout
    }

    /// Poll for new events. Call [`pop_event`](Self::pop_event) to handle them.
    pub fn poll(&mut self, now: Instant) {
        for transport in &mut self.transports.values_mut() {
            match transport {
                TransportEntry::Transport(transport) => {
                    transport.poll(now);
                }
                TransportEntry::TransportBuilder(transport_builder) => {
                    transport_builder.poll(now);
                }
            }
        }

        for media in self.state.iter_mut() {
            let transport = self.transports[media.transport_id()].unwrap_mut();
            media.poll(now, transport, &mut self.events);
        }
    }

    /// Returns the next event to process. Must be called until it return None.
    pub fn pop_event(&mut self) -> Option<Event> {
        for (transport_id, transport) in &mut self.transports {
            let event = match transport {
                TransportEntry::Transport(transport) => transport.pop_event(),
                TransportEntry::TransportBuilder(transport_builder) => {
                    transport_builder.pop_event()
                }
            };

            let Some(event) = event else {
                continue;
            };

            match event {
                TransportEvent::IceConnectionState { old, new } => {
                    return Some(Event::IceConnectionState(IceConnectionStateChanged {
                        transport_id,
                        old,
                        new,
                    }))
                }
                TransportEvent::IceGatheringState { old, new } => {
                    return Some(Event::IceGatheringState(IceGatheringStateChanged {
                        transport_id,
                        old,
                        new,
                    }))
                }
                TransportEvent::TransportConnectionState { old, new } => {
                    return Some(Event::TransportConnectionState(
                        TransportConnectionStateChanged {
                            transport_id,
                            old,
                            new,
                        },
                    ))
                }
                TransportEvent::SendData {
                    component,
                    data,
                    source,
                    target,
                } => {
                    return Some(Event::SendData {
                        transport_id,
                        component,
                        data,
                        source,
                        target,
                    })
                }
            }
        }

        self.events.pop_front()
    }

    /// Receive a packet from the given transport
    pub fn receive(&mut self, transport_id: TransportId, pkt: ReceivedPkt) {
        let transport = match &mut self.transports[transport_id] {
            TransportEntry::Transport(transport) => transport,
            TransportEntry::TransportBuilder(transport_builder) => {
                transport_builder.receive(pkt);
                return;
            }
        };

        match transport.receive(pkt) {
            ReceivedPacket::Rtp(packet) => {
                // Find the matching media using the mid field
                let entry = self
                    .state
                    .iter_mut()
                    .filter(|m| m.transport_id() == transport_id)
                    .find(|media| match (&media.mid(), &packet.extensions.mid) {
                        (Some(a), Some(b)) => a == b,
                        _ => false,
                    });

                // Try to find the correct media using the payload type
                let entry = if let Some(entry) = entry {
                    Some(entry)
                } else {
                    self.state
                        .iter_mut()
                        .filter(|media| media.transport_id() == transport_id)
                        .find(|media| media.remote_payload_types().contains(&packet.pt))
                };

                if let Some(media) = entry {
                    media.recv_rtp(packet);
                } else {
                    log::warn!("Failed to find media for RTP packet ssrc={:?}", packet.ssrc);
                }
            }
            ReceivedPacket::Rtcp(pkt_data) => {
                let rtcp_compound = match Compound::parse(&pkt_data) {
                    Ok(rtcp_compound) => rtcp_compound,
                    Err(e) => {
                        log::warn!("Failed to parse incoming RTCP packet, {e}");
                        return;
                    }
                };

                let packets: Vec<_> = match rtcp_compound.collect() {
                    Ok(packets) => packets,
                    Err(e) => {
                        log::warn!("Failed to parse incoming RTCP packet, {e}");
                        return;
                    }
                };

                if packets.is_empty() {
                    log::warn!("Discarding empty RTCP compound packet");
                    return;
                }

                // Find out what kind of rtcp packet this is
                let ssrc = match &packets[0] {
                    RtcpPacket::App(..) => {
                        // ignore
                        log::debug!("ignoring app RTCP packet");
                        return;
                    }
                    RtcpPacket::Bye(..) => {
                        // TODO: implement bye handling
                        log::warn!("ignoring BYE RTCP packet");
                        return;
                    }
                    RtcpPacket::Rr(receiver_report) => receiver_report.ssrc(),
                    RtcpPacket::Sdes(..) => {
                        log::debug!("ignoring invalid RTCP packet");
                        return;
                    }
                    RtcpPacket::Sr(sender_report) => sender_report.ssrc(),
                    RtcpPacket::TransportFeedback(transport_feedback) => {
                        transport_feedback.sender_ssrc()
                    }
                    RtcpPacket::PayloadFeedback(payload_feedback) => payload_feedback.sender_ssrc(),
                    RtcpPacket::Unknown(..) => {
                        log::debug!("ignoring unknown RTCP packet");
                        return;
                    }
                };

                let media = self
                    .state
                    .iter_mut()
                    .find(|media| media.remote_ssrc().any(|r_ssrc| r_ssrc.0 == ssrc));

                let Some(media) = media else {
                    log::warn!("Failed to find media for incoming RTCP packet");
                    return;
                };

                media.recv_rtcp(packets);
            }
            ReceivedPacket::Ignore => {
                // ignore
            }
        }
    }

    // TODO: add proper error handling
    pub fn send_rtp(&mut self, media_id: MediaId, packet: RtpPacket) {
        let media = self.state.iter_mut().find(|m| m.id() == media_id).unwrap();
        let transport = self.transports[media.transport_id()].unwrap_mut();

        media.send_rtp(transport, packet);
    }

    /// Returns the cumulative gathering state of all ice agents
    pub fn ice_gathering_state(&self) -> Option<IceGatheringState> {
        self.transports
            .values()
            .filter_map(|t| t.ice_agent())
            .map(|a| a.gathering_state())
            .min()
    }

    /// Returns the cumulative connection state of all ice agents
    pub fn ice_connection_state(&self) -> Option<IceConnectionState> {
        self.transports
            .values()
            .filter_map(|t| t.ice_agent())
            .map(|a| a.connection_state())
            .min()
    }

    /// `IceGatheringState` of the given media
    ///
    /// Returns `None` if the media doesn't exist or isn't using ICE
    pub fn ice_gathering_state_of_media(&self, media_id: MediaId) -> Option<IceGatheringState> {
        self.state
            .iter()
            .find(|m| m.id() == media_id)
            .and_then(|m| self.transports[m.transport_id()].ice_agent())
            .map(|a| a.gathering_state())
    }

    /// `IceConnectionState` of the given media
    ///
    /// Returns `None` if the media doesn't exist or isn't using ICE
    pub fn ice_connection_state_of_media(&self, media_id: MediaId) -> Option<IceConnectionState> {
        self.state
            .iter()
            .find(|m| m.id() == media_id)
            .and_then(|m| self.transports[m.transport_id()].ice_agent())
            .map(|a| a.connection_state())
    }
}

// i'm too lazy to work with the direction type, so using this as a cop out
#[derive(Debug, Clone, Copy, PartialEq)]
struct DirectionBools {
    send: bool,
    recv: bool,
}

impl From<DirectionBools> for Direction {
    fn from(value: DirectionBools) -> Self {
        match (value.send, value.recv) {
            (true, true) => Direction::SendRecv,
            (true, false) => Direction::SendOnly,
            (false, true) => Direction::RecvOnly,
            (false, false) => Direction::Inactive,
        }
    }
}

impl From<Direction> for DirectionBools {
    fn from(value: Direction) -> Self {
        let (send, recv) = match value {
            Direction::SendRecv => (true, true),
            Direction::RecvOnly => (false, true),
            Direction::SendOnly => (true, false),
            Direction::Inactive => (false, false),
        };

        Self { send, recv }
    }
}

fn opt_min<T: Ord>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (None, None) => None,
        (None, Some(b)) => Some(b),
        (Some(a), None) => Some(a),
        (Some(a), Some(b)) => Some(min(a, b)),
    }
}
