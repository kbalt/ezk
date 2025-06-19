//! # SDP media session
//!
//! See [`SdpSession`].
//!
//! Manages one or more [`RtpTransport`] and [`RtpSession`] pairs, depending on the local configuration and support for
//! transport bundling by the peer.

use super::{
    opt_min,
    rtp_transport::{Connectivity, RtpTransport, RtpTransportEvent, RtpTransportPorts},
};
use crate::{
    OpenSslContext,
    rtp_session::{RtpOutboundStream, RtpSession, RtpSessionEvent, SendRtpPacket},
    rtp_transport::RtpOrRtcp,
    sdp::{
        local_media::LocalMedia,
        media::{Media, MediaStreams},
    },
};
use bytes::Bytes;
use bytesstr::BytesStr;
use ice::{
    Component, IceAgent, IceConnectionState, IceCredentials, IceGatheringState, ReceivedPkt,
};
use openssl::hash::MessageDigest;
use rtp::{RtpExtensions, RtpPacket, rtcp_types::Compound};
use sdp_types::{
    Connection, Fingerprint, FingerprintAlgorithm, Fmtp, Group, IceCandidate, IceOptions,
    IcePassword, IceUsernameFragment, MediaDescription, Origin, Rtcp, RtpMap, Time,
    TransportProtocol,
};
use slotmap::{SlotMap, new_key_type};
use std::{
    collections::{BTreeSet, HashMap, VecDeque},
    mem::{replace, take},
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};
use transport::{OfferedTransport, TransportCreateError};

mod codecs;
mod config;
mod event;
mod local_media;
mod media;
mod rtp_extensions;
mod transport;

pub use codecs::{Codec, Codecs};
pub use config::{BundlePolicy, RtcpMuxPolicy, SdpSessionConfig, TransportType};
pub use event::{
    IceConnectionStateChanged, IceGatheringStateChanged, MediaAdded, MediaChanged, NegotiatedCodec,
    NegotiatedDtmf, SdpSessionEvent, TransportChange, TransportConnectionStateChanged,
};
pub use local_media::LocalMediaId;
pub use media::MediaId;
pub use sdp_types::{Direction, MediaType, ParseSessionDescriptionError, SessionDescription};
pub use transport::ResolveError;

#[derive(Debug, thiserror::Error)]
pub enum SdpError {
    #[error(transparent)]
    CreateTransport(#[from] TransportCreateError),
    #[error("Transport bundling is not supported by the peer")]
    PeerDoesNotSupportBundling,
    #[error("SDP answer did not contain any previously offered codec")]
    AnswerHasNoValidCodecs,
    #[error("Failed to map media m-line-index={mline} of SDP answer to any offered media")]
    AnswerContainsUnknownMedia { mline: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TransportId(u32);

new_key_type! {
    /// Internal id for transport that has been offered but negotiation hasn't been completed
    struct OfferedTransportId;
    /// Internal id for transport that is up and running
    struct EstablishedTransportId;
}

/// Reference to either a established or offered transport
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum AnyTransportId {
    Established(EstablishedTransportId),
    Offered(OfferedTransportId),
}

/// Sans-IO SDP session
pub struct SdpSession {
    config: SdpSessionConfig,

    id: u64,
    // TODO: actually increment the version
    version: u64,

    // Local ip address to use in connection attribute
    address: IpAddr,

    // Local configured media codecs
    next_pt: u8,
    local_media: SlotMap<LocalMediaId, LocalMedia>,

    // ICE
    ice_credentials: IceCredentials,
    stun_servers: Vec<SocketAddr>,

    // DTLS
    ssl_context: OpenSslContext,
    fingerprint: Fingerprint,

    // Transports
    next_transport_id: u32,
    transports: SlotMap<EstablishedTransportId, EstablishedTransport>,
    offered_transports: SlotMap<OfferedTransportId, OfferedTransport>,

    // Negotiated media
    next_media_id: MediaId,
    media: Vec<Media>,

    // Pending changes for the next SDP exchange
    pending_changes: Vec<PendingChange>,

    // Events for the user
    transport_changes: VecDeque<TransportChange>,
    events: VecDeque<SdpSessionEvent>,
}

struct EstablishedTransport {
    public_id: TransportId,
    transport: RtpTransport,
    rtp_session: RtpSession,

    /// SDP ICE candidates received when creating the transport
    /// These are used to later to match new media lines to existing transports
    initial_remote_ice_candidates: Vec<IceCandidate>,
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
    mid: BytesStr,
    direction: Direction,
    use_avpf: bool,
    /// Transport to use when not bundling,
    /// this is discarded when the peer chooses the bundle transport
    standalone_transport_id: Option<AnyTransportId>,
    /// Transport to use when bundling
    bundle_transport_id: AnyTransportId,
}

impl PendingMedia {
    fn matches_answer(
        &self,
        transports: &SlotMap<EstablishedTransportId, EstablishedTransport>,
        offered_transports: &SlotMap<OfferedTransportId, OfferedTransport>,
        desc: &MediaDescription,
    ) -> bool {
        if self.media_type != desc.media.media_type {
            return false;
        }

        if let Some(answer_mid) = &desc.mid {
            return self.mid == answer_mid.as_str();
        }

        if let Some(standalone_transport) = self.standalone_transport_id {
            let expected_sdp_transport = match standalone_transport {
                AnyTransportId::Established(transport_id) => transports[transport_id]
                    .transport
                    .type_()
                    .sdp_type(self.use_avpf),
                AnyTransportId::Offered(offered_transport_id) => offered_transports
                    [offered_transport_id]
                    .type_()
                    .sdp_type(self.use_avpf),
            };

            if expected_sdp_transport == desc.media.proto {
                return true;
            }
        }

        let expected_sdp_transport = match self.bundle_transport_id {
            AnyTransportId::Established(transport_id) => transports[transport_id]
                .transport
                .type_()
                .sdp_type(self.use_avpf),
            AnyTransportId::Offered(offered_transport_id) => offered_transports
                [offered_transport_id]
                .type_()
                .sdp_type(self.use_avpf),
        };

        expected_sdp_transport == desc.media.proto
    }
}

/// Some additional information to create a SDP answer. Must be passed into [`SdpSession::create_sdp_answer`].
///
/// All pending transport changes must be handled before creating the answer.
pub struct SdpAnswerState(Vec<SdpResponseEntry>);

enum SdpResponseEntry {
    Active(MediaId),
    Rejected {
        media_type: MediaType,
        mid: Option<BytesStr>,
    },
}

impl SdpSession {
    /// Create a new SdpSession with the given config and `address`.
    ///
    /// The `address` will be put into the SDP connection attribute, which will serve as fallback address if no ICE is
    /// used.
    pub fn new(ssl_context: OpenSslContext, address: IpAddr, config: SdpSessionConfig) -> Self {
        let digest = ssl_context
            .ctx
            .certificate()
            .expect("OpenSslContext context always contains a certificate")
            .digest(MessageDigest::sha256())
            .expect("Creating digest of certificate should not fail");

        let fingerprint = Fingerprint {
            algorithm: FingerprintAlgorithm::SHA256,
            fingerprint: digest.to_vec(),
        };

        SdpSession {
            config,
            id: u64::from(rand::random::<u16>()),
            version: u64::from(rand::random::<u16>()),
            address,
            next_pt: 96,
            local_media: SlotMap::with_key(),
            ice_credentials: IceCredentials::random(),
            stun_servers: Vec::new(),
            ssl_context,
            fingerprint,
            next_transport_id: 0,
            transports: SlotMap::with_key(),
            offered_transports: SlotMap::with_key(),
            next_media_id: MediaId(0),
            media: Vec::new(),
            pending_changes: Vec::new(),
            transport_changes: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    /// Register codecs for a media type with a limit of how many media session by can be created
    ///
    /// Returns `None` if no more payload type numbers are available
    pub fn add_local_media(
        &mut self,
        mut codecs: Codecs,
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
            direction: direction.into(),
            dtmf,
        }))
    }

    /// Add a stun server to use for ICE
    pub fn add_stun_server(&mut self, server: SocketAddr) {
        self.stun_servers.push(server);

        for transports in self.transports.values_mut() {
            match transports.transport.connectivity_mut() {
                Connectivity::Static { .. } => {}
                Connectivity::Ice(ice_agent) => ice_agent.add_stun_server(server),
            }
        }

        for transports in self.offered_transports.values_mut() {
            if let Some(ice_agent) = transports.ice_agent() {
                ice_agent.add_stun_server(server)
            }
        }
    }

    /// Request a new media session to be created
    pub fn add_media(&mut self, local_media_id: LocalMediaId, direction: Direction) -> MediaId {
        let media_id = self.next_media_id.increment();

        // Find out which type of transport to use for this media
        let transport_kind = self
            .transports
            .values()
            .map(|e| e.transport.type_())
            .max()
            .unwrap_or(self.config.offer_transport);

        // Find a transport of the previously found type to bundle
        let bundle_transport_id = self
            .transports
            .iter()
            .find(|(_, e)| e.transport.type_() == transport_kind)
            .map(|(id, _)| id);

        let (standalone_transport, bundle_transport) = match self.config.bundle_policy {
            BundlePolicy::MaxCompat => {
                let ice_agent = self.make_ice_agent();

                let public_transport_id = self.make_public_transport_id();

                let standalone_transport_id =
                    self.offered_transports.insert(OfferedTransport::new(
                        &mut self.transport_changes,
                        public_transport_id,
                        transport_kind,
                        ice_agent,
                        matches!(self.config.rtcp_mux_policy, RtcpMuxPolicy::Negotiate),
                    ));

                (
                    Some(AnyTransportId::Offered(standalone_transport_id)),
                    bundle_transport_id
                        .map(AnyTransportId::Established)
                        .unwrap_or(AnyTransportId::Offered(standalone_transport_id)),
                )
            }
            BundlePolicy::MaxBundle => {
                // Force bundling, only create a transport if none exists yet
                let transport_id = if let Some(existing_transport) = bundle_transport_id {
                    AnyTransportId::Established(existing_transport)
                } else {
                    let ice_agent = self.make_ice_agent();

                    let public_transport_id = self.make_public_transport_id();

                    let id = self.offered_transports.insert(OfferedTransport::new(
                        &mut self.transport_changes,
                        public_transport_id,
                        transport_kind,
                        ice_agent,
                        matches!(self.config.rtcp_mux_policy, RtcpMuxPolicy::Negotiate),
                    ));

                    AnyTransportId::Offered(id)
                };

                (None, transport_id)
            }
        };

        self.pending_changes
            .push(PendingChange::AddMedia(PendingMedia {
                id: media_id,
                local_media_id,
                media_type: self.local_media[local_media_id].codecs.media_type,
                mid: media_id.0.to_string().into(),
                direction,
                use_avpf: self.config.offer_avpf,
                standalone_transport_id: standalone_transport,
                bundle_transport_id: bundle_transport,
            }));

        media_id
    }

    fn make_ice_agent(&mut self) -> Option<IceAgent> {
        if !self.config.offer_ice {
            return None;
        }

        let mut ice_agent = IceAgent::new_for_offer(
            self.ice_credentials.clone(),
            true,
            matches!(self.config.rtcp_mux_policy, RtcpMuxPolicy::Require),
        );

        for server in &self.stun_servers {
            ice_agent.add_stun_server(*server);
        }

        Some(ice_agent)
    }

    /// Mark the media as deleted
    ///
    /// The actual deletion will be performed with the next SDP exchange
    pub fn remove_media(&mut self, media_id: MediaId) {
        if self.media.iter().any(|e| e.id == media_id) {
            self.pending_changes
                .push(PendingChange::RemoveMedia(media_id))
        }
    }

    /// Mark the media to be updated with the newly given direction
    pub fn update_media(&mut self, media_id: MediaId, new_direction: Direction) {
        if self.media.iter().any(|e| e.id == media_id) {
            self.pending_changes
                .push(PendingChange::ChangeDirection(media_id, new_direction))
        }
    }

    /// Returns if any media has been added
    pub fn has_media(&self) -> bool {
        let has_pending_media = self
            .pending_changes
            .iter()
            .any(|c| matches!(c, PendingChange::AddMedia(..)));

        (!self.media.is_empty()) || has_pending_media
    }

    /// Set the RTP/RTCP ports of a transport
    pub fn set_transport_ports(
        &mut self,
        transport_id: TransportId,
        ip_addrs: &[IpAddr],
        ports: RtpTransportPorts,
    ) {
        let ice_agent = if let Some(EstablishedTransport { transport, .. }) = self
            .transports
            .values_mut()
            .find(|e| e.public_id == transport_id)
        {
            transport.set_ports(ports);

            match transport.connectivity_mut() {
                Connectivity::Static { .. } => None,
                Connectivity::Ice(ice_agent) => Some(ice_agent),
            }
        } else if let Some(transport) = self
            .offered_transports
            .values_mut()
            .find(|e| e.public_id == transport_id)
        {
            transport.set_ports(ports);
            transport.ice_agent()
        } else {
            return;
        };

        if let Some(ice_agent) = ice_agent {
            for ip in ip_addrs {
                ice_agent.add_host_addr(Component::Rtp, SocketAddr::new(*ip, ports.rtp));

                if let Some(rtcp_port) = ports.rtcp {
                    ice_agent.add_host_addr(Component::Rtcp, SocketAddr::new(*ip, rtcp_port));
                }
            }
        }
    }

    /// Receive a SDP offer in this session.
    ///
    /// Returns an opaque response state object which can be used to create the actual response SDP.
    /// Before the SDP response can be created, the user must make all necessary changes to the transports using [`pop_transport_change`](Self::pop_transport_change)
    ///
    /// The actual answer can be created using [`create_sdp_answer`](Self::create_sdp_answer).
    pub fn receive_sdp_offer(
        &mut self,
        offer: SessionDescription,
    ) -> Result<SdpAnswerState, SdpError> {
        let mut new_state = vec![];
        let mut response = vec![];

        for (mline, remote_media_desc) in offer.media_descriptions.iter().enumerate() {
            let requested_direction: DirectionBools = remote_media_desc.direction.flipped().into();

            // First thing: Search the current state for an entry that matches this description - and update accordingly
            let matched_position = self
                .media
                .iter()
                .position(|media| media.matches(&self.transports, &offer, remote_media_desc));

            if let Some(position) = matched_position {
                self.update_active_media(requested_direction, self.media[position].id);
                let media = self.media.remove(position);
                response.push(SdpResponseEntry::Active(media.id));
                new_state.push(media);
                continue;
            }

            // Choose local media for this media description
            let chosen_media = self.local_media.iter_mut().find_map(|(id, local_media)| {
                local_media
                    .maybe_use_for_offer(remote_media_desc)
                    .map(|config| (id, config))
            });

            let Some((local_media_id, chosen_codec)) = chosen_media else {
                // no local media found for this
                response.push(SdpResponseEntry::Rejected {
                    media_type: remote_media_desc.media.media_type,
                    mid: remote_media_desc.mid.clone(),
                });

                log::debug!("Rejecting mline={mline}, no compatible local media found");
                continue;
            };

            // Get or create transport for the m-line
            let transport_id =
                self.get_or_create_established_transport(&new_state, &offer, remote_media_desc)?;

            let recv_fmtp = remote_media_desc
                .fmtp
                .iter()
                .find(|f| f.format == chosen_codec.remote_pt)
                .map(|f| f.params.to_string());

            let dtmf = if let Some(dtmf_pt) = chosen_codec.dtmf {
                let fmtp = remote_media_desc
                    .fmtp
                    .iter()
                    .find(|fmtp| fmtp.format == dtmf_pt)
                    .map(|fmtp| fmtp.params.to_string());

                Some(NegotiatedDtmf { pt: dtmf_pt, fmtp })
            } else {
                None
            };

            let media_id = self.next_media_id.increment();
            self.events
                .push_back(SdpSessionEvent::MediaAdded(MediaAdded {
                    id: media_id,
                    transport_id: self.transports[transport_id].public_id,
                    local_media_id,
                    direction: chosen_codec.direction.into(),
                    codec: NegotiatedCodec {
                        send_pt: chosen_codec.remote_pt,
                        recv_pt: chosen_codec.remote_pt,
                        name: chosen_codec.codec.name.clone(),
                        clock_rate: chosen_codec.codec.clock_rate,
                        channels: chosen_codec.codec.channels,
                        send_fmtp: chosen_codec.codec.fmtp.clone(),
                        recv_fmtp,
                        dtmf,
                    },
                }));

            response.push(SdpResponseEntry::Active(media_id));
            new_state.push(Media {
                id: media_id,
                local_media_id,
                media_type: remote_media_desc.media.media_type,
                use_avpf: is_avpf(&remote_media_desc.media.proto),
                mid: remote_media_desc.mid.clone(),
                direction: chosen_codec.direction,
                streams: MediaStreams::default(),
                transport_id,
                codec_pt: chosen_codec.remote_pt,
                codec: chosen_codec.codec,
                dtmf_pt: chosen_codec.dtmf,
            });
        }

        // Store new state and destroy all media sessions
        let removed_media = replace(&mut self.media, new_state);

        for media in removed_media {
            self.events
                .push_back(SdpSessionEvent::MediaRemoved(media.id));
        }

        self.remove_unused_transports();

        Ok(SdpAnswerState(response))
    }

    /// Get or create a transport for the given media description
    fn get_or_create_established_transport(
        &mut self,
        new_state: &[Media],
        session_desc: &SessionDescription,
        remote_media_desc: &MediaDescription,
    ) -> Result<EstablishedTransportId, TransportCreateError> {
        // See if there's a transport to be reused via BUNDLE group
        if let Some(mid) = &remote_media_desc.mid {
            if let Some(transport) = self.find_bundled_transport(new_state, session_desc, mid) {
                return Ok(transport);
            }
        }

        // Try and to find a transport outside of the bundle group by looking a the address attribute
        if let Some(transport) =
            self.find_similar_looking_transport(session_desc, remote_media_desc)
        {
            return Ok(transport);
        }

        let id = self.make_public_transport_id();

        let transport = transport::create_from_offer(
            &self.ssl_context,
            &self.ice_credentials,
            &self.stun_servers,
            &mut self.transport_changes,
            id,
            session_desc,
            remote_media_desc,
        )?;

        Ok(self.transports.insert(EstablishedTransport {
            public_id: id,
            transport,
            rtp_session: RtpSession::new(),
            initial_remote_ice_candidates: remote_media_desc.ice_candidates.clone(),
        }))
    }

    /// Some implementations like to replace the entire session description with their own mids but reuse the
    /// previously negotiated transport. This means that the transport is now "unused" from our point of view and
    /// the peer has created a new BUNDLE group. Following is a futile effort to try and catch that.
    fn find_similar_looking_transport(
        &mut self,
        session_desc: &SessionDescription,
        remote_media_desc: &MediaDescription,
    ) -> Option<EstablishedTransportId> {
        self.transports
            .iter()
            .find(|(_, t)| match t.transport.connectivity() {
                Connectivity::Static {
                    remote_rtp_address,
                    remote_rtcp_address,
                } => {
                    let Ok((other_remote_rtp_addr, other_remote_rtcp_addr)) =
                        transport::resolve::resolve_rtp_and_rtcp_address(
                            session_desc,
                            remote_media_desc,
                        )
                    else {
                        return false;
                    };

                    *remote_rtp_address == other_remote_rtp_addr
                        && *remote_rtcp_address == other_remote_rtcp_addr
                }
                Connectivity::Ice(..) => {
                    // Test if any of the host candidates have the same address
                    t.initial_remote_ice_candidates.iter().any(|c| {
                        c.typ == "host"
                            && remote_media_desc
                                .ice_candidates
                                .iter()
                                .any(|rc| rc.typ == "host" && c.address == rc.address)
                    })
                }
            })
            .map(|(t, _)| t)
    }

    fn find_bundled_transport(
        &self,
        new_state: &[Media],
        offer: &SessionDescription,
        mid: &BytesStr,
    ) -> Option<EstablishedTransportId> {
        let group = offer
            .group
            .iter()
            .find(|g| g.typ == "BUNDLE" && g.mids.contains(mid))?;

        new_state.iter().chain(&self.media).find_map(|media| {
            let mid = media.mid.as_ref()?;

            group
                .mids
                .iter()
                .any(|v| v == mid.as_str())
                .then_some(media.transport_id)
        })
    }

    /// Receive a SDP answer after sending an offer.
    pub fn receive_sdp_answer(&mut self, answer: SessionDescription) -> Result<(), SdpError> {
        // Backlog of already received RTP/RTCP packets per transport before the setup was complete
        // Will be handled at the end of SDP answer processing
        let mut backlog_of_early_received_rtp_or_rtcp = HashMap::new();

        'next_media_desc: for (mline, remote_media_desc) in
            answer.media_descriptions.iter().enumerate()
        {
            // Skip any rejected answers
            if remote_media_desc.direction == Direction::Inactive {
                continue;
            }

            let requested_direction: DirectionBools = remote_media_desc.direction.flipped().into();

            // Try to match an active media session, while filtering out media that is to be deleted
            for media in &mut self.media {
                let pending_removal = self
                    .pending_changes
                    .iter()
                    .any(|c| matches!(c, PendingChange::RemoveMedia(id) if *id == media.id));

                if pending_removal {
                    // Ignore this active media since it's supposed to be removed
                    continue;
                }

                if media.matches(&self.transports, &answer, remote_media_desc) {
                    let media_id = media.id;
                    self.update_active_media(requested_direction, media_id);
                    continue 'next_media_desc;
                }
            }

            // Try to match a new media session
            for (i, pending_change) in self.pending_changes.iter().enumerate() {
                let PendingChange::AddMedia(pending_media) = pending_change else {
                    continue;
                };

                if !pending_media.matches_answer(
                    &self.transports,
                    &self.offered_transports,
                    remote_media_desc,
                ) {
                    continue;
                }

                // Check which transport to use, (standalone or bundled)
                let is_bundled = answer
                    .group
                    .iter()
                    .any(|group| group.typ == "BUNDLE" && group.mids.contains(&pending_media.mid));

                let transport_id = if is_bundled {
                    pending_media.bundle_transport_id
                } else {
                    pending_media
                        .standalone_transport_id
                        .ok_or(SdpError::PeerDoesNotSupportBundling)?
                };

                // Build transport if necessary
                let (transport_id, public_transport_id) = match transport_id {
                    AnyTransportId::Established(id) => (id, self.transports[id].public_id),
                    AnyTransportId::Offered(id) => {
                        let offered_transport = self
                            .offered_transports
                            .remove(id)
                            .expect("Internal references must be valid");

                        let public_id = offered_transport.public_id;

                        let (transport, early_received_rtp_or_rtcp) = offered_transport
                            .build_from_answer(
                                &self.ssl_context,
                                &mut self.transport_changes,
                                &answer,
                                remote_media_desc,
                            )?;

                        let id = self.transports.insert(EstablishedTransport {
                            public_id,
                            transport,
                            rtp_session: RtpSession::new(),
                            initial_remote_ice_candidates: remote_media_desc.ice_candidates.clone(),
                        });

                        if !early_received_rtp_or_rtcp.is_empty() {
                            backlog_of_early_received_rtp_or_rtcp
                                .insert(id, early_received_rtp_or_rtcp);
                        }

                        (id, public_id)
                    }
                };

                let chosen_codec = self.local_media[pending_media.local_media_id]
                    .choose_codec_from_answer(remote_media_desc)
                    .ok_or(SdpError::AnswerHasNoValidCodecs)?;

                let recv_fmtp = remote_media_desc
                    .fmtp
                    .iter()
                    .find(|f| f.format == chosen_codec.remote_pt)
                    .map(|f| f.params.to_string());

                let dtmf = if let Some(dtmf_pt) = chosen_codec.dtmf {
                    let fmtp = remote_media_desc
                        .fmtp
                        .iter()
                        .find(|fmtp| fmtp.format == dtmf_pt)
                        .map(|fmtp| fmtp.params.to_string());

                    Some(NegotiatedDtmf { pt: dtmf_pt, fmtp })
                } else {
                    None
                };

                self.events
                    .push_back(SdpSessionEvent::MediaAdded(MediaAdded {
                        id: pending_media.id,
                        transport_id: public_transport_id,
                        local_media_id: pending_media.local_media_id,
                        direction: chosen_codec.direction.into(),
                        codec: NegotiatedCodec {
                            send_pt: chosen_codec.remote_pt,
                            recv_pt: chosen_codec.remote_pt,
                            name: chosen_codec.codec.name.clone(),
                            clock_rate: chosen_codec.codec.clock_rate,
                            channels: chosen_codec.codec.channels,
                            send_fmtp: chosen_codec.codec.fmtp.clone(),
                            recv_fmtp,
                            dtmf,
                        },
                    }));

                self.media.push(Media {
                    id: pending_media.id,
                    local_media_id: pending_media.local_media_id,
                    media_type: pending_media.media_type,
                    use_avpf: pending_media.use_avpf,
                    mid: remote_media_desc.mid.clone(),
                    direction: chosen_codec.direction,
                    streams: MediaStreams::default(),
                    transport_id,
                    codec_pt: chosen_codec.remote_pt,
                    codec: chosen_codec.codec,
                    dtmf_pt: chosen_codec.dtmf,
                });

                // remove the matched pending added media to avoid doubly matching it
                self.pending_changes.remove(i);

                continue 'next_media_desc;
            }

            return Err(SdpError::AnswerContainsUnknownMedia { mline });
        }

        // remove all media that is pending removal
        for change in take(&mut self.pending_changes) {
            if let PendingChange::RemoveMedia(media_id) = change {
                self.media.retain(|m| {
                    if m.id == media_id {
                        if let Some(ssrc) = m.streams.tx {
                            self.transports[m.transport_id]
                                .rtp_session
                                .remove_tx_stream(ssrc);
                        }

                        if let Some(ssrc) = m.streams.rx {
                            self.transports[m.transport_id]
                                .rtp_session
                                .remove_rx_stream(ssrc);
                        }

                        self.events
                            .push_back(SdpSessionEvent::MediaRemoved(media_id));
                        false
                    } else {
                        true
                    }
                });
            }
        }

        // Handle the backlog of early received RTP/RTCP packets
        for (id, early_received_rtp_or_rtcp) in backlog_of_early_received_rtp_or_rtcp {
            let transport = &mut self.transports[id];

            for (instant, rtp_or_rtcp) in early_received_rtp_or_rtcp {
                Self::handle_received_rtp_or_rtcp(
                    &mut self.media,
                    id,
                    transport,
                    rtp_or_rtcp,
                    instant,
                );
            }
        }

        self.remove_unused_transports();

        Ok(())
    }

    fn update_active_media(&mut self, requested_direction: DirectionBools, media_id: MediaId) {
        let media = self
            .media
            .iter_mut()
            .find(|media| media.id == media_id)
            .expect("media_id must be valid");

        if media.direction != requested_direction {
            self.events
                .push_back(SdpSessionEvent::MediaChanged(MediaChanged {
                    id: media_id,
                    old_direction: media.direction.into(),
                    new_direction: requested_direction.into(),
                }));

            media.direction = requested_direction;
        }
    }

    fn remove_unused_transports(&mut self) {
        self.offered_transports.retain(|id, transport| {
            let in_use_by_pending = self.pending_changes.iter().any(|change| {
                let id = AnyTransportId::Offered(id);

                if let PendingChange::AddMedia(add_media) = change {
                    add_media.bundle_transport_id == id
                        || add_media.standalone_transport_id == Some(id)
                } else {
                    false
                }
            });

            if !in_use_by_pending {
                self.transport_changes
                    .push_back(TransportChange::Remove(transport.public_id));
            }

            in_use_by_pending
        });

        self.transports.retain(|id, transport| {
            // Is the transport in use by active media?
            let in_use_by_active = self.media.iter().any(|media| media.transport_id == id);

            // Is the transport in use by any pending changes?
            let in_use_by_pending = self.pending_changes.iter().any(|change| {
                let id = AnyTransportId::Established(id);

                if let PendingChange::AddMedia(add_media) = change {
                    add_media.bundle_transport_id == id
                        || add_media.standalone_transport_id == Some(id)
                } else {
                    false
                }
            });

            let in_use = in_use_by_active || in_use_by_pending;

            if !in_use {
                self.transport_changes
                    .push_back(TransportChange::Remove(transport.public_id));
            }

            in_use
        });
    }

    /// Create an SDP Answer from a given state, which must be created by a previous call to [`SdpSession::receive_sdp_offer`].
    ///
    /// # Panics
    ///
    /// This function may panic if any transport has not been assigned a port,
    /// the given state is from an other Session or the current Session has changed since the state has been created.
    pub fn create_sdp_answer(&mut self, state: SdpAnswerState) -> SessionDescription {
        let mut media_descriptions = vec![];

        for entry in state.0 {
            match entry {
                SdpResponseEntry::Active(media_id) => {
                    let media = self
                        .media
                        .iter()
                        .find(|media| media.id == media_id)
                        .expect("SdpAnswerState must be valid");

                    media_descriptions.push(self.media_description_for_active(media, None));
                }
                SdpResponseEntry::Rejected { media_type, mid } => {
                    let mut desc = MediaDescription::rejected(media_type);
                    desc.mid = mid;
                    media_descriptions.push(desc);
                }
            }
        }

        let mut sess_desc = SessionDescription {
            origin: Origin {
                username: "-".into(),
                session_id: self.id.to_string().into(),
                session_version: self.version.to_string().into(),
                address: self.address.into(),
            },
            name: "-".into(),
            connection: Some(Connection {
                address: self.address.into(),
                ttl: None,
                num: None,
            }),
            bandwidth: vec![],
            time: Time { start: 0, stop: 0 },
            direction: Direction::SendRecv,
            group: self.build_bundle_groups(false),
            extmap: vec![],
            extmap_allow_mixed: true,
            ice_lite: false,
            ice_options: IceOptions::default(),
            ice_ufrag: None,
            ice_pwd: None,
            setup: None,
            fingerprint: vec![],
            attributes: vec![],
            media_descriptions,
        };

        self.decorate_session_desc(&mut sess_desc);

        sess_desc
    }

    /// Create a SDP offer from the current state of the `SdpSession`, this includes any pending media.
    pub fn create_sdp_offer(&mut self) -> SessionDescription {
        let mut media_descriptions = vec![];

        // Put the current media sessions in the offer
        for media in &self.media {
            let mut override_direction = None;

            // Apply requested changes
            for change in &self.pending_changes {
                match change {
                    PendingChange::AddMedia(..) => {}
                    PendingChange::RemoveMedia(media_id) => {
                        if media.id == *media_id {
                            continue;
                        }
                    }
                    PendingChange::ChangeDirection(media_id, direction) => {
                        if media.id == *media_id {
                            override_direction = Some(*direction);
                        }
                    }
                }
            }

            media_descriptions.push(self.media_description_for_active(media, override_direction));
        }

        // Add all pending added media
        for change in &self.pending_changes {
            let PendingChange::AddMedia(pending_media) = change else {
                continue;
            };

            let transport_id = pending_media
                .standalone_transport_id
                .unwrap_or(pending_media.bundle_transport_id);

            let (ports, transport_kind) = match transport_id {
                AnyTransportId::Established(id) => {
                    let transport = &self.transports[id].transport;
                    let ports = transport.require_ports();
                    let kind = transport.type_();

                    (ports, kind)
                }
                AnyTransportId::Offered(id) => {
                    let transport = &self.offered_transports[id];
                    let ports = transport.require_ports();
                    let kind = transport.type_();

                    (ports, kind)
                }
            };

            let mut rtpmap = vec![];
            let mut fmtp = vec![];
            let mut fmts = vec![];

            let local_media = &self.local_media[pending_media.local_media_id];

            for codec in &local_media.codecs.codecs {
                let pt = codec.pt.expect("pt is set when adding the codec");

                fmts.push(pt);

                rtpmap.push(RtpMap {
                    payload: pt,
                    encoding: codec.name.as_ref().into(),
                    clock_rate: codec.clock_rate,
                    params: codec.channels.map(|c| c.to_string().into()),
                });

                if let Some(param) = &codec.fmtp {
                    fmtp.push(Fmtp {
                        format: pt,
                        params: param.as_str().into(),
                    });
                }
            }

            for &(pt, clock_rate) in &local_media.dtmf {
                rtpmap.push(RtpMap {
                    payload: pt,
                    encoding: "telephone-event".into(),
                    clock_rate,
                    params: None,
                });
                fmts.push(pt);
            }

            let mut media_desc = MediaDescription {
                media: sdp_types::Media {
                    media_type: local_media.codecs.media_type,
                    port: ports.rtp,
                    ports_num: None,
                    proto: transport_kind.sdp_type(pending_media.use_avpf),
                    fmts,
                },
                connection: None,
                bandwidth: vec![],
                direction: pending_media.direction,
                rtcp: ports.rtcp.map(|port| Rtcp {
                    port,
                    address: None,
                }),
                // always offer rtcp-mux
                rtcp_mux: true,
                mid: Some(pending_media.mid.as_str().into()),
                rtpmap,
                fmtp,
                ice_ufrag: None,
                ice_pwd: None,
                ice_candidates: vec![],
                ice_end_of_candidates: false,
                crypto: vec![],
                extmap: vec![],
                extmap_allow_mixed: false,
                ssrc: vec![],
                setup: None,
                fingerprint: vec![],
                attributes: vec![],
            };

            match transport_id {
                AnyTransportId::Established(id) => {
                    transport::populate_desc(&self.transports[id].transport, &mut media_desc)
                }
                AnyTransportId::Offered(id) => {
                    self.offered_transports[id].populate_desc(&mut media_desc)
                }
            }

            media_descriptions.push(media_desc);
        }

        let mut sess_desc = SessionDescription {
            origin: Origin {
                username: "-".into(),
                session_id: self.id.to_string().into(),
                session_version: self.version.to_string().into(),
                address: self.address.into(),
            },
            name: "-".into(),
            connection: Some(Connection {
                address: self.address.into(),
                ttl: None,
                num: None,
            }),
            bandwidth: vec![],
            time: Time { start: 0, stop: 0 },
            direction: Direction::SendRecv,
            group: self.build_bundle_groups(true),
            extmap: vec![],
            extmap_allow_mixed: true,
            ice_lite: false,
            ice_options: IceOptions::default(),
            ice_ufrag: None,
            ice_pwd: None,
            setup: None,
            fingerprint: vec![],
            attributes: vec![],
            media_descriptions,
        };

        self.decorate_session_desc(&mut sess_desc);

        sess_desc
    }

    fn decorate_session_desc(&mut self, sess_desc: &mut SessionDescription) {
        let use_ice = self
            .transports
            .values()
            .any(|e| matches!(e.transport.connectivity(), Connectivity::Ice(..)))
            || self
                .offered_transports
                .values_mut()
                .any(|t| t.ice_agent().is_some());

        if use_ice {
            sess_desc.ice_ufrag = Some(IceUsernameFragment {
                ufrag: self.ice_credentials.ufrag.clone().into(),
            });

            sess_desc.ice_pwd = Some(IcePassword {
                pwd: self.ice_credentials.pwd.clone().into(),
            });
        }

        let use_dtls = self
            .transports
            .values()
            .any(|e| e.transport.type_() == TransportType::DtlsSrtp)
            || self.offered_transports.values().any(|t| t.is_dtls());

        if use_dtls {
            sess_desc.fingerprint.push(self.fingerprint.clone());
        }
    }

    fn media_description_for_active(
        &self,
        media: &Media,
        override_direction: Option<Direction>,
    ) -> MediaDescription {
        let mut rtpmap = vec![];
        let mut fmtp = vec![];

        rtpmap.push(RtpMap {
            payload: media.codec_pt,
            encoding: media.codec.name.as_ref().into(),
            clock_rate: media.codec.clock_rate,
            params: Default::default(),
        });

        fmtp.extend(media.codec.fmtp.as_ref().map(|param| Fmtp {
            format: media.codec_pt,
            params: param.as_str().into(),
        }));

        let transport = &self.transports[media.transport_id].transport;
        let ports = transport.require_ports();

        if let Some(dtmf_pt) = media.dtmf_pt {
            rtpmap.push(RtpMap {
                payload: dtmf_pt,
                encoding: "telephone-event".into(),
                clock_rate: media.codec.clock_rate,
                params: None,
            });
        }

        let mut media_desc = MediaDescription {
            media: sdp_types::Media {
                media_type: self.local_media[media.local_media_id].codecs.media_type,
                port: ports.rtp,
                ports_num: None,
                proto: transport.type_().sdp_type(media.use_avpf),
                fmts: vec![media.codec_pt],
            },
            connection: None,
            bandwidth: vec![],
            direction: override_direction.unwrap_or(media.direction.into()),
            rtcp: ports.rtcp.map(|port| Rtcp {
                port,
                address: None,
            }),
            rtcp_mux: transport.require_ports().rtcp.is_none(),
            mid: media.mid.clone(),
            rtpmap,
            fmtp,
            ice_ufrag: None,
            ice_pwd: None,
            ice_candidates: vec![],
            ice_end_of_candidates: false,
            crypto: vec![],
            extmap: vec![],
            extmap_allow_mixed: false,
            ssrc: vec![],
            setup: None,
            fingerprint: vec![],
            attributes: vec![],
        };

        transport::populate_desc(transport, &mut media_desc);

        media_desc
    }

    fn build_bundle_groups(&self, include_pending_changes: bool) -> Vec<Group> {
        let mut bundle_groups: HashMap<AnyTransportId, Vec<BytesStr>> = HashMap::new();

        for media in &self.media {
            if let Some(mid) = &media.mid {
                bundle_groups
                    .entry(AnyTransportId::Established(media.transport_id))
                    .or_default()
                    .push(mid.clone());
            }
        }

        if include_pending_changes {
            for change in &self.pending_changes {
                if let PendingChange::AddMedia(pending_media) = change {
                    bundle_groups
                        .entry(pending_media.bundle_transport_id)
                        .or_default()
                        .push(pending_media.mid.clone());
                }
            }
        }

        bundle_groups
            .into_values()
            .filter(|c| !c.is_empty())
            .map(|mids| Group {
                typ: BytesStr::from_static("BUNDLE"),
                mids,
            })
            .collect()
    }

    fn make_public_transport_id(&mut self) -> TransportId {
        let v = TransportId(self.next_transport_id);
        self.next_transport_id += 1;
        v
    }

    // ==== Post Setup

    /// Returns a duration after which [`poll`](Self::poll) must be called
    pub fn timeout(&self, now: Instant) -> Option<Duration> {
        let mut timeout = None;

        for EstablishedTransport {
            transport,
            rtp_session,
            ..
        } in self.transports.values()
        {
            timeout = opt_min(timeout, rtp_session.timeout(now));
            timeout = opt_min(timeout, transport.timeout(now));
        }

        for transport in self.offered_transports.values() {
            timeout = opt_min(timeout, transport.timeout(now));
        }

        timeout
    }

    /// Drive progress in the session forward.
    ///
    /// Creates events which can be accessed using [`pop_event`](Self::pop_event).
    pub fn poll(&mut self, now: Instant) {
        for EstablishedTransport {
            public_id,
            transport,
            rtp_session,
            ..
        } in self.transports.values_mut()
        {
            // Poll the transport itself
            transport.poll(now);

            while let Some(event) = transport.pop_event() {
                self.events
                    .extend(Self::map_transport_event(*public_id, event));
            }

            let mtu = transport.apply_overhead(self.config.mtu);

            // Poll the associated RTP session only if the transport is connected
            let Some(mut writer) = transport.writer() else {
                continue;
            };

            while let Some(event) = rtp_session.poll(now, mtu) {
                match event {
                    RtpSessionEvent::ReceiveRtp(rtp_packet) => {
                        let media = self
                            .media
                            .iter()
                            .find(|m| m.streams.rx == Some(rtp_packet.ssrc));

                        if let Some(media) = media {
                            self.events.push_back(SdpSessionEvent::ReceiveRTP {
                                media_id: media.id,
                                rtp_packet,
                            });
                        } else {
                            log::warn!(
                                "Failed to find media for received RTP packet ssrc={:?}",
                                rtp_packet.ssrc
                            );
                        }
                    }
                    RtpSessionEvent::SendRtp(rtp_packet) => {
                        writer.send_rtp(rtp_packet);
                    }
                    RtpSessionEvent::SendRtcp(rtcp_packet) => {
                        writer.send_rctp(rtcp_packet);
                    }
                }
            }

            while let Some(event) = transport.pop_event() {
                self.events
                    .extend(Self::map_transport_event(*public_id, event));
            }
        }

        for transport in self.offered_transports.values_mut() {
            transport.poll(now);

            while let Some(event) = transport.pop_event() {
                self.events
                    .extend(Self::map_transport_event(transport.public_id, event));
            }
        }
    }

    fn map_transport_event(
        transport_id: TransportId,
        event: RtpTransportEvent,
    ) -> Option<SdpSessionEvent> {
        match event {
            RtpTransportEvent::IceGatheringState { old, new } => Some(
                SdpSessionEvent::IceGatheringState(IceGatheringStateChanged {
                    transport_id,
                    old,
                    new,
                }),
            ),
            RtpTransportEvent::IceConnectionState { old, new } => Some(
                SdpSessionEvent::IceConnectionState(IceConnectionStateChanged {
                    transport_id,
                    old,
                    new,
                }),
            ),
            RtpTransportEvent::TransportConnectionState { old, new } => Some(
                SdpSessionEvent::TransportConnectionState(TransportConnectionStateChanged {
                    transport_id,
                    old,
                    new,
                }),
            ),
            RtpTransportEvent::SendData {
                component,
                data,
                source,
                target,
            } => Some(SdpSessionEvent::SendData {
                transport_id,
                component,
                data,
                source,
                target,
            }),
        }
    }

    /// Returns if there are events in the internal queue that have to be handled using [`SdpSession::pop_event`]
    pub fn has_events(&mut self) -> bool {
        !self.events.is_empty()
    }

    /// Pops a [`SdpSessionEvent`] from the internal events queue
    pub fn pop_event(&mut self) -> Option<SdpSessionEvent> {
        self.events.pop_front()
    }

    /// Pops a [`TransportChange`] from the internal events queue
    ///
    /// Must be called until it returns `None` after calling [`add_media`](Self::add_media), [`receive_sdp_offer`](Self::receive_sdp_offer) or [`receive_sdp_answer`](Self::receive_sdp_answer).
    pub fn pop_transport_change(&mut self) -> Option<TransportChange> {
        self.transport_changes.pop_front()
    }

    /// Pass a received packet to the session
    pub fn receive(&mut self, now: Instant, transport_id: TransportId, pkt: ReceivedPkt) {
        if let Some(transport) = self
            .offered_transports
            .values_mut()
            .find(|t| t.public_id == transport_id)
        {
            transport.receive(now, pkt);

            while let Some(event) = transport.pop_event() {
                self.events
                    .extend(Self::map_transport_event(transport.public_id, event));
            }
        } else if let Some((transport_id, transport)) = self
            .transports
            .iter_mut()
            .find(|(_, t)| t.public_id == transport_id)
        {
            let public_id = transport.public_id;

            if let Some(rtp_or_rtcp) = transport.transport.receive(pkt) {
                Self::handle_received_rtp_or_rtcp(
                    &mut self.media,
                    transport_id,
                    transport,
                    rtp_or_rtcp,
                    now,
                );
            }

            while let Some(event) = transport.transport.pop_event() {
                self.events
                    .extend(Self::map_transport_event(public_id, event));
            }
        } else {
            log::warn!("SdpSession::receive with unknown TransportId called");
        }
    }

    fn handle_received_rtp_or_rtcp(
        media: &mut [Media],
        transport_id: EstablishedTransportId,
        transport: &mut EstablishedTransport,
        rtp_or_rtcp: RtpOrRtcp,
        now: Instant,
    ) {
        match rtp_or_rtcp {
            RtpOrRtcp::Rtp(rtp_packet) => {
                if let Some(rx_stream) = transport.rtp_session.rx_stream(rtp_packet.ssrc) {
                    rx_stream.receive_rtp(now, rtp_packet);
                } else {
                    Self::handle_new_ssrc(
                        media,
                        &mut transport.rtp_session,
                        now,
                        transport_id,
                        rtp_packet,
                    );
                }
            }
            RtpOrRtcp::Rtcp(rtcp_packet) => {
                let compound = match Compound::parse(&rtcp_packet) {
                    Ok(compound) => compound,
                    Err(e) => {
                        log::warn!("Failed to parse incoming RTCP packet: {e}");
                        return;
                    }
                };

                transport.rtp_session.receive_rtcp(now, compound);
            }
        }
    }

    fn handle_new_ssrc(
        media: &mut [Media],
        rtp_session: &mut RtpSession,
        now: Instant,
        transport_id: EstablishedTransportId,
        rtp_packet: RtpPacket,
    ) {
        // Find media that matches the incoming RTP packet
        let media = media.iter_mut().find(|media| {
            // media must use the same transport and be negotiated to receive data
            if media.transport_id != transport_id || !media.direction.recv {
                return false;
            }

            // Does it match the mid attribute?
            if let (Some(a), Some(b)) = (&media.mid, &rtp_packet.extensions.mid) {
                return a.as_bytes() == b;
            }

            // If mid cannot be matched since either its not sent or we don't expect it to be sent, check for the payload type instead
            media.accepts_pt(rtp_packet.pt)
        });

        let Some(media) = media else {
            // TODO: instead of discarding the packet & stream, keep it and try to rematch later when SDP negotiation is finished?
            log::warn!(
                "RTP packet with ssrc={} cannot be mapped to any negotiated media, ignoring",
                rtp_packet.ssrc.0
            );
            return;
        };

        let rx_stream = rtp_session.new_rx_stream(rtp_packet.ssrc, media.codec.clock_rate);

        media.streams.rx = Some(rtp_packet.ssrc);

        rx_stream.receive_rtp(now, rtp_packet);
    }

    /// Maximum allowed RTP payload size for given media
    pub fn max_payload_size_for_media(&self, media_id: MediaId) -> Option<usize> {
        let media = self.media.iter().find(|m| m.id == media_id)?;

        // TODO: this will need revisiting when more RTP extensions are added
        let mtu = if let Some(mid) = &media.mid {
            self.config.mtu.with_additional_rtp_extension(mid.len())
        } else {
            self.config.mtu
        };

        Some(
            self.transports[media.transport_id]
                .transport
                .apply_overhead(mtu)
                .for_rtp_payload(),
        )
    }

    /// Returns a temporary [`MediaWriter`] which can be used to send RTP packets
    pub fn writer(&mut self, id: MediaId) -> Option<MediaWriter<'_>> {
        let media = self.media.iter_mut().find(|m| m.id == id)?;

        if !media.direction.send {
            return None;
        }

        let transport = &mut self.transports[media.transport_id];

        let stream = match media.streams.tx {
            Some(ssrc) => transport.rtp_session.tx_stream(ssrc)?,
            None => {
                let stream = transport.rtp_session.new_tx_stream(media.codec.clock_rate);
                media.streams.tx = Some(stream.ssrc());
                stream
            }
        };

        Some(MediaWriter { media, stream })
    }

    /// Returns the cumulative gathering state of all ice agents
    pub fn ice_gathering_state(&self) -> Option<IceGatheringState> {
        self.transports
            .values()
            .filter_map(|t| match t.transport.connectivity() {
                Connectivity::Static { .. } => None,
                Connectivity::Ice(ice_agent) => Some(ice_agent.gathering_state()),
            })
            .min()
    }

    /// Returns the cumulative connection state of all ice agents
    pub fn ice_connection_state(&self) -> Option<IceConnectionState> {
        self.transports
            .values()
            .filter_map(|t| match t.transport.connectivity() {
                Connectivity::Static { .. } => None,
                Connectivity::Ice(ice_agent) => Some(ice_agent.connection_state()),
            })
            .min()
    }
}

fn is_avpf(t: &TransportProtocol) -> bool {
    match t {
        TransportProtocol::RtpAvpf
        | TransportProtocol::RtpSavpf
        | TransportProtocol::UdpTlsRtpSavpf => true,
        TransportProtocol::Unspecified
        | TransportProtocol::RtpAvp
        | TransportProtocol::RtpSavp
        | TransportProtocol::UdpTlsRtpSavp
        | TransportProtocol::Other(..) => false,
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

pub struct MediaWriter<'a> {
    media: &'a Media,
    stream: &'a mut RtpOutboundStream,
}

impl MediaWriter<'_> {
    pub fn send_rtp(&mut self, packet: SendRtpPacket) {
        let mid: Option<&Bytes> = match &self.media.mid {
            Some(e) => Some(e.as_ref()),
            None => None,
        };

        self.stream
            .send_rtp(packet.with_extensions(RtpExtensions { mid: mid.cloned() }));
    }
}
