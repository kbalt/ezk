#![deny(unreachable_pub, unsafe_code)]

//! sans io implementation of an ICE agent

use core::fmt;
use rand::distr::{Alphanumeric, SampleString};
use sdp_types::{IceCandidate, UntaggedAddress};
use slotmap::{SlotMap, new_key_type};
use std::{
    cmp::{max, min},
    collections::VecDeque,
    hash::{DefaultHasher, Hash, Hasher},
    mem::take,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};
use stun::{StunConfig, StunServerBinding};
use stun_types::{
    Class, Message, TransactionId,
    attributes::{
        ErrorCode, Fingerprint, IceControlled, IceControlling, Priority, UseCandidate,
        XorMappedAddress,
    },
};

mod stun;

/// A message received on a UDP socket
pub struct ReceivedPkt<D = Vec<u8>> {
    /// The received data
    pub data: D,
    /// Source address of the message
    pub source: SocketAddr,
    /// Local socket destination address of the message
    pub destination: SocketAddr,
    /// On which component socket this was received
    pub component: Component,
}

/// Component of the data stream
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Component {
    /// The RTP component of the data stream. This will also contain RTCP if rtcp-mux is enabled.
    Rtp = 1,
    /// The RTCP component of the data stream. This will not be used if rtcp-mux is enabled.
    Rtcp = 2,
}

/// ICE related events emitted by the [`IceAgent`]
#[derive(Debug)]
pub enum IceEvent {
    GatheringStateChanged {
        old: IceGatheringState,
        new: IceGatheringState,
    },
    ConnectionStateChanged {
        old: IceConnectionState,
        new: IceConnectionState,
    },
    DiscoveredAddr {
        component: Component,
        target: SocketAddr,
    },
    SendData {
        component: Component,
        data: Vec<u8>,
        source: Option<IpAddr>,
        target: SocketAddr,
    },
}

/// The ICE agent state machine
pub struct IceAgent {
    stun_config: StunConfig,

    stun_server: Vec<StunServerBinding>,

    local_credentials: IceCredentials,
    remote_credentials: Option<IceCredentials>,

    local_candidates: SlotMap<LocalCandidateId, Candidate>,
    remote_candidates: SlotMap<RemoteCandidateId, Candidate>,

    pairs: Vec<CandidatePair>,
    triggered_check_queue: VecDeque<(LocalCandidateId, RemoteCandidateId)>,

    rtcp_mux: bool,
    is_controlling: bool,
    control_tie_breaker: u64,
    max_pairs: usize,

    gathering_state: IceGatheringState,
    connection_state: IceConnectionState,

    last_ta_trigger: Option<Instant>,

    /// STUN Messages that are received before the remote credentials are available
    backlog: Vec<ReceivedPkt<Message>>,

    events: VecDeque<IceEvent>,
}

/// State of gathering candidates from external (STUN/TURN) servers.
/// If no STUN server is configured this state will jump directly to `Complete`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum IceGatheringState {
    /// The ICE agent was just created
    New,
    /// The ICE agent is in the process of gathering candidates
    Gathering,
    /// The ICE agent has finished gathering candidates. If something happens that requires collecting new candidates,
    /// such as the addition of a new ICE server, the state will revert to `Gathering` to gather those candidates.
    Complete,
}

/// State of the ICE agent
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
// Ordering might look weird, but it's so the total state of all ice agents can be "combined" using `min`
pub enum IceConnectionState {
    /// The ICE agent has failed to find a valid candidate pair for all components
    Failed,

    /// Checks to ensure that components are still connected failed for at least one component.
    /// This is a less stringent test than `Failed` and may trigger intermittently and resolve just as spontaneously on
    /// less reliable networks, or during temporary disconnections.
    /// When the problem resolves, the connection may return to the `Connected` state.
    Disconnected,

    /// The ICE agent is awaiting local & remote ice candidates
    New,
    /// The ICE agent is in the process of checking candidates pairs
    Checking,
    /// The ICE agent has found a valid pair for all components
    Connected,
}

new_key_type!(
    struct LocalCandidateId;
    struct RemoteCandidateId;
);

#[derive(Debug, PartialEq, Clone, Copy, Hash)]
enum CandidateKind {
    Host = 126,
    PeerReflexive = 110,
    ServerReflexive = 100,
    // TODO: Relayed = 0,
}

struct Candidate {
    addr: SocketAddr,
    // transport: udp
    kind: CandidateKind,
    priority: u32,
    foundation: String,

    component: Component,

    // The transport address that an ICE agent sends from for a particular candidate.
    // For host, server-reflexive, and peer-reflexive candidates, the base is the same as the host candidate.
    // For relayed candidates, the base is the same as the relayed candidate
    //  (i.e., the transport address used by the TURN server to send from).
    base: SocketAddr,
}

struct CandidatePair {
    local: LocalCandidateId,
    remote: RemoteCandidateId,
    priority: u64,
    state: CandidatePairState,
    component: Component,

    // Nominated by the peer
    received_use_candidate: bool,
    // Nominated by us
    nominated: bool,
}

#[derive(Debug, Clone, PartialEq)]
enum CandidatePairState {
    /// A check has not been sent for this pair, but the pair is not Frozen.
    Waiting,

    /// A check has been sent for this pair, but the transaction is in progress.
    InProgress {
        transaction_id: TransactionId,
        stun_request: Vec<u8>,
        retransmit_at: Instant,
        retransmits: u32,
        source: IpAddr,
        target: SocketAddr,
    },

    // A check has been sent for this pair, and it produced a successful result.
    Succeeded,

    /// A check has been sent for this pair, and it failed (a response to the check
    /// was never received, or a failure response was received).
    Failed,
}

/// Credentials of an ICE agent
///
/// These must be exchanges using some external signaling protocol like SDP
#[derive(Clone)]
pub struct IceCredentials {
    pub ufrag: String,
    pub pwd: String,
}

impl IceCredentials {
    pub fn random() -> Self {
        let mut rng = rand::rng();

        Self {
            ufrag: Alphanumeric.sample_string(&mut rng, 8),
            pwd: Alphanumeric.sample_string(&mut rng, 32),
        }
    }
}

impl IceAgent {
    pub fn new_from_answer(
        local_credentials: IceCredentials,
        remote_credentials: IceCredentials,
        is_controlling: bool,
        rtcp_mux: bool,
    ) -> Self {
        IceAgent {
            stun_config: StunConfig::new(),
            stun_server: vec![],
            local_credentials,
            remote_credentials: Some(remote_credentials),
            local_candidates: SlotMap::with_key(),
            remote_candidates: SlotMap::with_key(),
            pairs: Vec::new(),
            triggered_check_queue: VecDeque::new(),
            rtcp_mux,
            is_controlling,
            control_tie_breaker: rand::random(),
            max_pairs: 100,
            gathering_state: IceGatheringState::New,
            connection_state: IceConnectionState::New,
            last_ta_trigger: None,
            backlog: vec![],
            events: VecDeque::new(),
        }
    }

    pub fn new_for_offer(
        local_credentials: IceCredentials,
        is_controlling: bool,
        rtcp_mux: bool,
    ) -> Self {
        IceAgent {
            stun_config: StunConfig::new(),
            stun_server: vec![],
            local_credentials,
            remote_credentials: None,
            local_candidates: SlotMap::with_key(),
            remote_candidates: SlotMap::with_key(),
            pairs: Vec::new(),
            triggered_check_queue: VecDeque::new(),
            rtcp_mux,
            is_controlling,
            control_tie_breaker: rand::random(),
            max_pairs: 100,
            gathering_state: IceGatheringState::New,
            connection_state: IceConnectionState::New,
            last_ta_trigger: None,
            backlog: vec![],
            events: VecDeque::new(),
        }
    }

    /// Set all the remote information in one step. This function is usually set once after receiving a SDP answer.
    pub fn set_remote_data(
        &mut self,
        credentials: IceCredentials,
        candidates: &[IceCandidate],
        rtcp_mux: bool,
    ) {
        // TODO: assert that we can't change from rtcp-mux: true -> false
        self.rtcp_mux = rtcp_mux;

        // Remove all rtcp candidates and stun server bindings rtcp-mux is enabled
        if rtcp_mux {
            self.stun_server.retain(|s| s.component() == Component::Rtp);
            self.local_candidates
                .retain(|_, c| c.component == Component::Rtp);
        }

        self.remote_credentials = Some(credentials);

        for candidate in candidates {
            self.add_remote_candidate(candidate);
        }

        for pkt in take(&mut self.backlog) {
            self.receive_stun(pkt);
        }
    }

    /// Return the ice-agent's ice credentials
    pub fn credentials(&self) -> &IceCredentials {
        &self.local_credentials
    }

    /// Register a host address for a given ICE component. This will be used to create a host candidate.
    /// For the ICE agent to work properly, all available ip addresses of the host system should be provided.
    pub fn add_host_addr(&mut self, component: Component, addr: SocketAddr) {
        if addr.ip().is_unspecified() {
            return;
        }

        if let SocketAddr::V6(v6) = addr {
            let ip = v6.ip();
            if ip.to_ipv4().is_some() || ip.to_ipv4_mapped().is_some() {
                return;
            }
        }

        self.add_local_candidate(component, CandidateKind::Host, addr, addr);
    }

    /// Add a STUN server which the ICE agent should use to gather additional (server-reflexive) candidates.
    pub fn add_stun_server(&mut self, server: SocketAddr) {
        // TODO: ideally create a stun server binding for every local interface
        self.stun_server
            .push(StunServerBinding::new(server, Component::Rtp));

        if !self.rtcp_mux {
            self.stun_server
                .push(StunServerBinding::new(server, Component::Rtcp));
        }
    }

    /// Returns the current ICE candidate gathering state
    pub fn gathering_state(&self) -> IceGatheringState {
        self.gathering_state
    }

    /// Returns the current ICE connection state
    pub fn connection_state(&self) -> IceConnectionState {
        self.connection_state
    }

    /// Returns the discovered local & remote address for the given component
    pub fn discovered_addr(&self, mut component: Component) -> Option<(SocketAddr, SocketAddr)> {
        if self.rtcp_mux {
            component = Component::Rtp;
        }

        self.pairs
            .iter()
            .find(|pair| {
                pair.component == component
                    && pair.state == CandidatePairState::Succeeded
                    && pair.nominated
            })
            .map(|pair| {
                (
                    self.local_candidates[pair.local].addr,
                    self.remote_candidates[pair.remote].addr,
                )
            })
    }

    fn add_local_candidate(
        &mut self,
        component: Component,
        kind: CandidateKind,
        base: SocketAddr,
        addr: SocketAddr,
    ) {
        // Check if we need to create a new candidate for this
        let already_exists = self
            .local_candidates
            .values()
            .any(|c| c.kind == kind && c.base == base && c.addr == addr);

        if already_exists {
            // ignore
            return;
        }

        log::debug!("add local candidate {component:?} {kind:?} {addr}");

        // Calculate the candidate priority using offsets + count of candidates of the same type
        // (trick that I have stolen from str0m's implementation)
        let local_preference_offset = match kind {
            CandidateKind::Host => (65535 / 4) * 3,
            CandidateKind::PeerReflexive => (65535 / 4) * 2,
            CandidateKind::ServerReflexive => 65535 / 4,
            // CandidateKind::Relayed => 0,
        };

        let local_preference = self
            .local_candidates
            .values()
            .filter(|c| c.kind == kind)
            .count() as u32
            + local_preference_offset;

        let kind_preference = (kind as u32) << 24;
        let local_preference = local_preference << 8;
        let priority = kind_preference + local_preference + (256 - component as u32);

        self.local_candidates.insert(Candidate {
            addr,
            kind,
            priority,
            foundation: compute_foundation(kind, base.ip(), None, "udp").to_string(),
            component,
            base,
        });

        self.form_pairs();
    }

    /// Add a peer's ice-candidate which has been received using an extern signaling protocol
    pub fn add_remote_candidate(&mut self, candidate: &IceCandidate) {
        let kind = match candidate.typ.as_str() {
            "host" => CandidateKind::Host,
            "srflx" => CandidateKind::ServerReflexive,
            _ => return,
        };

        // TODO: currently only udp transport is supported
        if !candidate.transport.eq_ignore_ascii_case("udp") {
            return;
        }

        let Ok(priority) = u32::try_from(candidate.priority) else {
            log::warn!("Candidate has priority larger than u32::MAX");
            return;
        };

        let component = match candidate.component {
            1 => Component::Rtp,
            // Discard candidates for rtcp if rtcp-mux is enabled
            2 if !self.rtcp_mux => Component::Rtcp,
            _ => {
                log::debug!(
                    "Discard remote candidate with unsupported component candidate:{candidate}"
                );
                return;
            }
        };

        let ip = match candidate.address {
            UntaggedAddress::Fqdn(..) => return,
            UntaggedAddress::IpAddress(ip_addr) => ip_addr,
        };

        self.remote_candidates.insert(Candidate {
            addr: SocketAddr::new(ip, candidate.port),
            kind,
            priority,
            foundation: candidate.foundation.to_string(),
            component,
            base: SocketAddr::new(ip, candidate.port), // TODO: do I even need this?
        });

        self.form_pairs();
    }

    fn form_pairs(&mut self) {
        for (local_id, local_candidate) in &self.local_candidates {
            for (remote_id, remote_candidate) in &self.remote_candidates {
                // Remote peer-reflexive candidates are not paired here
                if remote_candidate.kind == CandidateKind::PeerReflexive {
                    continue;
                }

                // Do not pair candidates with different components
                if local_candidate.component != remote_candidate.component {
                    continue;
                }

                // Check if the pair already exists
                let already_exists = self
                    .pairs
                    .iter()
                    .any(|pair| pair.local == local_id && pair.remote == remote_id);

                if already_exists {
                    continue;
                }

                // Exclude pairs with different ip version
                match (local_candidate.addr.ip(), remote_candidate.addr.ip()) {
                    (IpAddr::V4(l), IpAddr::V4(r)) if l.is_link_local() == r.is_link_local() => {
                        /* ok */
                    }
                    // Only pair IPv6 addresses when either both or neither are link local addresses
                    (IpAddr::V6(l), IpAddr::V6(r))
                        if l.is_unicast_link_local() == r.is_unicast_link_local() =>
                    { /* ok */ }
                    _ => {
                        // Would make an invalid pair, skip
                        continue;
                    }
                }

                Self::add_candidate_pair(
                    local_id,
                    local_candidate,
                    remote_id,
                    remote_candidate,
                    self.is_controlling,
                    &mut self.pairs,
                    false,
                );
            }
        }

        self.pairs.sort_unstable_by_key(|p| p.priority);

        self.prune_pairs();
    }

    fn add_candidate_pair(
        local_id: LocalCandidateId,
        local_candidate: &Candidate,
        remote_id: RemoteCandidateId,
        remote_candidate: &Candidate,
        is_controlling: bool,
        pairs: &mut Vec<CandidatePair>,
        received_use_candidate: bool,
    ) {
        if pairs
            .iter()
            .any(|p| p.local == local_id && p.remote == remote_id)
        {
            // pair already exists
            return;
        }

        let priority = pair_priority(local_candidate, remote_candidate, is_controlling);

        log::debug!(
            "add pair {}, priority: {priority}, component={:?}",
            DisplayPair(local_candidate, remote_candidate),
            local_candidate.component,
        );

        pairs.push(CandidatePair {
            local: local_id,
            remote: remote_id,
            priority,
            state: CandidatePairState::Waiting,
            component: local_candidate.component,
            received_use_candidate,
            nominated: false,
        });
        pairs.sort_unstable_by_key(|p| p.priority);
    }

    fn recompute_pair_priorities(&mut self) {
        for pair in &mut self.pairs {
            pair.priority = pair_priority(
                &self.local_candidates[pair.local],
                &self.remote_candidates[pair.remote],
                self.is_controlling,
            );
        }

        self.pairs.sort_unstable_by_key(|p| p.priority);
    }

    /// Prune the lowest priority pairs until `max_pairs` is reached
    fn prune_pairs(&mut self) {
        while self.pairs.len() > self.max_pairs {
            let pair = self
                .pairs
                .pop()
                .expect("just checked that self.pairs.len() > self.max_pairs");

            log::debug!(
                "Pruned pair {}",
                DisplayPair(
                    &self.local_candidates[pair.local],
                    &self.remote_candidates[pair.remote]
                )
            );
        }
    }

    /// Receive network packets for this ICE agent
    pub fn receive(&mut self, pkt: ReceivedPkt) {
        let mut stun_msg = match Message::parse(pkt.data) {
            Ok(stun_msg) => stun_msg,
            Err(e) => {
                log::debug!("Failed to parse stun message {e}");
                return;
            }
        };

        let passed_fingerprint_check = stun_msg
            .attribute::<Fingerprint>()
            .is_some_and(|r| r.is_ok());

        if !passed_fingerprint_check {
            log::trace!(
                "Incoming STUN {:?} failed fingerprint check, discarding",
                stun_msg.class()
            );
            return;
        }

        let pkt = ReceivedPkt {
            data: stun_msg,
            source: pkt.source,
            destination: pkt.destination,
            component: pkt.component,
        };

        self.receive_stun(pkt);
    }

    fn receive_stun(&mut self, pkt: ReceivedPkt<Message>) {
        match pkt.data.class() {
            Class::Request => self.receive_stun_request(pkt),
            Class::Indication => { /* ignore */ }
            Class::Success => self.receive_stun_success(pkt),
            Class::Error => self.receive_stun_error(pkt),
        }
    }

    fn receive_stun_success(&mut self, mut pkt: ReceivedPkt<Message>) {
        // Check our stun server binding checks before verifying integrity since these aren't authenticated
        for stun_server_binding in &mut self.stun_server {
            if !stun_server_binding.wants_stun_response(pkt.data.transaction_id()) {
                continue;
            }

            let Some(addr) = stun_server_binding.receive_stun_response(&self.stun_config, pkt.data)
            else {
                // TODO; no xor mapped in response, discard message
                return;
            };

            let component = stun_server_binding.component();
            self.add_local_candidate(
                component,
                CandidateKind::ServerReflexive,
                pkt.destination,
                addr,
            );

            return;
        }

        // Store messages later if the remote credentials aren't set yet
        let Some(remote_credentials) = &self.remote_credentials else {
            self.backlog.push(pkt);
            return;
        };

        if !stun::verify_integrity(&self.local_credentials, remote_credentials, &mut pkt.data) {
            log::debug!("Incoming stun success failed the integrity check, discarding");
            return;
        }

        // A connectivity check is considered a success if each of the following
        // criteria is true:
        // o  The Binding request generated a success response; and
        // o  The source and destination transport addresses in the Binding
        //    request and response are symmetric.
        let Some(pair) = self
            .pairs
            .iter_mut()
            .find(|p| {
                matches!(p.state, CandidatePairState::InProgress { transaction_id, .. } if pkt.data.transaction_id() == transaction_id)
            }) else {
                log::debug!("Failed to find transaction for STUN success, discarding");
                return;
            };

        let CandidatePairState::InProgress { source, target, .. } = &pair.state else {
            unreachable!()
        };

        if pkt.source == *target || pkt.destination.ip() == *source {
            log::debug!(
                "got success response for pair {} nominated={}",
                DisplayPair(
                    &self.local_candidates[pair.local],
                    &self.remote_candidates[pair.remote],
                ),
                pair.nominated,
            );

            // This request was a nomination for this pair
            if pair.nominated {
                let local_candidate = &self.local_candidates[pair.local];
                let remote_candidate = &self.remote_candidates[pair.remote];

                self.events.push_back(IceEvent::DiscoveredAddr {
                    component: local_candidate.component,
                    target: remote_candidate.addr,
                });
            }

            pair.state = CandidatePairState::Succeeded;
        } else {
            log::debug!(
                "got success response with invalid source address for pair {}",
                DisplayPair(
                    &self.local_candidates[pair.local],
                    &self.remote_candidates[pair.remote]
                )
            );

            // The ICE agent MUST check that the source and destination transport addresses in the Binding request and
            // response are symmetric. That is, the source IP address and port of the response MUST be equal to the
            // destination IP address and port to which the Binding request was sent, and the destination IP address and
            // port of the response MUST be equal to the source IP address and port from which the Binding request was sent.
            // If the addresses are not symmetric, the agent MUST set the candidate pair state to Failed.
            pair.nominated = false;
            pair.state = CandidatePairState::Failed;
        }

        // Check if we discover a new peer-reflexive candidate here
        if let Some(Ok(mapped_addr)) = pkt.data.attribute::<XorMappedAddress>() {
            if mapped_addr.0 != self.local_candidates[pair.local].addr {
                let component = pair.component;
                self.add_local_candidate(
                    component,
                    CandidateKind::PeerReflexive,
                    pkt.destination,
                    mapped_addr.0,
                );
            }
        } else {
            log::trace!("no (valid) XOR-MAPPED-ADDRESS attribute in STUN success response");
        }
    }

    fn receive_stun_error(&mut self, mut pkt: ReceivedPkt<Message>) {
        let Some(remote_credentials) = &self.remote_credentials else {
            self.backlog.push(pkt);
            return;
        };

        if !stun::verify_integrity(&self.local_credentials, remote_credentials, &mut pkt.data) {
            log::debug!("Incoming stun error response failed the integrity check, discarding");
            return;
        }

        let Some(pair) = self
            .pairs
            .iter_mut()
            .find(|p| {
                matches!(p.state, CandidatePairState::InProgress { transaction_id, .. } if pkt.data.transaction_id() == transaction_id)
            }) else {
                log::debug!("Failed to find transaction for STUN error, discarding");
                return;
            };

        if let Some(Ok(error_code)) = pkt.data.attribute::<ErrorCode>() {
            log::debug!(
                "Candidate pair failed with code={}, reason={}",
                error_code.number,
                error_code.reason
            );

            // If the Binding request generates a 487 (Role Conflict) error response,
            // and if the ICE agent included an ICE-CONTROLLED attribute in the request,
            // the agent MUST switch to the controlling role.
            // If the agent included an ICE-CONTROLLING attribute in the request, the agent MUST switch to the controlled role.
            if error_code.number == 487 {
                if pkt.data.attribute::<IceControlled>().is_some() {
                    self.is_controlling = true;
                } else if pkt.data.attribute::<IceControlling>().is_some() {
                    self.is_controlling = false;
                }

                // Once the agent has switched its role, the agent MUST add the
                // candidate pair whose check generated the 487 error response to the
                // triggered-check queue associated with the checklist to which the pair
                // belongs, and set the candidate pair state to Waiting.
                pair.state = CandidatePairState::Waiting;
                self.triggered_check_queue
                    .push_back((pair.local, pair.remote));

                // A role switch requires an agent to recompute pair priorities, since the priority values depend on the role.
                self.recompute_pair_priorities();
            }
        }
    }

    fn receive_stun_request(&mut self, mut pkt: ReceivedPkt<Message>) {
        let Some(remote_credentials) = &self.remote_credentials else {
            self.backlog.push(pkt);
            return;
        };

        if !stun::verify_integrity(&self.local_credentials, remote_credentials, &mut pkt.data) {
            log::debug!("Incoming stun request failed the integrity check, discarding");
            return;
        }

        let Some(Ok(priority)) = pkt.data.attribute::<Priority>() else {
            log::debug!("Incoming stun request did not contain PRIORITY attribute");
            return;
        };

        let use_candidate = pkt.data.attribute::<UseCandidate>().is_some();

        // Detect and handle role conflict
        if self.is_controlling {
            if let Some(Ok(ice_controlling)) = pkt.data.attribute::<IceControlling>() {
                if self.control_tie_breaker >= ice_controlling.0 {
                    let response = stun::make_role_error(
                        pkt.data.transaction_id(),
                        &self.local_credentials,
                        remote_credentials,
                        pkt.source,
                        true,
                        self.control_tie_breaker,
                    );

                    self.events.push_back(IceEvent::SendData {
                        component: pkt.component,
                        data: response,
                        source: Some(pkt.destination.ip()),
                        target: pkt.source,
                    });

                    return;
                } else {
                    self.is_controlling = false;
                    self.recompute_pair_priorities();
                }
            }
        } else if !self.is_controlling
            && let Some(Ok(ice_controlled)) = pkt.data.attribute::<IceControlled>()
        {
            if self.control_tie_breaker >= ice_controlled.0 {
                let response = stun::make_role_error(
                    pkt.data.transaction_id(),
                    &self.local_credentials,
                    remote_credentials,
                    pkt.source,
                    false,
                    self.control_tie_breaker,
                );

                self.events.push_back(IceEvent::SendData {
                    component: pkt.component,
                    data: response,
                    source: Some(pkt.destination.ip()),
                    target: pkt.source,
                });
                return;
            } else {
                self.is_controlling = true;
                self.recompute_pair_priorities();
            }
        }

        let local_id = match self
            .local_candidates
            .iter()
            .find(|(_, c)| c.kind == CandidateKind::Host && c.addr == pkt.destination)
        {
            Some((id, _)) => id,
            None => {
                log::warn!(
                    "Failed to find matching local candidate for incoming STUN request ({})?",
                    pkt.destination
                );
                return;
            }
        };

        let matching_remote_candidate = self.remote_candidates.iter().find(|(_, c)| {
            // todo: also match protocol
            c.addr == pkt.source
        });

        let remote_id = match matching_remote_candidate {
            Some((remote, _)) => remote,
            None => {
                // No remote candidate with the source ip addr, create new peer-reflexive candidate
                let peer_reflexive_id = self.remote_candidates.insert(Candidate {
                    addr: pkt.source,
                    kind: CandidateKind::PeerReflexive,
                    priority: priority.0,
                    foundation: "~".into(),
                    component: pkt.component,
                    base: pkt.source,
                });

                // Pair it with the local candidate
                Self::add_candidate_pair(
                    local_id,
                    &self.local_candidates[local_id],
                    peer_reflexive_id,
                    &self.remote_candidates[peer_reflexive_id],
                    self.is_controlling,
                    &mut self.pairs,
                    false,
                );

                self.triggered_check_queue
                    .push_back((local_id, peer_reflexive_id));

                peer_reflexive_id
            }
        };

        let pair = self
            .pairs
            .iter_mut()
            .find(|p| p.local == local_id && p.remote == remote_id)
            .expect("local_id & remote_id are valid");

        pair.received_use_candidate = use_candidate;
        log::trace!(
            "got connectivity check for pair {}",
            DisplayPair(
                &self.local_candidates[pair.local],
                &self.remote_candidates[pair.remote],
            )
        );

        let stun_response = stun::make_success_response(
            pkt.data.transaction_id(),
            &self.local_credentials,
            pkt.source,
        );

        self.events.push_back(IceEvent::SendData {
            component: pair.component,
            data: stun_response,
            source: Some(self.local_candidates[local_id].base.ip()),
            target: pkt.source,
        });

        // Check nomination state if we received a use-candidate
        if use_candidate {
            self.poll_nomination();
        }
    }

    /// Drive the ICE agent forward. This must be called after the duration returned by [`timeout`](IceAgent::timeout).
    pub fn poll(&mut self, now: Instant) {
        // Progress all STUN-server bindings (used to create and maintain server-reflexive candidates)
        for stun_server_bindings in &mut self.stun_server {
            stun_server_bindings.poll(now, &self.stun_config, |event| self.events.push_back(event));
        }

        // Handle pending stun retransmissions
        self.poll_retransmit(now);
        self.poll_state();
        self.poll_nomination();

        // Skip anything beyond this before we received the remote credentials & candidates
        let Some(remote_credentials) = &self.remote_credentials else {
            return;
        };

        // Limit new checks to 1 per 50ms
        if let Some(it) = self.last_ta_trigger
            && it + Duration::from_millis(50) > now
        {
            return;
        }
        self.last_ta_trigger = Some(now);

        // If the triggered-check queue associated with the checklist
        // contains one or more candidate pairs, the agent removes the top
        // pair from the queue, performs a connectivity check on that pair,
        // puts the candidate pair state to In-Progress, and aborts the
        // subsequent steps.
        let pair = self
            .triggered_check_queue
            .pop_front()
            .and_then(|(local_id, remote_id)| {
                self.pairs
                    .iter_mut()
                    .find(|p| p.local == local_id && p.remote == remote_id)
            });

        let pair = if let Some(pair) = pair {
            Some(pair)
        } else {
            // If there are one or more candidate pairs in the Waiting state,
            // the agent picks the highest-priority candidate pair (if there are
            // multiple pairs with the same priority, the pair with the lowest
            // component ID is picked) in the Waiting state, performs a
            // connectivity check on that pair, puts the candidate pair state to
            // In-Progress, and aborts the subsequent steps.
            self.pairs
                .iter_mut()
                .find(|p| p.state == CandidatePairState::Waiting)
        };

        if let Some(pair) = pair {
            log::debug!(
                "start connectivity check for pair {}",
                DisplayPair(
                    &self.local_candidates[pair.local],
                    &self.remote_candidates[pair.remote]
                )
            );

            let transaction_id = TransactionId::random();

            let stun_request = stun::make_binding_request(
                transaction_id,
                &self.local_credentials,
                remote_credentials,
                &self.local_candidates[pair.local],
                self.is_controlling,
                self.control_tie_breaker,
                pair.nominated,
            );

            let source = self.local_candidates[pair.local].base.ip();
            let target = self.remote_candidates[pair.remote].addr;

            pair.state = CandidatePairState::InProgress {
                transaction_id,
                stun_request: stun_request.clone(),
                retransmit_at: now + self.stun_config.retransmit_delta(0),
                retransmits: 0,
                source,
                target,
            };

            self.events.push_back(IceEvent::SendData {
                component: pair.component,
                data: stun_request,
                source: Some(source),
                target,
            });
        }
    }

    /// Check all pending STUN transactions for pending retransmits
    fn poll_retransmit(&mut self, now: Instant) {
        for pair in &mut self.pairs {
            let CandidatePairState::InProgress {
                transaction_id: _,
                stun_request,
                retransmit_at,
                retransmits,
                source,
                target,
            } = &mut pair.state
            else {
                continue;
            };

            if *retransmit_at > now {
                continue;
            }

            if *retransmits >= self.stun_config.max_retransmits {
                pair.state = CandidatePairState::Failed;
                continue;
            }

            *retransmits += 1;
            *retransmit_at += self.stun_config.retransmit_delta(*retransmits);

            self.events.push_back(IceEvent::SendData {
                component: pair.component,
                data: stun_request.clone(),
                source: Some(*source),
                target: *target,
            });
        }
    }

    fn poll_state(&mut self) {
        // Check gathering state
        let mut all_completed = true;
        for stun_server in &self.stun_server {
            if !stun_server.is_completed() {
                all_completed = false;
            }
        }

        if all_completed && self.gathering_state != IceGatheringState::Complete {
            self.events.push_back(IceEvent::GatheringStateChanged {
                old: self.gathering_state,
                new: IceGatheringState::Complete,
            });

            self.gathering_state = IceGatheringState::Complete;
        } else if !all_completed && self.gathering_state != IceGatheringState::Gathering {
            self.events.push_back(IceEvent::GatheringStateChanged {
                old: self.gathering_state,
                new: IceGatheringState::Gathering,
            });

            self.gathering_state = IceGatheringState::Gathering;
        }

        // Check connection state
        let mut has_rtp_nomination = false;
        let mut has_rtcp_nomination = false;

        let mut rtp_in_progress = false;
        let mut rtcp_in_progress = false;

        for pair in &self.pairs {
            if pair.nominated && matches!(pair.state, CandidatePairState::Succeeded) {
                match pair.component {
                    Component::Rtp => has_rtp_nomination = true,
                    Component::Rtcp => has_rtcp_nomination = true,
                }
            }

            if matches!(
                pair.state,
                CandidatePairState::Waiting | CandidatePairState::InProgress { .. }
            ) {
                match pair.component {
                    Component::Rtp => rtp_in_progress = true,
                    Component::Rtcp => rtcp_in_progress = true,
                }
            }
        }

        let has_nomination_for_all_components = if self.rtcp_mux {
            has_rtp_nomination
        } else {
            has_rtp_nomination && has_rtcp_nomination
        };

        let still_possible = if self.rtcp_mux {
            rtp_in_progress
        } else {
            rtp_in_progress && rtcp_in_progress
        };

        if has_nomination_for_all_components
            && self.connection_state != IceConnectionState::Connected
        {
            self.set_connection_state(IceConnectionState::Connected);
        } else if !has_nomination_for_all_components {
            if still_possible {
                match self.connection_state {
                    IceConnectionState::New => {
                        self.set_connection_state(IceConnectionState::Checking);
                    }
                    IceConnectionState::Checking => {}
                    IceConnectionState::Connected => {
                        self.set_connection_state(IceConnectionState::Disconnected);
                    }
                    IceConnectionState::Failed => {}
                    IceConnectionState::Disconnected => {}
                }
            } else {
                self.set_connection_state(IceConnectionState::Failed);
            }
        }
    }

    fn set_connection_state(&mut self, new: IceConnectionState) {
        if self.connection_state != new {
            self.events.push_back(IceEvent::ConnectionStateChanged {
                old: self.connection_state,
                new,
            });
            self.connection_state = new;
        }
    }

    /// Progress the nomination state of the agent.
    fn poll_nomination(&mut self) {
        self.poll_nomination_of_component(Component::Rtp);

        if !self.rtcp_mux {
            self.poll_nomination_of_component(Component::Rtcp);
        }
    }
    /// Progress the candidate nomination for a given component
    fn poll_nomination_of_component(&mut self, component: Component) {
        if self.is_controlling {
            // Nothing to do, already nominated a pair
            let skip = self
                .pairs
                .iter()
                .any(|p| p.component == component && p.nominated);
            if skip {
                return;
            }

            let best_pair = self
                .pairs
                .iter_mut()
                .filter(|p| {
                    p.component == component && matches!(p.state, CandidatePairState::Succeeded)
                })
                .max_by_key(|p| p.priority);

            let Some(pair) = best_pair else {
                // no pair to nominate
                return;
            };

            log::debug!(
                "nominating {}",
                DisplayPair(
                    &self.local_candidates[pair.local],
                    &self.remote_candidates[pair.remote]
                )
            );

            pair.nominated = true;

            // Make another binding request with use-candidate as soon as possible, by pushing it to the front of the queue
            self.triggered_check_queue
                .push_front((pair.local, pair.remote));
        } else {
            // Not controlling, check if we have received a use-candidate for a successful pair

            // Skip this if we already have a nominated pair
            let skip = self.pairs.iter().any(|p| p.nominated);
            if skip {
                return;
            }

            // Find the highest priority pair that received a use-candidate && was successful
            let pair = self
                .pairs
                .iter_mut()
                .filter(|p| {
                    p.component == component
                        && p.received_use_candidate
                        && matches!(p.state, CandidatePairState::Succeeded)
                })
                .max_by_key(|p| p.priority);

            let Some(pair) = pair else {
                // no pair to nominate
                return;
            };

            log::debug!(
                "using pair {}",
                DisplayPair(
                    &self.local_candidates[pair.local],
                    &self.remote_candidates[pair.remote]
                )
            );

            pair.nominated = true;

            self.events.push_back(IceEvent::DiscoveredAddr {
                component,
                target: self.remote_candidates[pair.remote].addr,
            });
        }
    }

    /// Returns the next event to process
    ///
    /// This must be called until it returns None
    pub fn pop_event(&mut self) -> Option<IceEvent> {
        self.events.pop_front()
    }

    /// Returns a duration after which to call [`poll`](IceAgent::poll)
    pub fn timeout(&self, now: Instant) -> Option<Duration> {
        // Next TA trigger
        let ta = if self.remote_credentials.is_some() {
            Some(
                self.last_ta_trigger
                    .map(|it| {
                        let poll_at = it + Duration::from_millis(50);
                        poll_at.checked_duration_since(now).unwrap_or_default()
                    })
                    .unwrap_or_default(),
            )
        } else {
            None
        };

        // Next stun binding refresh/retransmit
        let stun_bindings = self.stun_server.iter().filter_map(|b| b.timeout(now)).min();

        opt_min(ta, stun_bindings)
    }

    /// Returns all discovered local ice agents, does not include peer-reflexive candidates
    pub fn ice_candidates(&self) -> Vec<IceCandidate> {
        self.local_candidates
            .values()
            .filter(|c| matches!(c.kind, CandidateKind::Host | CandidateKind::ServerReflexive))
            .map(|c| {
                let rel_addr = if c.kind == CandidateKind::ServerReflexive {
                    Some(c.base)
                } else {
                    None
                };

                IceCandidate {
                    foundation: c.foundation.clone().into(),
                    component: c.component as _,
                    transport: "UDP".into(),
                    priority: c.priority.into(),
                    address: UntaggedAddress::IpAddress(c.addr.ip()),
                    port: c.addr.port(),
                    typ: match c.kind {
                        CandidateKind::Host => "host".into(),
                        CandidateKind::ServerReflexive => "srflx".into(),
                        _ => unreachable!(),
                    },
                    rel_addr: rel_addr.map(|addr| UntaggedAddress::IpAddress(addr.ip())),
                    rel_port: rel_addr.map(|addr| addr.port()),
                    unknown: vec![],
                }
            })
            .collect()
    }
}

fn pair_priority(
    local_candidate: &Candidate,
    remote_candidate: &Candidate,
    is_controlling: bool,
) -> u64 {
    let (g, d) = if is_controlling {
        (
            local_candidate.priority as u64,
            remote_candidate.priority as u64,
        )
    } else {
        (
            remote_candidate.priority as u64,
            local_candidate.priority as u64,
        )
    };

    // pair priority = 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)
    2u64.pow(32) * min(g, d) + 2 * max(g, d) + if g > d { 1 } else { 0 }
}

fn compute_foundation(
    kind: CandidateKind,
    base: IpAddr,
    rel_addr: Option<IpAddr>,
    proto: &str,
) -> u64 {
    let mut hasher = DefaultHasher::new();
    (kind, base, rel_addr, proto).hash(&mut hasher);
    hasher.finish()
}

struct DisplayPair<'a>(&'a Candidate, &'a Candidate);

impl fmt::Display for DisplayPair<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn fmt_candidate(f: &mut fmt::Formatter<'_>, c: &Candidate) -> fmt::Result {
            match c.kind {
                CandidateKind::Host => write!(f, "host({})", c.addr),
                CandidateKind::PeerReflexive => {
                    write!(f, "peer-reflexive(base:{}, peer:{})", c.base, c.addr)
                }
                CandidateKind::ServerReflexive => {
                    write!(f, "server-reflexive(base:{}, server:{})", c.base, c.addr)
                } // CandidateKind::Relayed => write!(f, "relayed(base:{}, relay:{})", c.base, c.addr),
            }
        }

        fmt_candidate(f, self.0)?;
        write!(f, " <-> ")?;
        fmt_candidate(f, self.1)
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
