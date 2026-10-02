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

const MAX_EARLY_CHECKS: usize = 64;
const MAX_REMOTE_CANDIDATES: usize = 100;
const MAX_CANCELLED_TRANSACTIONS: usize = 64;

/// Minimum ICE runtime before timeout as recommended in RFC 8863
const PAC_TIMEOUT: Duration = Duration::from_millis(39_500);

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
        source: SocketAddr,
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
    cancelled_transactions: Vec<CancelledTransaction>,

    rtcp_mux: bool,
    is_controlling: bool,
    control_tie_breaker: u64,
    max_pairs: usize,

    gathering_state: IceGatheringState,
    connection_state: IceConnectionState,

    /// Pair last reported as used for each component (index = component - 1)
    selected_pairs: [Option<(LocalCandidateId, RemoteCandidateId)>; 2],

    pac_deadline: Option<Instant>,

    last_ta_trigger: Option<Instant>,

    /// STUN Messages that are received before the remote credentials are available.
    /// Capped to prevent unbounded growth from unauthenticated traffic.
    backlog: Vec<ReceivedCheck>,

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
    /// Only used for remote candidates, since local relayed candidates (TURN) aren't supported yet
    Relayed = 0,
}

#[derive(Debug)]
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

#[derive(Debug)]
struct CandidatePair {
    local: LocalCandidateId,
    remote: RemoteCandidateId,
    priority: u64,
    state: CandidatePairState,
    component: Component,

    nomination: CandidatePairNomination,

    /// The controlling peer sent a request with USE-CANDIDATE for this pair.
    ///
    /// The pair is selected as soon as it has succeeded.
    remote_nominated: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum CandidatePairNomination {
    /// Not nominated
    None,
    /// Sent off nominations STUN request with use-candidate attribute
    Nominated,
    /// Candidate is nominated as used
    Selected,
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
        /// If the request was sent with ICE-CONTROLLING (true) or ICE-CONTROLLED (false)
        controlling: bool,
        /// If the request contained the USE-CANDIDATE attribute
        use_candidate: bool,
    },

    // A check has been sent for this pair, and it produced a successful result.
    Succeeded,

    /// A check has been sent for this pair, and it failed (a response to the check
    /// was never received, or a failure response was received).
    Failed,
}

/// Transaction that has been replaced by a new check of the same pair, kept to match incoming responses
#[derive(Debug)]
struct CancelledTransaction {
    local: LocalCandidateId,
    remote: RemoteCandidateId,
    transaction_id: TransactionId,
    source: IpAddr,
    target: SocketAddr,
    controlling: bool,
    use_candidate: bool,
    expires_at: Instant,
}

#[derive(Debug)]
struct ReceivedCheck {
    received_at: Instant,
    remote_ufrag: String,
    source: SocketAddr,
    destination: SocketAddr,
    component: Component,
    priority: u32,
    use_candidate: bool,
    ice_controlling: Option<u64>,
    ice_controlled: Option<u64>,
}

/// Connectivity check transaction a STUN response belongs to
struct MatchedTransaction {
    pair_index: usize,
    source: IpAddr,
    target: SocketAddr,
    controlling: bool,
    use_candidate: bool,
    /// The transaction is the pair's in-progress check and hasn't been cancelled
    active: bool,
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
            cancelled_transactions: Vec::new(),
            rtcp_mux,
            is_controlling,
            control_tie_breaker: rand::random(),
            max_pairs: 100,
            gathering_state: IceGatheringState::New,
            connection_state: IceConnectionState::New,
            selected_pairs: [None; 2],
            pac_deadline: None,
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
            cancelled_transactions: Vec::new(),
            rtcp_mux,
            is_controlling,
            control_tie_breaker: rand::random(),
            max_pairs: 100,
            gathering_state: IceGatheringState::New,
            connection_state: IceConnectionState::New,
            selected_pairs: [None; 2],
            pac_deadline: None,
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

        for early_check in take(&mut self.backlog) {
            if self
                .remote_credentials
                .as_ref()
                .is_none_or(|c| c.ufrag != early_check.remote_ufrag)
            {
                log::debug!(
                    "Discard connectivity check from {} with unknown username fragment",
                    early_check.source
                );
                continue;
            }

            let Some(local_id) = self.host_candidate(early_check.destination) else {
                continue;
            };

            self.detect_role_conflict(early_check.received_at, &early_check);
            self.handle_check(early_check.received_at, local_id, early_check);
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

        self.add_local_candidate(component, CandidateKind::Host, addr, addr, None);
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

    /// Returns if the agent is currently in the controlling role
    ///
    /// The role may change during ICE processing to resolve a role conflict.
    pub fn is_controlling(&self) -> bool {
        self.is_controlling
    }

    /// Returns the discovered local & remote address for the given component
    pub fn discovered_addr(&self, mut component: Component) -> Option<(SocketAddr, SocketAddr)> {
        if self.rtcp_mux {
            component = Component::Rtp;
        }

        self.selected_pair(component).map(|pair| {
            (
                self.local_candidates[pair.local].base,
                self.remote_candidates[pair.remote].base,
            )
        })
    }

    /// The pair used for a component: the highest priority pair that has been selected and succeeded
    fn selected_pair(&self, component: Component) -> Option<&CandidatePair> {
        // pairs are sorted by priority
        self.pairs.iter().find(|pair| {
            pair.component == component
                && pair.state == CandidatePairState::Succeeded
                && pair.nomination == CandidatePairNomination::Selected
        })
    }

    fn add_local_candidate(
        &mut self,
        component: Component,
        kind: CandidateKind,
        base: SocketAddr,
        addr: SocketAddr,
        stun_server: Option<SocketAddr>,
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
            CandidateKind::Relayed => 0,
        };

        let local_preference = self
            .local_candidates
            .values()
            .filter(|c| c.component == component && c.kind == kind)
            .count() as u32
            + local_preference_offset;

        let kind_preference = (kind as u32) << 24;
        let local_preference = local_preference << 8;
        let priority = kind_preference + local_preference + (256 - component as u32);

        let local_id = self.local_candidates.insert(Candidate {
            addr,
            kind,
            priority,
            foundation: compute_foundation(kind, base.ip(), stun_server, "udp").to_string(),
            component,
            base,
        });

        self.form_pairs_for_local(local_id);
    }

    /// Add a peer's ice-candidate which has been received using an extern signaling protocol
    pub fn add_remote_candidate(&mut self, candidate: &IceCandidate) {
        let kind = if candidate.typ.eq_ignore_ascii_case("host") {
            CandidateKind::Host
        } else if candidate.typ.eq_ignore_ascii_case("srflx") {
            CandidateKind::ServerReflexive
        } else if candidate.typ.eq_ignore_ascii_case("prflx") {
            CandidateKind::PeerReflexive
        } else if candidate.typ.eq_ignore_ascii_case("relay") {
            CandidateKind::Relayed
        } else {
            log::debug!("Ignoring remote candidate with unknown type candidate:{candidate}");
            return;
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

        let addr = SocketAddr::new(ip, candidate.port);

        let remote_id = if let Some((remote_id, existing)) = self
            .remote_candidates
            .iter_mut()
            .find(|(_, c)| c.addr == addr && c.component == component)
        {
            if existing.kind != CandidateKind::PeerReflexive {
                log::debug!("Discard duplicate remote candidate candidate:{candidate}");
                return;
            }

            existing.kind = kind;
            existing.priority = priority;
            existing.foundation = candidate.foundation.to_string();

            self.recompute_pair_priorities();

            remote_id
        } else {
            if self.remote_candidates.len() >= MAX_REMOTE_CANDIDATES {
                log::debug!(
                    "Discard remote candidate, too many remote candidates candidate:{candidate}"
                );
                return;
            }

            self.remote_candidates.insert(Candidate {
                addr,
                kind,
                priority,
                foundation: candidate.foundation.to_string(),
                component,
                base: addr,
            })
        };

        self.form_pairs_for_remote(remote_id);
    }

    fn form_pairs_for_local(&mut self, local_id: LocalCandidateId) {
        let local_candidate = &self.local_candidates[local_id];

        for (remote_id, remote_candidate) in &self.remote_candidates {
            if can_pair(local_candidate, remote_candidate) {
                Self::add_candidate_pair(
                    local_id,
                    local_candidate,
                    remote_id,
                    remote_candidate,
                    self.is_controlling,
                    &mut self.pairs,
                );
            }
        }

        self.prune_pairs();
    }

    fn form_pairs_for_remote(&mut self, remote_id: RemoteCandidateId) {
        let remote_candidate = &self.remote_candidates[remote_id];

        for (local_id, local_candidate) in &self.local_candidates {
            if can_pair(local_candidate, remote_candidate) {
                Self::add_candidate_pair(
                    local_id,
                    local_candidate,
                    remote_id,
                    remote_candidate,
                    self.is_controlling,
                    &mut self.pairs,
                );
            }
        }

        self.prune_pairs();
    }

    fn add_candidate_pair(
        local_id: LocalCandidateId,
        local_candidate: &Candidate,
        remote_id: RemoteCandidateId,
        remote_candidate: &Candidate,
        is_controlling: bool,
        pairs: &mut Vec<CandidatePair>,
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

        let index = pairs.partition_point(|p| p.priority >= priority);

        pairs.insert(
            index,
            CandidatePair {
                local: local_id,
                remote: remote_id,
                priority,
                state: CandidatePairState::Waiting,
                component: local_candidate.component,
                nomination: CandidatePairNomination::None,
                remote_nominated: false,
            },
        );
    }

    fn recompute_pair_priorities(&mut self) {
        for pair in &mut self.pairs {
            pair.priority = pair_priority(
                &self.local_candidates[pair.local],
                &self.remote_candidates[pair.remote],
                self.is_controlling,
            );
        }

        self.pairs
            .sort_unstable_by_key(|b| std::cmp::Reverse(b.priority));
    }

    /// Switch the agent's role to resolve a role conflict
    fn set_role(&mut self, now: Instant, is_controlling: bool) {
        if self.is_controlling == is_controlling {
            return;
        }

        log::debug!(
            "switching role to {}",
            if is_controlling {
                "controlling"
            } else {
                "controlled"
            }
        );

        self.is_controlling = is_controlling;

        // Nominations belong to the previous role, the (new) controlling agent has to nominate again
        for pair in &mut self.pairs {
            pair.nomination = CandidatePairNomination::None;
            pair.remote_nominated = false;
        }

        // In-flight checks still carry the previous role, repeat them with the new one
        for index in 0..self.pairs.len() {
            if matches!(
                self.pairs[index].state,
                CandidatePairState::InProgress { .. }
            ) {
                self.cancel_check(now, index);

                let pair = &self.pairs[index];
                self.enqueue_triggered_check((pair.local, pair.remote), false);
            }
        }

        // A role switch requires an agent to recompute pair priorities, since the priority values depend on the role.
        self.recompute_pair_priorities();
    }

    /// Add a pair to the triggered-check queue, if it isn't already queued.
    ///
    /// With `front` set the pair is moved to the front of the queue.
    fn enqueue_triggered_check(
        &mut self,
        pair_key: (LocalCandidateId, RemoteCandidateId),
        front: bool,
    ) {
        if front {
            self.triggered_check_queue.retain(|key| *key != pair_key);
            self.triggered_check_queue.push_front(pair_key);
        } else if !self.triggered_check_queue.contains(&pair_key) {
            self.triggered_check_queue.push_back(pair_key);
        }
    }

    /// Stop retransmitting the in-progress check of a pair and set the pair to Waiting.
    ///
    /// A response to the cancelled check is still accepted until the transaction would have timed out.
    fn cancel_check(&mut self, now: Instant, pair_index: usize) {
        let pair = &mut self.pairs[pair_index];

        let CandidatePairState::InProgress {
            transaction_id,
            source,
            target,
            controlling,
            use_candidate,
            ..
        } = pair.state
        else {
            return;
        };

        pair.state = CandidatePairState::Waiting;

        if self.cancelled_transactions.len() >= MAX_CANCELLED_TRANSACTIONS {
            self.cancelled_transactions.remove(0);
        }

        self.cancelled_transactions.push(CancelledTransaction {
            local: pair.local,
            remote: pair.remote,
            transaction_id,
            source,
            target,
            controlling,
            use_candidate,
            expires_at: now + self.stun_config.transaction_timeout(),
        });
    }

    /// Find the connectivity check a STUN response belongs to.
    ///
    /// A matched cancelled transaction is consumed.
    fn match_transaction(&mut self, transaction_id: TransactionId) -> Option<MatchedTransaction> {
        let active = self
            .pairs
            .iter()
            .enumerate()
            .find_map(|(pair_index, p)| match p.state {
                CandidatePairState::InProgress {
                    transaction_id: id,
                    source,
                    target,
                    controlling,
                    use_candidate,
                    ..
                } if id == transaction_id => Some(MatchedTransaction {
                    pair_index,
                    source,
                    target,
                    controlling,
                    use_candidate,
                    active: true,
                }),
                _ => None,
            });

        if active.is_some() {
            return active;
        }

        let index = self
            .cancelled_transactions
            .iter()
            .position(|t| t.transaction_id == transaction_id)?;

        let cancelled = self.cancelled_transactions.remove(index);

        let pair_index = self
            .pairs
            .iter()
            .position(|p| p.local == cancelled.local && p.remote == cancelled.remote)?;

        Some(MatchedTransaction {
            pair_index,
            source: cancelled.source,
            target: cancelled.target,
            controlling: cancelled.controlling,
            use_candidate: cancelled.use_candidate,
            active: false,
        })
    }

    /// Use the pair for its component, which concludes ICE processing for the component
    fn select_pair(&mut self, pair_index: usize) {
        let pair = &mut self.pairs[pair_index];

        if pair.nomination == CandidatePairNomination::Selected {
            return;
        }

        pair.nomination = CandidatePairNomination::Selected;

        log::debug!(
            "selected pair {}",
            DisplayPair(
                &self.local_candidates[pair.local],
                &self.remote_candidates[pair.remote]
            )
        );

        let component = pair.component;

        // Remove all triggered checks for this component
        self.triggered_check_queue.retain(|(local_id, _)| {
            self.local_candidates
                .get(*local_id)
                .is_some_and(|c| c.component != component)
        });
    }

    /// Emit a [`IceEvent::DiscoveredAddr`] when the pair used by a component changed
    fn report_selected_pairs(&mut self) {
        for component in [Component::Rtp, Component::Rtcp] {
            if component == Component::Rtcp && self.rtcp_mux {
                continue;
            }

            let selected = self
                .selected_pair(component)
                .map(|pair| (pair.local, pair.remote));

            let reported = &mut self.selected_pairs[component as usize - 1];

            if *reported == selected {
                continue;
            }

            *reported = selected;

            if let Some((local, remote)) = selected {
                self.events.push_back(IceEvent::DiscoveredAddr {
                    component,
                    source: self.local_candidates[local].base,
                    target: self.remote_candidates[remote].addr,
                });
            }
        }
    }

    fn prune_pairs(&mut self) {
        let mut excess = self.pairs.len().saturating_sub(self.max_pairs);

        if excess == 0 {
            return;
        }

        let mut to_prune = Vec::with_capacity(excess);

        // Do two passes, prioritize removing failed pairs, then waiting
        for prunable in [CandidatePairState::Failed, CandidatePairState::Waiting] {
            for (index, pair) in self.pairs.iter().enumerate().rev() {
                if excess == 0 {
                    break;
                }

                let keep = pair.nomination != CandidatePairNomination::None
                    || pair.remote_nominated
                    || pair.state != prunable;

                if !keep {
                    to_prune.push(index);
                    excess -= 1;
                }
            }
        }

        to_prune.sort_unstable_by(|a, b| b.cmp(a));

        for index in to_prune {
            let pair = self.pairs.remove(index);

            log::debug!(
                "pruned pair {}",
                DisplayPair(
                    &self.local_candidates[pair.local],
                    &self.remote_candidates[pair.remote]
                )
            );
        }

        // Remove triggered checks of pruned pairs
        let pairs = &self.pairs;
        self.triggered_check_queue.retain(|(local_id, remote_id)| {
            pairs
                .iter()
                .any(|p| p.local == *local_id && p.remote == *remote_id)
        });
    }

    /// Receive network packets for this ICE agent
    pub fn receive(&mut self, now: Instant, pkt: ReceivedPkt) {
        let mut stun_msg = match Message::parse(pkt.data) {
            Ok(stun_msg) => stun_msg,
            Err(e) => {
                log::debug!("Failed to parse stun message {e}");
                return;
            }
        };

        let passed_fingerprint_check = stun_msg
            .attribute::<Fingerprint>()
            .is_none_or(|r| r.is_ok());

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

        self.receive_stun(now, pkt);

        // Received messages may conclude or revive ICE processing, report it without waiting for the next poll
        self.poll_state(now);
    }

    fn receive_stun(&mut self, now: Instant, pkt: ReceivedPkt<Message>) {
        match pkt.data.class() {
            Class::Request => self.receive_stun_request(now, pkt),
            Class::Indication => { /* ignore */ }
            Class::Success => self.receive_stun_success(now, pkt),
            Class::Error => self.receive_stun_error(now, pkt),
        }
    }

    fn receive_stun_success(&mut self, now: Instant, mut pkt: ReceivedPkt<Message>) {
        // Check our stun server binding checks before verifying integrity since these aren't authenticated
        for stun_server_binding in &mut self.stun_server {
            if !stun_server_binding.wants_stun_response(pkt.data.transaction_id()) {
                continue;
            }

            let Some(addr) =
                stun_server_binding.receive_stun_success(now, &self.stun_config, pkt.data)
            else {
                // TODO; no xor mapped in response, discard message
                return;
            };

            let component = stun_server_binding.component();
            let stun_server = stun_server_binding.server();
            self.add_local_candidate(
                component,
                CandidateKind::ServerReflexive,
                pkt.destination,
                addr,
                Some(stun_server),
            );

            return;
        }

        let Some(remote_credentials) = &self.remote_credentials else {
            log::debug!(
                "Got STUN success response before remote credentials are known, discarding"
            );
            return;
        };

        if !stun::verify_response(remote_credentials, &mut pkt.data) {
            log::debug!("Incoming stun success failed the integrity check, discarding");
            return;
        }

        // A connectivity check is considered a success if each of the following
        // criteria is true:
        // o  The Binding request generated a success response; and
        // o  The source and destination transport addresses in the Binding
        //    request and response are symmetric.
        let Some(transaction) = self.match_transaction(pkt.data.transaction_id()) else {
            log::debug!("Failed to find transaction for STUN success, discarding");
            return;
        };

        let pair_index = transaction.pair_index;

        if pkt.source == transaction.target && pkt.destination.ip() == transaction.source {
            let pair = &self.pairs[pair_index];

            log::debug!(
                "got success response for pair {} nomination={:?} cancelled={}",
                DisplayPair(
                    &self.local_candidates[pair.local],
                    &self.remote_candidates[pair.remote],
                ),
                pair.nomination,
                !transaction.active,
            );

            // A response to a cancelled check validates the pair as well. Keep the newer check matchable, since it
            // may be the one carrying the nomination.
            if !transaction.active {
                self.cancel_check(now, pair_index);
            }

            let pair = &mut self.pairs[pair_index];
            pair.state = CandidatePairState::Succeeded;

            // This request was a nomination for this pair (controlling), or the peer nominated this pair (controlled)
            let nominated = if self.is_controlling {
                transaction.use_candidate && pair.nomination == CandidatePairNomination::Nominated
            } else {
                pair.remote_nominated
            };

            if nominated {
                self.select_pair(pair_index);
            }
        } else if transaction.active {
            let pair = &mut self.pairs[pair_index];

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
            pair.nomination = CandidatePairNomination::None;
            pair.state = CandidatePairState::Failed;
        } else {
            // The pair has a newer check which decides its state
            log::debug!("got success response with invalid source address for a cancelled check");
        }

        let pair = &self.pairs[pair_index];

        // Check if we discover a new peer-reflexive candidate here
        if let Some(Ok(mapped_addr)) = pkt.data.attribute::<XorMappedAddress>() {
            if mapped_addr.0 != self.local_candidates[pair.local].addr {
                let component = pair.component;
                self.add_local_candidate(
                    component,
                    CandidateKind::PeerReflexive,
                    pkt.destination,
                    mapped_addr.0,
                    None,
                );
            }
        } else {
            log::trace!("no (valid) XOR-MAPPED-ADDRESS attribute in STUN success response");
        }
    }

    fn receive_stun_error(&mut self, now: Instant, mut pkt: ReceivedPkt<Message>) {
        // Check our stun server binding checks before verifying integrity since these aren't authenticated
        for stun_server_binding in &mut self.stun_server {
            if !stun_server_binding.wants_stun_response(pkt.data.transaction_id()) {
                continue;
            }

            stun_server_binding.receive_stun_error(pkt.data);

            return;
        }

        let Some(remote_credentials) = &self.remote_credentials else {
            log::debug!("Got STUN error response before remote credentials are known, discarding");
            return;
        };

        if !stun::verify_response(remote_credentials, &mut pkt.data) {
            log::debug!("Incoming stun error response failed the integrity check, discarding");
            return;
        }

        let Some(transaction) = self.match_transaction(pkt.data.transaction_id()) else {
            log::debug!("Failed to find transaction for STUN error, discarding");
            return;
        };

        let pair = &mut self.pairs[transaction.pair_index];

        let error_code = pkt.data.attribute::<ErrorCode>().and_then(|r| r.ok());

        let display_pair = DisplayPair(
            &self.local_candidates[pair.local],
            &self.remote_candidates[pair.remote],
        );

        if let Some(error_code) = &error_code {
            log::debug!(
                "Candidate pair {display_pair} failed with code={}, reason={}, cancelled={}",
                error_code.number,
                error_code.reason,
                !transaction.active,
            );
        } else {
            log::debug!(
                "Candidate pair {display_pair} failed without error code, cancelled={}",
                !transaction.active
            );
        }

        if error_code.is_some_and(|e| e.number == 487) {
            let pair_key = (pair.local, pair.remote);

            // Set to Waiting before switching roles, so the pair isn't queued again as an in-progress check.
            // A cancelled check has already been superseded by a newer one.
            if transaction.active {
                pair.state = CandidatePairState::Waiting;
            }

            // If the Binding request generates a 487 (Role Conflict) error response,
            // and if the ICE agent included an ICE-CONTROLLED attribute in the request,
            // the agent MUST switch to the controlling role.
            // If the agent included an ICE-CONTROLLING attribute in the request, the agent MUST switch to the controlled role.
            //
            // The role may already have been switched since the request was sent (by another 487 or an incoming request),
            // in which case it must not be switched back.
            if transaction.controlling == self.is_controlling {
                // The agent MUST change the tiebreaker value.
                self.control_tie_breaker = rand::random();
                self.set_role(now, !transaction.controlling);
            }

            // Once the agent has switched its role, the agent MUST add the
            // candidate pair whose check generated the 487 error response to the
            // triggered-check queue associated with the checklist to which the pair
            // belongs, and set the candidate pair state to Waiting.
            if transaction.active {
                self.enqueue_triggered_check(pair_key, false);
            }
        } else if transaction.active {
            pair.state = CandidatePairState::Failed;
            pair.nomination = CandidatePairNomination::None;
        }
    }

    fn receive_stun_request(&mut self, now: Instant, mut pkt: ReceivedPkt<Message>) {
        let Some(remote_ufrag) = stun::verify_request(&self.local_credentials, &mut pkt.data)
        else {
            log::debug!("Incoming stun request failed the integrity check, discarding");
            return;
        };

        let Some(Ok(priority)) = pkt.data.attribute::<Priority>() else {
            log::debug!("Incoming stun request did not contain PRIORITY attribute");
            return;
        };

        let check = ReceivedCheck {
            received_at: now,
            remote_ufrag,
            source: pkt.source,
            destination: pkt.destination,
            component: pkt.component,
            priority: priority.0,
            use_candidate: pkt.data.attribute::<UseCandidate>().is_some(),
            ice_controlling: pkt
                .data
                .attribute::<IceControlling>()
                .and_then(|r| r.ok())
                .map(|a| a.0),
            ice_controlled: pkt
                .data
                .attribute::<IceControlled>()
                .and_then(|r| r.ok())
                .map(|a| a.0),
        };

        let Some(local_id) = self.host_candidate(pkt.destination) else {
            log::warn!(
                "Failed to find matching local candidate for incoming STUN request ({})?",
                pkt.destination
            );
            return;
        };

        match &self.remote_credentials {
            None => {
                self.send_success_response(&pkt, local_id);

                if let Some(existing_early_check) = self.backlog.iter_mut().find(|c| {
                    c.source == check.source
                        && c.destination == check.destination
                        && c.component == check.component
                        && c.remote_ufrag == check.remote_ufrag
                }) {
                    let use_candidate = existing_early_check.use_candidate || check.use_candidate;
                    *existing_early_check = check;
                    existing_early_check.use_candidate = use_candidate;
                } else if self.backlog.len() < MAX_EARLY_CHECKS {
                    self.backlog.push(check);
                } else {
                    log::debug!("Discarding early check, limit reached");
                }

                return;
            }
            Some(remote_credentials) if remote_credentials.ufrag != check.remote_ufrag => {
                // The request is valid, but doesn't belong to the peer this agent is connecting to
                log::debug!(
                    "Got connectivity check from {} with unknown username fragment",
                    check.source
                );
                self.send_success_response(&pkt, local_id);
                return;
            }
            Some(_) => {}
        }

        if self.detect_role_conflict(now, &check) {
            let response =
                stun::make_role_error(pkt.data.transaction_id(), &self.local_credentials);

            self.events.push_back(IceEvent::SendData {
                component: pkt.component,
                data: response,
                source: Some(pkt.destination.ip()),
                target: pkt.source,
            });

            return;
        }

        self.send_success_response(&pkt, local_id);
        self.handle_check(now, local_id, check);
    }

    /// Find the host candidate with the given address
    fn host_candidate(&self, addr: SocketAddr) -> Option<LocalCandidateId> {
        self.local_candidates
            .iter()
            .find(|(_, c)| c.kind == CandidateKind::Host && c.addr == addr)
            .map(|(id, _)| id)
    }

    /// Respond to a connectivity check with a success response
    fn send_success_response(&mut self, pkt: &ReceivedPkt<Message>, local_id: LocalCandidateId) {
        let local_candidate = &self.local_candidates[local_id];

        let stun_response = stun::make_success_response(
            pkt.data.transaction_id(),
            &self.local_credentials,
            pkt.source,
        );

        self.events.push_back(IceEvent::SendData {
            component: local_candidate.component,
            data: stun_response,
            source: Some(local_candidate.base.ip()),
            target: pkt.source,
        });
    }

    /// Detect & handle role conflicts, returns if the agent keeps it role
    fn detect_role_conflict(&mut self, now: Instant, check: &ReceivedCheck) -> bool {
        if self.is_controlling {
            if let Some(ice_controlling) = check.ice_controlling {
                if self.control_tie_breaker >= ice_controlling {
                    return true;
                }

                self.set_role(now, false);
            }
        } else if let Some(ice_controlled) = check.ice_controlled {
            if self.control_tie_breaker < ice_controlled {
                return true;
            }

            self.set_role(now, true);
        }

        false
    }

    fn handle_check(&mut self, now: Instant, local_id: LocalCandidateId, check: ReceivedCheck) {
        let matching_remote_candidate = self.remote_candidates.iter().find(|(_, c)| {
            // todo: also match protocol
            c.addr == check.source
        });

        let remote_id = match matching_remote_candidate {
            Some((remote, _)) => remote,
            None if self.remote_candidates.len() >= MAX_REMOTE_CANDIDATES => {
                log::debug!(
                    "Not adding peer-reflexive candidate {}, limit reached",
                    check.source
                );
                return;
            }
            None => {
                // No remote candidate with the source ip addr, create new peer-reflexive candidate
                self.remote_candidates.insert(Candidate {
                    addr: check.source,
                    kind: CandidateKind::PeerReflexive,
                    priority: check.priority,
                    foundation: "~".into(),
                    component: check.component,
                    base: check.source,
                })
            }
        };

        let pair_key = (local_id, remote_id);

        let pair_index = if let Some(pair_index) = self
            .pairs
            .iter()
            .position(|p| p.local == local_id && p.remote == remote_id)
        {
            pair_index
        } else {
            log::debug!(
                "Got STUN request for candidates without pair, local-candidate: {} remote-candidate: {}, adding new pair",
                DisplayCandidate(&self.local_candidates[local_id]),
                DisplayCandidate(&self.remote_candidates[remote_id])
            );

            // Pair it with the local candidate
            Self::add_candidate_pair(
                local_id,
                &self.local_candidates[local_id],
                remote_id,
                &self.remote_candidates[remote_id],
                self.is_controlling,
                &mut self.pairs,
            );

            self.prune_pairs();

            let Some(pair_index) = self
                .pairs
                .iter()
                .position(|p| p.local == local_id && p.remote == remote_id)
            else {
                // The new pair was pruned
                return;
            };

            pair_index
        };

        let pair = &mut self.pairs[pair_index];
        let component = pair.component;

        log::trace!(
            "got connectivity check for pair {}",
            DisplayPair(
                &self.local_candidates[pair.local],
                &self.remote_candidates[pair.remote],
            )
        );

        let nominated = check.use_candidate && !self.is_controlling;

        if nominated {
            pair.remote_nominated = true;
        }

        // ICE processing of the component has been concluded, no further checks are required unless the peer
        // nominates another pair
        if !nominated && self.component_has_nominated_valid_pair(component) {
            return;
        }

        match self.pairs[pair_index].state {
            CandidatePairState::Succeeded => {
                if nominated {
                    self.select_pair(pair_index);
                }
            }
            CandidatePairState::InProgress { .. } => {
                // Validate the pair as soon as possible, instead of waiting for retransmissions of the in-progress check
                self.cancel_check(now, pair_index);
                self.enqueue_triggered_check(pair_key, nominated);
            }
            CandidatePairState::Waiting | CandidatePairState::Failed => {
                self.pairs[pair_index].state = CandidatePairState::Waiting;
                self.enqueue_triggered_check(pair_key, nominated);
            }
        }
    }

    /// Drive the ICE agent forward. This must be called after the duration returned by [`timeout`](IceAgent::timeout).
    pub fn poll(&mut self, now: Instant) {
        // Progress all STUN-server bindings (used to create and maintain server-reflexive candidates)
        for stun_server_bindings in &mut self.stun_server {
            stun_server_bindings.poll(now, &self.stun_config, |event| self.events.push_back(event));
        }

        // Stop waiting for responses to cancelled checks, once they would have timed out
        self.cancelled_transactions.retain(|t| t.expires_at > now);

        // Handle pending stun retransmissions
        self.poll_retransmit(now);
        self.poll_state(now);
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
        let mut pair_index = None;

        while let Some((local_id, remote_id)) = self.triggered_check_queue.pop_front() {
            let Some(index) = self
                .pairs
                .iter()
                .position(|p| p.local == local_id && p.remote == remote_id)
            else {
                // pair has been pruned
                continue;
            };

            let pair = &self.pairs[index];

            // Skip entries which have been checked since they were queued. Succeeded pairs are only checked again to
            // send the nomination.
            let wants_check = match pair.state {
                CandidatePairState::Waiting => true,
                CandidatePairState::Succeeded => {
                    pair.nomination == CandidatePairNomination::Nominated
                }
                CandidatePairState::InProgress { .. } | CandidatePairState::Failed => false,
            };

            if wants_check {
                pair_index = Some(index);
                break;
            }
        }

        if pair_index.is_none() && !self.all_components_have_nominated_valid_pair() {
            // If there are one or more candidate pairs in the Waiting state,
            // the agent picks the highest-priority candidate pair (if there are
            // multiple pairs with the same priority, the pair with the lowest
            // component ID is picked) in the Waiting state, performs a
            // connectivity check on that pair, puts the candidate pair state to
            // In-Progress, and aborts the subsequent steps.
            pair_index = self
                .pairs
                .iter()
                .position(|p| p.state == CandidatePairState::Waiting);
        }

        if let Some(pair_index) = pair_index {
            let pair = &mut self.pairs[pair_index];
            let use_candidate = pair.nomination == CandidatePairNomination::Nominated;

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
                use_candidate,
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
                controlling: self.is_controlling,
                use_candidate,
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
                controlling: _,
                use_candidate: _,
            } = &mut pair.state
            else {
                continue;
            };

            if *retransmit_at > now {
                continue;
            }

            if *retransmits >= self.stun_config.max_retransmits {
                log::debug!(
                    "failed connectivity check for pair {}",
                    DisplayPair(
                        &self.local_candidates[pair.local],
                        &self.remote_candidates[pair.remote]
                    )
                );

                pair.state = CandidatePairState::Failed;
                pair.nomination = CandidatePairNomination::None;
                continue;
            }

            *retransmits += 1;
            // Relative to `now`, so a late poll doesn't leave the deadline in the past
            *retransmit_at = now + self.stun_config.retransmit_delta(*retransmits);

            log::trace!(
                "retransmitting connectivity check for pair {}",
                DisplayPair(
                    &self.local_candidates[pair.local],
                    &self.remote_candidates[pair.remote]
                )
            );

            self.events.push_back(IceEvent::SendData {
                component: pair.component,
                data: stun_request.clone(),
                source: Some(*source),
                target: *target,
            });
        }
    }

    fn poll_state(&mut self, now: Instant) {
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

        // Don't try to evaluate connection state when the remote data hasn't been set yet
        if self.remote_credentials.is_none() {
            return;
        }

        let pac_deadline = *self.pac_deadline.get_or_insert(now + PAC_TIMEOUT);

        // Check connection state
        let mut has_rtp_nomination = false;
        let mut has_rtcp_nomination = false;

        let mut rtp_in_progress = false;
        let mut rtcp_in_progress = false;

        for pair in &self.pairs {
            if pair.nomination == CandidatePairNomination::Selected
                && matches!(pair.state, CandidatePairState::Succeeded)
            {
                match pair.component {
                    Component::Rtp => has_rtp_nomination = true,
                    Component::Rtcp => has_rtcp_nomination = true,
                }
            }

            if matches!(
                pair.state,
                CandidatePairState::Waiting
                    | CandidatePairState::InProgress { .. }
                    | CandidatePairState::Succeeded
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
                    IceConnectionState::Failed => {
                        // A pair has been revived, e.g. by a check received from the peer
                        self.set_connection_state(IceConnectionState::Checking);
                    }
                    IceConnectionState::Disconnected => {}
                }
            } else if now < pac_deadline {
                // PAC deadline not hit, so not failed yet
                if self.connection_state == IceConnectionState::Connected {
                    self.set_connection_state(IceConnectionState::Disconnected);
                }
            } else {
                self.set_connection_state(IceConnectionState::Failed);
            }
        }

        self.report_selected_pairs();
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
    ///
    /// Only the controlling agent nominates pairs. The controlled agent selects the pairs nominated by its peer once
    /// they succeeded (see [`select_pair`](Self::select_pair)).
    fn poll_nomination_of_component(&mut self, component: Component) {
        if !self.is_controlling || self.component_has_nominated_valid_pair(component) {
            return;
        }

        // Controlling, select a succeeded pair and send a use-candidate
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

        pair.nomination = CandidatePairNomination::Nominated;

        // Make another binding request with use-candidate as soon as possible, by pushing it to the front of the queue
        let pair_key = (pair.local, pair.remote);
        self.enqueue_triggered_check(pair_key, true);
    }

    fn all_components_have_nominated_valid_pair(&self) -> bool {
        self.component_has_nominated_valid_pair(Component::Rtp)
            && (self.rtcp_mux || self.component_has_nominated_valid_pair(Component::Rtcp))
    }

    fn component_has_nominated_valid_pair(&self, component: Component) -> bool {
        self.pairs.iter().any(|p| {
            p.component == component
                && p.nomination == CandidatePairNomination::Selected
                && matches!(p.state, CandidatePairState::Succeeded)
        })
    }

    /// Returns the next event to process
    ///
    /// This must be called until it returns None
    pub fn pop_event(&mut self) -> Option<IceEvent> {
        self.events.pop_front()
    }

    /// Returns a duration after which to call [`poll`](IceAgent::poll)
    ///
    /// Right after [`poll`](IceAgent::poll) was called with the same `now`, this never returns `Some(Duration::ZERO)`.
    pub fn timeout(&self, now: Instant) -> Option<Duration> {
        // Next TA trigger
        let ta = if self.remote_credentials.is_some()
            && (!self.all_components_have_nominated_valid_pair()
                || !self.triggered_check_queue.is_empty())
        {
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

        // Pair STUN retransmit
        let pair_retransmit = self
            .pairs
            .iter()
            .filter_map(|p| {
                if let CandidatePairState::InProgress { retransmit_at, .. } = &p.state {
                    Some(retransmit_at.saturating_duration_since(now))
                } else {
                    None
                }
            })
            .min();

        // Next stun binding refresh/retransmit
        let stun_bindings = self.stun_server.iter().filter_map(|b| b.timeout(now)).min();

        // Expiry of the PAC timer, after which ICE processing may fail
        let pac = self
            .pac_deadline
            .filter(|deadline| {
                *deadline > now && self.connection_state != IceConnectionState::Connected
            })
            .map(|deadline| deadline - now);

        opt_min(opt_min(opt_min(ta, pair_retransmit), stun_bindings), pac)
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

fn can_pair(local_candidate: &Candidate, remote_candidate: &Candidate) -> bool {
    // Peer-reflexive candidates are only paired with the local candidate a check from them was received on
    if remote_candidate.kind == CandidateKind::PeerReflexive {
        return false;
    }

    if local_candidate.component != remote_candidate.component {
        return false;
    }

    match (local_candidate.addr.ip(), remote_candidate.addr.ip()) {
        (IpAddr::V4(l), IpAddr::V4(r)) => l.is_link_local() == r.is_link_local(),
        (IpAddr::V6(l), IpAddr::V6(r)) => l.is_unicast_link_local() == r.is_unicast_link_local(),
        _ => false,
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
    // for server-reflexive candidates
    stun_server: Option<SocketAddr>,
    proto: &str,
) -> u64 {
    let mut hasher = DefaultHasher::new();
    (kind, base, stun_server, proto).hash(&mut hasher);
    hasher.finish()
}

struct DisplayPair<'a>(&'a Candidate, &'a Candidate);

impl fmt::Display for DisplayPair<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_candidate(f, self.0)?;
        write!(f, " <-> ")?;
        fmt_candidate(f, self.1)
    }
}

struct DisplayCandidate<'a>(&'a Candidate);

impl fmt::Display for DisplayCandidate<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt_candidate(f, self.0)
    }
}

fn fmt_candidate(f: &mut fmt::Formatter<'_>, c: &Candidate) -> fmt::Result {
    match c.kind {
        CandidateKind::Host => write!(f, "host({})", c.addr),
        CandidateKind::PeerReflexive => {
            write!(f, "peer-reflexive(base:{}, peer:{})", c.base, c.addr)
        }
        CandidateKind::ServerReflexive => {
            write!(f, "server-reflexive(base:{}, server:{})", c.base, c.addr)
        }
        CandidateKind::Relayed => write!(f, "relayed(base:{}, relay:{})", c.base, c.addr),
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
