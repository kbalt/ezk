use super::{Candidate, IceCredentials, IceEvent};
use crate::Component;
use std::{
    cmp::min,
    net::SocketAddr,
    time::{Duration, Instant},
};
use stun_types::{
    attributes::{
        ErrorCode, Fingerprint, IceControlled, IceControlling, MessageIntegrity,
        MessageIntegrityKey, Priority, UseCandidate, Username, XorMappedAddress,
    },
    Class, Message, MessageBuilder, Method, TransactionId,
};

pub(crate) struct StunConfig {
    pub(crate) initial_rto: Duration,
    pub(crate) max_retransmits: u32,
    pub(crate) max_rto: Duration,
    pub(crate) binding_refresh_interval: Duration,
}

impl StunConfig {
    pub(crate) fn new() -> Self {
        Self {
            // Copying str0m & libwebrtc defaults here
            initial_rto: Duration::from_millis(250),
            // RFC 5389 default
            max_retransmits: 7,
            // Like str0m & libwebrtc capping the maximum retransmit value
            max_rto: Duration::from_secs(3),
            // TODO: I made this number up
            binding_refresh_interval: Duration::from_secs(20),
        }
    }

    pub(crate) fn retransmit_delta(&self, attempts: u32) -> Duration {
        let rto = Duration::from_millis(
            (self.initial_rto.as_millis() << attempts)
                .try_into()
                .unwrap(),
        );

        min(rto, self.max_rto)
    }
}

pub(super) fn make_binding_request(
    transaction_id: TransactionId,
    local_credentials: &IceCredentials,
    remote_credentials: &IceCredentials,
    local_candidate: &Candidate,
    is_controlling: bool,
    control_tie_breaker: u64,
    use_candidate: bool,
) -> Vec<u8> {
    let mut stun_message = MessageBuilder::new(Class::Request, Method::Binding, transaction_id);

    let username = format!("{}:{}", remote_credentials.ufrag, local_credentials.ufrag);
    stun_message.add_attr(Username::new(&username));
    stun_message.add_attr(Priority(local_candidate.priority));

    if is_controlling {
        stun_message.add_attr(IceControlling(control_tie_breaker));
    } else {
        stun_message.add_attr(IceControlled(control_tie_breaker));
    }

    if use_candidate {
        stun_message.add_attr(UseCandidate);
    }

    stun_message.add_attr_with(
        MessageIntegrity,
        MessageIntegrityKey::new(&remote_credentials.pwd),
    );

    stun_message.add_attr(Fingerprint);

    stun_message.finish()
}

pub(super) fn make_success_response(
    transaction_id: TransactionId,
    local_credentials: &IceCredentials,
    source: SocketAddr,
) -> Vec<u8> {
    let mut stun_message = MessageBuilder::new(Class::Success, Method::Binding, transaction_id);

    stun_message.add_attr(XorMappedAddress(source));
    stun_message.add_attr_with(
        MessageIntegrity,
        MessageIntegrityKey::new(&local_credentials.pwd),
    );

    stun_message.add_attr(Fingerprint);

    stun_message.finish()
}

pub(super) fn make_role_error(
    transaction_id: TransactionId,
    local_credentials: &IceCredentials,
    remote_credentials: &IceCredentials,
    source: SocketAddr,
    is_controlling: bool,
    control_tie_breaker: u64,
) -> Vec<u8> {
    let mut stun_message = MessageBuilder::new(Class::Success, Method::Binding, transaction_id);

    let username = format!("{}:{}", local_credentials.ufrag, remote_credentials.ufrag);
    stun_message.add_attr(Username::new(&username));

    stun_message.add_attr(ErrorCode {
        number: 487,
        reason: "Role Conflict",
    });

    if is_controlling {
        stun_message.add_attr(IceControlling(control_tie_breaker));
    } else {
        stun_message.add_attr(IceControlled(control_tie_breaker));
    }

    stun_message.add_attr(XorMappedAddress(source));
    stun_message.add_attr_with(
        MessageIntegrity,
        MessageIntegrityKey::new(&remote_credentials.pwd),
    );
    stun_message.add_attr(Fingerprint);

    stun_message.finish()
}

pub(crate) fn verify_integrity(
    local_credentials: &IceCredentials,
    remote_credentials: &IceCredentials,
    stun_msg: &mut Message,
) -> bool {
    let is_request = match stun_msg.class() {
        Class::Request | Class::Indication => true,
        Class::Success | Class::Error => false,
    };

    let key = if is_request {
        &local_credentials.pwd
    } else {
        &remote_credentials.pwd
    };

    let passed_integrity_check = stun_msg
        .attribute_with::<MessageIntegrity>(MessageIntegrityKey::new(key))
        .is_some_and(|r| r.is_ok());

    if !passed_integrity_check {
        return false;
    }

    if is_request {
        // STUN requests require the USERNAME attribute to be set, validate that is contains the one we expect
        let expected_username = format!("{}:{}", local_credentials.ufrag, remote_credentials.ufrag);
        let username = match stun_msg.attribute::<Username>() {
            Some(Ok(username)) => username,
            Some(Err(e)) => {
                log::debug!("Failed to parse STUN username attribute, {e}");
                return false;
            }
            None => {
                log::debug!("STUN request is missing the USERNAME attribute");
                return false;
            }
        };

        if username.0 != expected_username {
            return false;
        }
    }

    // All checks passed
    true
}

pub(crate) struct StunServerBinding {
    server: SocketAddr,
    component: Component,
    state: StunServerBindingState,
    /// XorMappedAddress from last STUN response
    last_mapped_addr: Option<SocketAddr>,
}

enum StunServerBindingState {
    /// Waiting to be polled to send their first request
    Waiting,
    /// Mid STUN transaction to create binding
    InProgress {
        transaction_id: TransactionId,
        stun_request: Vec<u8>,
        retransmit_at: Instant,
        retransmits: u32,
    },
    /// Waiting to refresh the binding
    WaitingForRefresh { refresh_at: Instant },
    /// Failed to reach the STUN server
    Failed,
}

impl StunServerBinding {
    pub(crate) fn new(server: SocketAddr, component: Component) -> Self {
        Self {
            server,
            component,
            state: StunServerBindingState::Waiting,
            last_mapped_addr: None,
        }
    }

    pub(crate) fn component(&self) -> Component {
        self.component
    }

    /// Returns if the binding has either been completed or failed to complete
    pub(crate) fn is_completed(&self) -> bool {
        self.last_mapped_addr.is_some() || matches!(self.state, StunServerBindingState::Failed)
    }

    pub(crate) fn timeout(&self, now: Instant) -> Option<Duration> {
        match &self.state {
            StunServerBindingState::Waiting => Some(Duration::ZERO),
            StunServerBindingState::InProgress { retransmit_at, .. } => Some(
                retransmit_at
                    .checked_duration_since(now)
                    .unwrap_or(Duration::ZERO),
            ),
            StunServerBindingState::WaitingForRefresh { refresh_at, .. } => Some(
                refresh_at
                    .checked_duration_since(now)
                    .unwrap_or(Duration::ZERO),
            ),
            StunServerBindingState::Failed => None,
        }
    }

    pub(crate) fn poll(
        &mut self,
        now: Instant,
        stun_config: &StunConfig,
        mut on_event: impl FnMut(IceEvent),
    ) {
        match &mut self.state {
            StunServerBindingState::Waiting => {
                self.start_binding_request(now, stun_config, on_event)
            }
            StunServerBindingState::InProgress {
                transaction_id: _,
                stun_request,
                retransmit_at,
                retransmits,
            } => {
                if *retransmit_at > now {
                    return;
                }

                if *retransmits >= stun_config.max_retransmits {
                    self.state = StunServerBindingState::Failed;
                    self.last_mapped_addr = None;
                    return;
                }

                *retransmits += 1;
                *retransmit_at += stun_config.retransmit_delta(*retransmits);

                on_event(IceEvent::SendData {
                    component: self.component,
                    data: stun_request.clone(),
                    source: None,
                    target: self.server,
                });
            }
            StunServerBindingState::WaitingForRefresh { refresh_at, .. } => {
                if now > *refresh_at {
                    self.start_binding_request(now, stun_config, on_event);
                }
            }
            StunServerBindingState::Failed => {
                // nothing to do
            }
        }
    }

    fn start_binding_request(
        &mut self,
        now: Instant,
        stun_config: &StunConfig,
        mut on_event: impl FnMut(IceEvent),
    ) {
        let transaction_id = TransactionId::random();

        let mut builder = MessageBuilder::new(Class::Request, Method::Binding, transaction_id);
        builder.add_attr(Fingerprint);

        let stun_request = builder.finish();

        on_event(IceEvent::SendData {
            component: self.component,
            data: stun_request.clone(),
            source: None,
            target: self.server,
        });

        self.state = StunServerBindingState::InProgress {
            transaction_id,
            stun_request,
            retransmit_at: now + stun_config.retransmit_delta(0),
            retransmits: 0,
        };
    }

    pub(crate) fn wants_stun_response(&self, transaction_id: TransactionId) -> bool {
        matches!(&self.state, StunServerBindingState::InProgress { transaction_id: tsx_id, .. } if transaction_id == *tsx_id)
    }

    /// Receive a STUN success response
    ///
    /// Returns a SocketAddr discovered through the STUN binding
    pub(crate) fn receive_stun_response(
        &mut self,
        stun_config: &StunConfig,
        mut stun_msg: Message,
    ) -> Option<SocketAddr> {
        let mapped = stun_msg.attribute::<XorMappedAddress>()?.unwrap();

        self.state = StunServerBindingState::WaitingForRefresh {
            refresh_at: Instant::now() + stun_config.binding_refresh_interval,
        };
        self.last_mapped_addr = Some(mapped.0);

        Some(mapped.0)
    }
}
