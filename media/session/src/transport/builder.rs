use super::{
    dtls_srtp::{to_openssl_digest, DtlsSetup, DtlsSrtpSession},
    resolve_rtp_and_rtcp_address,
    sdes_srtp::{self, SdesSrtpOffer},
    IceAgent, ReceivedPacket, SessionTransportState, Transport, TransportEvent, TransportKind,
    TransportRequiredChanges,
};
use crate::{
    events::TransportConnectionState, rtp::extensions::RtpExtensionIdsExt, ReceivedPkt,
    RtcpMuxPolicy, TransportType,
};
use core::panic;
use ice::{IceCredentials, IceEvent};
use rtp::RtpExtensionIds;
use sdp_types::{Fingerprint, MediaDescription, SessionDescription, Setup};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};
use stun_types::{is_stun_message, IsStunMessageInfo};

/// Builder for a transport which has yet to be negotiated
pub(crate) struct TransportBuilder {
    pub(crate) local_rtp_port: Option<u16>,
    pub(crate) local_rtcp_port: Option<u16>,

    kind: TransportBuilderKind,

    pub(crate) ice_agent: Option<IceAgent>,

    // Backlog of messages received before the SDP answer has been received
    backlog: Vec<ReceivedPkt>,
}

enum TransportBuilderKind {
    Rtp,
    SdesSrtp(SdesSrtpOffer),
    DtlsSrtp { fingerprint: Vec<Fingerprint> },
}

impl TransportBuilder {
    pub(crate) fn placeholder() -> Self {
        Self {
            local_rtp_port: None,
            local_rtcp_port: None,
            kind: TransportBuilderKind::Rtp,
            ice_agent: None,
            backlog: vec![],
        }
    }

    pub(crate) fn new(
        state: &mut SessionTransportState,
        mut required_changes: TransportRequiredChanges<'_>,
        type_: TransportType,
        rtcp_mux_policy: RtcpMuxPolicy,
        offer_ice: bool,
    ) -> Self {
        match rtcp_mux_policy {
            RtcpMuxPolicy::Negotiate => required_changes.require_socket_pair(),
            RtcpMuxPolicy::Require => required_changes.require_socket(),
        }

        let kind = match type_ {
            TransportType::Rtp => TransportBuilderKind::Rtp,
            TransportType::SdesSrtp => {
                TransportBuilderKind::SdesSrtp(sdes_srtp::SdesSrtpOffer::new())
            }
            TransportType::DtlsSrtp => TransportBuilderKind::DtlsSrtp {
                fingerprint: vec![state.dtls_fingerprint()],
            },
        };

        let ice_agent = if offer_ice {
            let mut ice_agent = IceAgent::new_for_offer(
                state.ice_credentials(),
                true,
                matches!(rtcp_mux_policy, RtcpMuxPolicy::Require),
            );

            for server in &state.stun_servers {
                ice_agent.add_stun_server(*server);
            }

            Some(ice_agent)
        } else {
            None
        };

        Self {
            local_rtp_port: None,
            local_rtcp_port: None,
            ice_agent,
            kind,
            backlog: vec![],
        }
    }

    pub(crate) fn populate_desc(&self, desc: &mut MediaDescription) {
        desc.extmap.extend(RtpExtensionIds::offer().to_extmap());

        match &self.kind {
            TransportBuilderKind::Rtp => {}
            TransportBuilderKind::SdesSrtp(offer) => {
                offer.extend_crypto(&mut desc.crypto);
            }
            TransportBuilderKind::DtlsSrtp { fingerprint, .. } => {
                desc.setup = Some(Setup::ActPass);
                desc.fingerprint.extend_from_slice(fingerprint);
            }
        }

        if let Some(ice_agent) = &self.ice_agent {
            desc.ice_candidates.extend(ice_agent.ice_candidates());
            desc.ice_ufrag = Some(sdp_types::IceUsernameFragment {
                ufrag: ice_agent.credentials().ufrag.clone().into(),
            });
            desc.ice_pwd = Some(sdp_types::IcePassword {
                pwd: ice_agent.credentials().pwd.clone().into(),
            });
        }
    }

    pub(crate) fn type_(&self) -> TransportType {
        match self.kind {
            TransportBuilderKind::Rtp => TransportType::Rtp,
            TransportBuilderKind::SdesSrtp { .. } => TransportType::SdesSrtp,
            TransportBuilderKind::DtlsSrtp { .. } => TransportType::DtlsSrtp,
        }
    }

    pub(crate) fn timeout(&self, now: Instant) -> Option<Duration> {
        if let Some(ice_agent) = &self.ice_agent {
            ice_agent.timeout(now)
        } else {
            None
        }
    }

    pub(crate) fn pop_event(&mut self) -> Option<TransportEvent> {
        let ice_agent = self.ice_agent.as_mut()?;

        match ice_agent.pop_event()? {
            IceEvent::GatheringStateChanged { old, new } => {
                Some(TransportEvent::IceGatheringState { old, new })
            }
            IceEvent::ConnectionStateChanged { old, new } => {
                Some(TransportEvent::IceConnectionState { old, new })
            }
            IceEvent::UseAddr { .. } => unreachable!(),
            IceEvent::SendData {
                component,
                data,
                source,
                target,
            } => Some(TransportEvent::SendData {
                component,
                data,
                source,
                target,
            }),
        }
    }

    pub(crate) fn poll(&mut self, now: Instant) {
        if let Some(ice_agent) = &mut self.ice_agent {
            ice_agent.poll(now);
        }
    }

    pub(crate) fn receive(&mut self, pkt: ReceivedPkt) {
        if let Some(ice_agent) = &mut self.ice_agent {
            if matches!(is_stun_message(&pkt.data), IsStunMessageInfo::Yes { .. }) {
                ice_agent.receive(pkt);
                return;
            }
        }

        // Limit the backlog buffer so it doesn't become a problem
        // this will never ever happen in a well behaved environment
        if self.backlog.len() > 100 {
            return;
        }

        self.backlog.push(pkt);
    }

    pub(crate) fn build_from_answer(
        mut self,
        state: &mut SessionTransportState,
        mut required_changes: TransportRequiredChanges<'_>,
        session_desc: &SessionDescription,
        remote_media_desc: &MediaDescription,
    ) -> Transport {
        let (remote_rtp_address, remote_rtcp_address) =
            resolve_rtp_and_rtcp_address(session_desc, remote_media_desc).unwrap();

        // Remove RTCP socket if the answer has rtcp-mux set
        if remote_media_desc.rtcp_mux && self.local_rtcp_port.is_some() {
            required_changes.remove_rtcp_socket();
            self.local_rtcp_port = None;
        }

        let ice_ufrag = session_desc
            .ice_ufrag
            .as_ref()
            .or(remote_media_desc.ice_ufrag.as_ref());

        let ice_pwd = session_desc
            .ice_pwd
            .as_ref()
            .or(remote_media_desc.ice_pwd.as_ref());

        let ice_agent = if let Some((mut ice_agent, (ufrag, pwd))) =
            self.ice_agent.zip(ice_ufrag.zip(ice_pwd))
        {
            ice_agent.set_remote_data(
                IceCredentials {
                    ufrag: ufrag.ufrag.to_string(),
                    pwd: pwd.pwd.to_string(),
                },
                &remote_media_desc.ice_candidates,
                remote_media_desc.rtcp_mux,
            );

            Some(ice_agent)
        } else {
            None
        };

        let receive_extension_ids = RtpExtensionIds::from_sdp(session_desc, remote_media_desc);

        let mut transport = match self.kind {
            TransportBuilderKind::Rtp => Transport {
                local_rtp_port: self.local_rtp_port,
                local_rtcp_port: self.local_rtcp_port,
                remote_rtp_address,
                remote_rtcp_address,
                rtcp_mux: remote_media_desc.rtcp_mux,
                ice_agent,
                negotiated_extension_ids: receive_extension_ids,
                connection_state: TransportConnectionState::New,
                kind: TransportKind::Rtp,
                events: VecDeque::new(),
            },
            TransportBuilderKind::SdesSrtp(offer) => {
                let (crypto, inbound, outbound) = offer.receive_answer(&remote_media_desc.crypto);

                Transport {
                    local_rtp_port: self.local_rtp_port,
                    local_rtcp_port: self.local_rtcp_port,
                    remote_rtp_address,
                    remote_rtcp_address,
                    rtcp_mux: remote_media_desc.rtcp_mux,
                    ice_agent,
                    negotiated_extension_ids: receive_extension_ids,
                    connection_state: TransportConnectionState::New,
                    kind: TransportKind::SdesSrtp {
                        crypto: vec![crypto],
                        inbound,
                        outbound,
                    },
                    events: VecDeque::new(),
                }
            }
            TransportBuilderKind::DtlsSrtp { fingerprint } => {
                let setup = match remote_media_desc.setup {
                    Some(Setup::Active) => DtlsSetup::Accept,
                    Some(Setup::Passive) => DtlsSetup::Connect,
                    _ => panic!("missing or invalid setup attribute"),
                };

                let remote_fingerprints: Vec<_> = session_desc
                    .fingerprint
                    .iter()
                    .chain(remote_media_desc.fingerprint.iter())
                    .filter_map(|e| Some((to_openssl_digest(&e.algorithm)?, e.fingerprint.clone())))
                    .collect();

                let dtls =
                    DtlsSrtpSession::new(state.ssl_context(), remote_fingerprints.clone(), setup)
                        .unwrap();

                Transport {
                    local_rtp_port: self.local_rtp_port,
                    local_rtcp_port: self.local_rtcp_port,
                    remote_rtp_address,
                    remote_rtcp_address,
                    rtcp_mux: remote_media_desc.rtcp_mux,
                    ice_agent,
                    negotiated_extension_ids: receive_extension_ids,
                    connection_state: TransportConnectionState::New,
                    kind: TransportKind::DtlsSrtp {
                        fingerprint,
                        setup: match setup {
                            DtlsSetup::Accept => Setup::Passive,
                            DtlsSetup::Connect => Setup::Active,
                        },
                        dtls,
                        srtp: None,
                    },
                    events: VecDeque::new(),
                }
            }
        };

        // RTP & SDES-SRTP transport are instantly set to the connected state if ICE is not used
        if matches!(
            transport.kind,
            TransportKind::Rtp | TransportKind::SdesSrtp { .. }
        ) && transport.ice_agent.is_none()
        {
            transport.set_connection_state(TransportConnectionState::Connecting);
        }

        // Feed the already received messages into the transport
        for pkt in self.backlog {
            match transport.receive(pkt) {
                ReceivedPacket::Rtp(_) => todo!("handle early rtp"),
                ReceivedPacket::Rtcp(_) => todo!("handle early rtcp"),
                ReceivedPacket::TransportSpecific => {}
            };
        }

        transport
    }
}
