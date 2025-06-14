use std::{
    collections::VecDeque,
    net::SocketAddr,
    time::{Duration, Instant},
};

use super::TransportId;
use crate::{
    sdp::{rtp_extensions::RtpExtensionIdsExt, TransportChange, TransportType},
    rtp_transport::{
        ice_to_transport_event, Connectivity, DtlsSetup, DtlsSrtpCreateError, RtpDtlsSrtpTransport, RtpOrRtcp, RtpTransport, RtpTransportEvent, RtpTransportKind, RtpTransportPorts
    },
};
use ice::{IceAgent, IceCredentials, ReceivedPkt};
use openssl::{hash::MessageDigest, ssl::SslContext};
use resolve::resolve_rtp_and_rtcp_address;
use rtp::RtpExtensionIds;
use sdes_srtp::{SdesSrtpNegotiationError, SdesSrtpOffer};
use sdp_types::{
    FingerprintAlgorithm, MediaDescription, SessionDescription, Setup, TransportProtocol,
};
use stun_types::{IsStunMessageInfo, is_stun_message};

pub(super) mod resolve;
mod sdes_srtp;

pub use resolve::ResolveError;

#[derive(Debug, thiserror::Error)]
pub enum TransportCreateError {
    #[error("Failed to create DTLS-SRTP transport: {0}")]
    CreateDtlsSrtp(#[from] DtlsSrtpCreateError),
    #[error("Failed to negotiate SDES-SRTP session: {0}")]
    FailedSdesSrtp(#[from] SdesSrtpNegotiationError),
    #[error("Invalid or missing setup attribute in SDP")]
    InvalidSetupAttribute,
    #[error(transparent)]
    Resolve(#[from] ResolveError),
    #[error("Unknown transport type")]
    UnknownTransportType,
}

pub(crate) struct OfferedTransport {
    pub(crate) public_id: TransportId,

    ports: Option<RtpTransportPorts>,

    kind: OfferedTransportKind,
    ice_agent: Option<IceAgent>,

    /// Buffer of prematurely received packets, before the SDP negotiation is complete
    backlog: Vec<(Instant, ReceivedPkt)>,
}

enum OfferedTransportKind {
    Unencrypted,
    SdesSrtp(SdesSrtpOffer),
    DtlsSrtp,
}

impl OfferedTransport {
    pub(crate) fn new(
        changes: &mut VecDeque<TransportChange>,
        id: TransportId,
        kind: TransportType,
        ice_agent: Option<IceAgent>,
        rtcp_mux: bool,
    ) -> Self {
        if rtcp_mux {
            changes.push_back(TransportChange::CreateSocket(id));
        } else {
            changes.push_back(TransportChange::CreateSocketPair(id));
        }

        let kind = match kind {
            TransportType::Rtp => OfferedTransportKind::Unencrypted,
            TransportType::SdesSrtp => OfferedTransportKind::SdesSrtp(SdesSrtpOffer::new()),
            TransportType::DtlsSrtp => OfferedTransportKind::DtlsSrtp,
        };

        Self {
            public_id: id,
            ports: None,
            kind,
            ice_agent,
            backlog: Vec::new(),
        }
    }

    pub(crate) fn set_ports(&mut self, ports: RtpTransportPorts) {
        self.ports = Some(ports)
    }

    #[track_caller]
    pub(crate) fn require_ports(&self) -> &RtpTransportPorts {
        self.ports
            .as_ref()
            .expect("RtpTransports::require_ports called before set_ports")
    }

    pub(crate) fn ice_agent(&mut self) -> Option<&mut IceAgent> {
        self.ice_agent.as_mut()
    }

    pub(crate) fn type_(&self) -> TransportType {
        match &self.kind {
            OfferedTransportKind::Unencrypted => TransportType::Rtp,
            OfferedTransportKind::SdesSrtp(..) => TransportType::SdesSrtp,
            OfferedTransportKind::DtlsSrtp => TransportType::DtlsSrtp,
        }
    }

    pub(crate) fn is_dtls(&self) -> bool {
        matches!(self.kind, OfferedTransportKind::DtlsSrtp)
    }

    pub(crate) fn populate_desc(&self, desc: &mut MediaDescription) {
        desc.extmap.extend(RtpExtensionIds::offer().to_extmap());

        match &self.kind {
            OfferedTransportKind::Unencrypted => {}
            OfferedTransportKind::SdesSrtp(offer) => {
                offer.extend_crypto(&mut desc.crypto);
            }
            OfferedTransportKind::DtlsSrtp => {
                // we're not setting the fingerprint attribute on media level
                desc.setup = Some(Setup::ActPass);
            }
        }
    }

    pub(crate) fn build_from_answer(
        self,
        ssl_context: &SslContext,
        changes: &mut VecDeque<TransportChange>,
        remote_session_desc: &SessionDescription,
        remote_media_desc: &MediaDescription,
    ) -> Result<(RtpTransport, Vec<(Instant, RtpOrRtcp)>), TransportCreateError> {
        let mut ports = *self.require_ports();

        // Remove RTCP socket if the answer has rtcp-mux set
        if remote_media_desc.rtcp_mux && ports.rtcp.is_some() {
            changes.push_back(TransportChange::RemoveRtcpSocket(self.public_id));
            ports.rtcp = None;
        }

        let ice_ufrag = remote_session_desc
            .ice_ufrag
            .as_ref()
            .or(remote_media_desc.ice_ufrag.as_ref());

        let ice_pwd = remote_session_desc
            .ice_pwd
            .as_ref()
            .or(remote_media_desc.ice_pwd.as_ref());

        let connectivity = if let Some((mut ice_agent, (ufrag, pwd))) =
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

            Connectivity::Ice(ice_agent)
        } else {
            let (remote_rtp_address, remote_rtcp_address) =
                resolve_rtp_and_rtcp_address(remote_session_desc, remote_media_desc)?;

            Connectivity::Static {
                remote_rtp_address,
                remote_rtcp_address,
            }
        };

        let kind = match self.kind {
            OfferedTransportKind::Unencrypted => RtpTransportKind::Unencrypted,
            OfferedTransportKind::SdesSrtp(sdes_srtp_offer) => {
                let transport = sdes_srtp_offer
                    .receive_answer(&remote_media_desc.crypto)
                    .map_err(TransportCreateError::FailedSdesSrtp)?;

                RtpTransportKind::SdesSrtp(transport)
            }
            OfferedTransportKind::DtlsSrtp => {
                let setup = match remote_media_desc.setup {
                    Some(Setup::Active) => DtlsSetup::Accept,
                    Some(Setup::Passive) => DtlsSetup::Connect,
                    Some(Setup::HoldConn | Setup::ActPass) | None => {
                        return Err(TransportCreateError::InvalidSetupAttribute);
                    }
                };

                let fingerprints = remote_session_desc
                    .fingerprint
                    .iter()
                    .chain(remote_media_desc.fingerprint.iter())
                    .filter_map(|e| Some((to_openssl_digest(&e.algorithm)?, e.fingerprint.clone())))
                    .collect();

                RtpTransportKind::DtlsSrtp(RtpDtlsSrtpTransport::new(
                    ssl_context,
                    fingerprints,
                    setup,
                )?)
            }
        };

        let mut transport = RtpTransport::new(
            connectivity,
            remote_media_desc.rtcp_mux,
            RtpExtensionIds::from_sdp(remote_session_desc, remote_media_desc),
            kind,
        );
        transport.set_ports(ports);

        let mut received_rtp_or_rtcp = vec![];

        // Feed the already received messages into the transport
        for (instant, pkt) in self.backlog {
            if let Some(rtp_or_rtcp) = transport.receive(pkt) {
                received_rtp_or_rtcp.push((instant, rtp_or_rtcp));
            }
        }

        Ok((transport, received_rtp_or_rtcp))
    }

    pub(crate) fn timeout(&self, now: Instant) -> Option<Duration> {
        self.ice_agent
            .as_ref()
            .and_then(|ice_agent| ice_agent.timeout(now))
    }

    pub(crate) fn poll(&mut self, now: Instant) {
        if let Some(ice_agent) = &mut self.ice_agent {
            ice_agent.poll(now);
        }
    }

    pub(crate) fn pop_event(&mut self) -> Option<RtpTransportEvent> {
        self.ice_agent()
            .and_then(|ice_agent| ice_agent.pop_event())
            .and_then(ice_to_transport_event)
    }

    pub(crate) fn receive(&mut self, now: Instant, pkt: ReceivedPkt) {
        if let Some(ice_agent) = &mut self.ice_agent {
            if matches!(is_stun_message(&pkt.data), IsStunMessageInfo::Yes { .. }) {
                ice_agent.receive(pkt);
                return;
            }
        }

        // Limit the backlog buffer so it doesn't become a problem
        // this will never ever happen in a well behaved environment
        if self.backlog.len() > 100 {
            log::warn!(
                "OfferedTransport dropping received packet since backlog buffer is at its limit"
            );
            return;
        }

        self.backlog.push((now, pkt));
    }
}

/// create RtpTransport from SDP offer & SdpSession
pub(super) fn create_from_offer(
    ssl_context: &SslContext,
    ice_credentials: &IceCredentials,
    stun_servers: &[SocketAddr],
    changes: &mut VecDeque<TransportChange>,
    id: TransportId,
    session_desc: &SessionDescription,
    media_desc: &MediaDescription,
) -> Result<RtpTransport, TransportCreateError> {
    if media_desc.rtcp_mux {
        changes.push_back(TransportChange::CreateSocket(id));
    } else {
        changes.push_back(TransportChange::CreateSocketPair(id));
    }

    let ice_ufrag = session_desc
        .ice_ufrag
        .as_ref()
        .or(media_desc.ice_ufrag.as_ref());

    let ice_pwd = session_desc
        .ice_pwd
        .as_ref()
        .or(media_desc.ice_pwd.as_ref());

    let connectivity = if let Some((ufrag, pwd)) = ice_ufrag.zip(ice_pwd) {
        let mut ice_agent = IceAgent::new_from_answer(
            ice_credentials.clone(),
            IceCredentials {
                ufrag: ufrag.ufrag.to_string(),
                pwd: pwd.pwd.to_string(),
            },
            false,
            media_desc.rtcp_mux,
        );

        for server in stun_servers {
            ice_agent.add_stun_server(*server);
        }

        for candidate in &media_desc.ice_candidates {
            ice_agent.add_remote_candidate(candidate);
        }

        Connectivity::Ice(ice_agent)
    } else {
        let (remote_rtp_address, remote_rtcp_address) =
            resolve_rtp_and_rtcp_address(session_desc, media_desc).unwrap();

        Connectivity::Static {
            remote_rtp_address,
            remote_rtcp_address,
        }
    };

    let extension_ids = RtpExtensionIds::from_sdp(session_desc, media_desc);

    let transport_kind = match &media_desc.media.proto {
        TransportProtocol::RtpAvp | TransportProtocol::RtpAvpf => RtpTransportKind::Unencrypted,
        TransportProtocol::RtpSavp | TransportProtocol::RtpSavpf => {
            RtpTransportKind::SdesSrtp(sdes_srtp::negotiate_from_offer(&media_desc.crypto)?)
        }
        TransportProtocol::UdpTlsRtpSavp | TransportProtocol::UdpTlsRtpSavpf => {
            let setup = match media_desc.setup {
                Some(Setup::Active) => DtlsSetup::Accept,
                Some(Setup::Passive) => DtlsSetup::Connect,
                Some(Setup::ActPass) => {
                    // Use passive when accepting an offer so both sides will have the DTLS fingerprint
                    // before any request is sent
                    DtlsSetup::Accept
                }
                Some(Setup::HoldConn) | None => {
                    return Err(TransportCreateError::InvalidSetupAttribute);
                }
            };

            let fingerprints: Vec<_> = session_desc
                .fingerprint
                .iter()
                .chain(media_desc.fingerprint.iter())
                .filter_map(|e| Some((to_openssl_digest(&e.algorithm)?, e.fingerprint.clone())))
                .collect();

            RtpTransportKind::DtlsSrtp(RtpDtlsSrtpTransport::new(ssl_context, fingerprints, setup)?)
        }
        _ => return Err(TransportCreateError::UnknownTransportType),
    };

    Ok(RtpTransport::new(
        connectivity,
        media_desc.rtcp_mux,
        extension_ids,
        transport_kind,
    ))
}

pub(super) fn populate_desc(transport: &RtpTransport, media_desc: &mut MediaDescription) {
    media_desc
        .extmap
        .extend(transport.extension_ids().to_extmap());

    match transport.kind() {
        RtpTransportKind::Unencrypted => {}
        RtpTransportKind::SdesSrtp(rtp_sdes_srtp_transport) => {
            media_desc
                .crypto
                .push(rtp_sdes_srtp_transport.local_sdp_crypto().clone());
        }
        RtpTransportKind::DtlsSrtp(rtp_dtls_srtp_transport) => {
            // we're not setting the fingerprint attribute on the media level
            media_desc.setup = Some(match rtp_dtls_srtp_transport.setup() {
                DtlsSetup::Accept => Setup::Passive,
                DtlsSetup::Connect => Setup::Active,
            });
        }
    }
}

pub(super) fn to_openssl_digest(algo: &FingerprintAlgorithm) -> Option<MessageDigest> {
    match algo {
        FingerprintAlgorithm::SHA1 => Some(MessageDigest::sha1()),
        FingerprintAlgorithm::SHA224 => Some(MessageDigest::sha224()),
        FingerprintAlgorithm::SHA256 => Some(MessageDigest::sha256()),
        FingerprintAlgorithm::SHA384 => Some(MessageDigest::sha384()),
        FingerprintAlgorithm::SHA512 => Some(MessageDigest::sha512()),
        FingerprintAlgorithm::MD5 => Some(MessageDigest::md5()),
        FingerprintAlgorithm::MD2 => None,
        FingerprintAlgorithm::Other(..) => None,
    }
}
