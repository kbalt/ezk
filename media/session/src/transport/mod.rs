use crate::{
    events::{TransportConnectionState, TransportRequiredChanges},
    opt_min,
    rtp::extensions::RtpExtensionIdsExt,
    Error, TransportType,
};
use dtls_srtp::{make_ssl_context, DtlsSetup, DtlsSrtpSession, DtlsState};
use ice::{
    Component, IceAgent, IceConnectionState, IceCredentials, IceEvent, IceGatheringState,
    ReceivedPkt,
};
use openssl::{hash::MessageDigest, ssl::SslContext};
use rtp::{RtpExtensionIds, RtpPacket};
use sdp_types::{
    Connection, Fingerprint, FingerprintAlgorithm, MediaDescription, SessionDescription, Setup,
    SrtpCrypto, TaggedAddress, TransportProtocol,
};
use std::{
    collections::VecDeque,
    io,
    net::{IpAddr, SocketAddr, ToSocketAddrs},
    time::{Duration, Instant},
};

mod builder;
mod dtls_srtp;
mod packet_kind;
mod sdes_srtp;

pub(crate) use builder::TransportBuilder;
pub(crate) use packet_kind::PacketKind;

#[derive(Default)]
pub(crate) struct SessionTransportState {
    ssl_context: Option<openssl::ssl::SslContext>,
    ice_credentials: Option<IceCredentials>,
    stun_servers: Vec<SocketAddr>,
}

impl SessionTransportState {
    pub(crate) fn add_stun_server(&mut self, server: SocketAddr) {
        self.stun_servers.push(server);
    }

    fn ssl_context(&mut self) -> &mut SslContext {
        self.ssl_context.get_or_insert_with(make_ssl_context)
    }

    fn dtls_fingerprint(&mut self) -> Fingerprint {
        let ctx = self.ssl_context();

        Fingerprint {
            algorithm: FingerprintAlgorithm::SHA256,
            fingerprint: ctx
                .certificate()
                .unwrap()
                .digest(MessageDigest::sha256())
                .unwrap()
                .to_vec(),
        }
    }

    fn ice_credentials(&mut self) -> IceCredentials {
        self.ice_credentials
            .get_or_insert_with(IceCredentials::random)
            .clone()
    }
}

pub(crate) enum TransportEvent {
    IceGatheringState {
        old: IceGatheringState,
        new: IceGatheringState,
    },
    IceConnectionState {
        old: IceConnectionState,
        new: IceConnectionState,
    },
    TransportConnectionState {
        old: TransportConnectionState,
        new: TransportConnectionState,
    },
    SendData {
        component: Component,
        data: Vec<u8>,
        source: Option<IpAddr>,
        target: SocketAddr,
    },
}

pub(crate) struct Transport {
    pub(crate) local_rtp_port: Option<u16>,
    pub(crate) local_rtcp_port: Option<u16>,

    pub(crate) remote_rtp_address: SocketAddr,
    pub(crate) remote_rtcp_address: SocketAddr,

    rtcp_mux: bool,

    pub(crate) ice_agent: Option<IceAgent>,

    /// The receiving extension ids
    negotiated_extension_ids: RtpExtensionIds,

    connection_state: TransportConnectionState,
    kind: TransportKind,

    events: VecDeque<TransportEvent>,
}

enum TransportKind {
    Rtp,
    SdesSrtp {
        /// Local crypto attribute
        crypto: Vec<SrtpCrypto>,
        inbound: srtp::Session,
        outbound: srtp::Session,
    },
    DtlsSrtp {
        /// Local DTLS certificate fingerprint attribute
        fingerprint: Vec<Fingerprint>,
        setup: Setup,

        dtls: DtlsSrtpSession,
        srtp: Option<(srtp::Session, srtp::Session)>,
    },
}

impl Transport {
    pub(crate) fn create_from_offer(
        state: &mut SessionTransportState,
        mut required_changes: TransportRequiredChanges<'_>,
        session_desc: &SessionDescription,
        remote_media_desc: &MediaDescription,
    ) -> Result<Option<Self>, Error> {
        if remote_media_desc.rtcp_mux {
            required_changes.require_socket();
        } else {
            required_changes.require_socket_pair();
        }

        let (remote_rtp_address, remote_rtcp_address) =
            resolve_rtp_and_rtcp_address(session_desc, remote_media_desc).unwrap();

        let ice_ufrag = session_desc
            .ice_ufrag
            .as_ref()
            .or(remote_media_desc.ice_ufrag.as_ref());

        let ice_pwd = session_desc
            .ice_pwd
            .as_ref()
            .or(remote_media_desc.ice_pwd.as_ref());

        let ice_agent = if let Some((ufrag, pwd)) = ice_ufrag.zip(ice_pwd) {
            let mut ice_agent = IceAgent::new_from_answer(
                state.ice_credentials(),
                IceCredentials {
                    ufrag: ufrag.ufrag.to_string(),
                    pwd: pwd.pwd.to_string(),
                },
                false,
                remote_media_desc.rtcp_mux,
            );

            for server in &state.stun_servers {
                ice_agent.add_stun_server(*server);
            }

            for candidate in &remote_media_desc.ice_candidates {
                ice_agent.add_remote_candidate(candidate);
            }

            Some(ice_agent)
        } else {
            None
        };

        let receive_extension_ids = RtpExtensionIds::from_sdp(session_desc, remote_media_desc);

        let mut transport = match &remote_media_desc.media.proto {
            TransportProtocol::RtpAvp | TransportProtocol::RtpAvpf => Transport {
                local_rtp_port: None,
                local_rtcp_port: None,
                remote_rtp_address,
                remote_rtcp_address,
                rtcp_mux: remote_media_desc.rtcp_mux,
                ice_agent,
                negotiated_extension_ids: receive_extension_ids,
                connection_state: TransportConnectionState::New,
                kind: TransportKind::Rtp,
                events: VecDeque::new(),
            },
            TransportProtocol::RtpSavp | TransportProtocol::RtpSavpf => {
                let (crypto, inbound, outbound) =
                    sdes_srtp::negotiate_from_offer(&remote_media_desc.crypto)?;

                Transport {
                    local_rtp_port: None,
                    local_rtcp_port: None,
                    remote_rtp_address,
                    remote_rtcp_address,
                    rtcp_mux: remote_media_desc.rtcp_mux,
                    ice_agent,
                    negotiated_extension_ids: receive_extension_ids,
                    connection_state: TransportConnectionState::New,
                    kind: TransportKind::SdesSrtp {
                        crypto,
                        inbound,
                        outbound,
                    },
                    events: VecDeque::new(),
                }
            }
            TransportProtocol::UdpTlsRtpSavp | TransportProtocol::UdpTlsRtpSavpf => {
                Self::dtls_srtp_from_offer(
                    state,
                    session_desc,
                    remote_media_desc,
                    remote_rtp_address,
                    remote_rtcp_address,
                    ice_agent,
                    receive_extension_ids,
                )?
            }
            _ => return Ok(None),
        };

        // RTP & SDES-SRTP transport are instantly set to the connected state if ICE is not used
        if matches!(
            transport.kind,
            TransportKind::Rtp | TransportKind::SdesSrtp { .. }
        ) && transport.ice_agent.is_none()
        {
            transport.set_connection_state(TransportConnectionState::Connected);
        }

        Ok(Some(transport))
    }

    pub(crate) fn dtls_srtp_from_offer(
        state: &mut SessionTransportState,
        session_desc: &SessionDescription,
        remote_media_desc: &MediaDescription,
        remote_rtp_address: SocketAddr,
        remote_rtcp_address: SocketAddr,
        ice_agent: Option<IceAgent>,
        receive_extension_ids: RtpExtensionIds,
    ) -> Result<Self, Error> {
        let setup = match remote_media_desc.setup {
            Some(Setup::Active) => DtlsSetup::Accept,
            Some(Setup::Passive) => DtlsSetup::Connect,
            Some(Setup::ActPass) => {
                // Use passive when accepting an offer so both sides will have the DTLS fingerprint
                // before any request is sent
                DtlsSetup::Accept
            }
            Some(Setup::HoldConn) | None => {
                return Err(io::Error::other("missing or invalid setup attribute").into());
            }
        };

        let remote_fingerprints: Vec<_> = session_desc
            .fingerprint
            .iter()
            .chain(remote_media_desc.fingerprint.iter())
            .filter_map(|e| {
                Some((
                    dtls_srtp::to_openssl_digest(&e.algorithm)?,
                    e.fingerprint.clone(),
                ))
            })
            .collect();

        let dtls = DtlsSrtpSession::new(state.ssl_context(), remote_fingerprints.clone(), setup)?;

        Ok(Transport {
            local_rtp_port: None,
            local_rtcp_port: None,
            remote_rtp_address,
            remote_rtcp_address,
            rtcp_mux: remote_media_desc.rtcp_mux,
            ice_agent,
            negotiated_extension_ids: receive_extension_ids,
            connection_state: TransportConnectionState::New,
            kind: TransportKind::DtlsSrtp {
                fingerprint: vec![state.dtls_fingerprint()],
                setup: match setup {
                    DtlsSetup::Accept => Setup::Passive,
                    DtlsSetup::Connect => Setup::Active,
                },
                dtls,
                srtp: None,
            },
            events: VecDeque::new(),
        })
    }

    pub(crate) fn type_(&self) -> TransportType {
        match self.kind {
            TransportKind::Rtp => TransportType::Rtp,
            TransportKind::SdesSrtp { .. } => TransportType::SdesSrtp,
            TransportKind::DtlsSrtp { .. } => TransportType::DtlsSrtp,
        }
    }

    pub(crate) fn populate_desc(&self, desc: &mut MediaDescription) {
        desc.extmap
            .extend(self.negotiated_extension_ids.to_extmap());

        match &self.kind {
            TransportKind::Rtp => {}
            TransportKind::SdesSrtp { crypto, .. } => {
                desc.crypto.extend_from_slice(crypto);
            }
            TransportKind::DtlsSrtp {
                fingerprint, setup, ..
            } => {
                desc.setup = Some(*setup);
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

    pub(crate) fn timeout(&self, now: Instant) -> Option<Duration> {
        let timeout = match &self.kind {
            TransportKind::Rtp => None,
            TransportKind::SdesSrtp { .. } => None,
            TransportKind::DtlsSrtp { dtls, .. } => dtls.timeout(),
        };

        if let Some(ice_agent) = &self.ice_agent {
            opt_min(ice_agent.timeout(now), timeout)
        } else {
            timeout
        }
    }

    pub(crate) fn pop_event(&mut self) -> Option<TransportEvent> {
        while let Some(ice_event) = self.ice_agent.as_mut().and_then(IceAgent::pop_event) {
            match ice_event {
                IceEvent::GatheringStateChanged { old, new } => {
                    return Some(TransportEvent::IceGatheringState { old, new })
                }
                IceEvent::ConnectionStateChanged { old, new } => {
                    return Some(TransportEvent::IceConnectionState { old, new })
                }
                IceEvent::UseAddr { component, target } => match component {
                    Component::Rtp => self.remote_rtp_address = target,
                    Component::Rtcp => self.remote_rtcp_address = target,
                },
                IceEvent::SendData {
                    component,
                    data,
                    source,
                    target,
                } => {
                    return Some(TransportEvent::SendData {
                        component,
                        data,
                        source,
                        target,
                    })
                }
            }
        }

        if matches!(
            self.connection_state,
            TransportConnectionState::Connecting | TransportConnectionState::Connected
        ) {
            if let TransportKind::DtlsSrtp { dtls, .. } = &mut self.kind {
                if let Some(data) = dtls.pop_to_send() {
                    return Some(TransportEvent::SendData {
                        component: Component::Rtp,
                        data,
                        source: None,
                        target: self.remote_rtp_address,
                    });
                }
            }
        }

        self.events.pop_front()
    }

    pub(crate) fn poll(&mut self, now: Instant) {
        match &mut self.kind {
            TransportKind::Rtp => {}
            TransportKind::SdesSrtp { .. } => {}
            TransportKind::DtlsSrtp { dtls, .. } => {
                assert!(dtls.handshake().unwrap().is_none());

                while let Some(data) = dtls.pop_to_send() {
                    self.events.push_back(TransportEvent::SendData {
                        component: Component::Rtp,
                        data,
                        source: None, // TODO: set this
                        target: self.remote_rtp_address,
                    });
                }
            }
        }

        // update state
        if let Some(ice_agent) = &mut self.ice_agent {
            ice_agent.poll(now);

            match ice_agent.connection_state() {
                IceConnectionState::New => {}
                IceConnectionState::Checking => {}
                IceConnectionState::Connected => self.update_connection_state_on_ice_connected(),
                IceConnectionState::Failed => {
                    self.set_connection_state(TransportConnectionState::Failed);
                }
                IceConnectionState::Disconnected => {
                    // unclear if the transport state should change here, since this state may be temporary
                }
            }
        } else {
            self.update_connection_state_on_ice_connected();
        }
    }

    fn update_connection_state_on_ice_connected(&mut self) {
        match &self.kind {
            TransportKind::Rtp | TransportKind::SdesSrtp { .. } => {
                self.set_connection_state(TransportConnectionState::Connected);
            }
            TransportKind::DtlsSrtp { dtls, srtp, .. } => match dtls.state() {
                DtlsState::Accepting | DtlsState::Connecting => {
                    self.set_connection_state(TransportConnectionState::Connecting);
                }
                DtlsState::Connected => {
                    assert!(
                        srtp.is_some(),
                        "SRTP session must exist if DTLS transport is connected"
                    );

                    self.set_connection_state(TransportConnectionState::Connected);
                }
                DtlsState::Failed => {
                    self.set_connection_state(TransportConnectionState::Failed);
                }
            },
        }
    }

    pub(crate) fn receive(&mut self, mut pkt: ReceivedPkt) -> ReceivedPacket {
        match PacketKind::identify(&pkt.data) {
            PacketKind::Rtp => {
                // Handle incoming RTP packet
                if let TransportKind::SdesSrtp { inbound, .. }
                | TransportKind::DtlsSrtp {
                    srtp: Some((inbound, _)),
                    ..
                } = &mut self.kind
                {
                    inbound.unprotect(&mut pkt.data).unwrap();
                }

                match RtpPacket::parse(self.negotiated_extension_ids, pkt.data) {
                    Ok(packet) => ReceivedPacket::Rtp(packet),
                    Err(e) => {
                        log::warn!("Failed to parse RTP packet, {e}");
                        ReceivedPacket::TransportSpecific
                    }
                }
            }
            PacketKind::Rtcp => {
                // Handle incoming RTCP packet
                if let TransportKind::SdesSrtp { inbound, .. }
                | TransportKind::DtlsSrtp {
                    srtp: Some((inbound, _)),
                    ..
                } = &mut self.kind
                {
                    inbound.unprotect_rtcp(&mut pkt.data).unwrap();
                }

                ReceivedPacket::Rtcp(pkt.data)
            }
            PacketKind::Stun => {
                if let Some(ice_agent) = &mut self.ice_agent {
                    ice_agent.receive(pkt);
                }

                ReceivedPacket::TransportSpecific
            }
            PacketKind::Dtls => {
                // We only expect DTLS traffic on the rtp socket
                if pkt.component != Component::Rtp {
                    return ReceivedPacket::TransportSpecific;
                }

                if let TransportKind::DtlsSrtp { dtls, srtp, .. } = &mut self.kind {
                    dtls.receive(pkt.data.clone());

                    if let Some((inbound, outbound)) = dtls.handshake().unwrap() {
                        *srtp = Some((inbound.into_session(), outbound.into_session()));
                    }

                    while let Some(data) = dtls.pop_to_send() {
                        self.events.push_back(TransportEvent::SendData {
                            component: Component::Rtp,
                            data,
                            source: None, // TODO: set this
                            target: self.remote_rtp_address,
                        });
                    }
                }

                ReceivedPacket::TransportSpecific
            }
            PacketKind::Unknown => {
                // Discard
                ReceivedPacket::TransportSpecific
            }
        }
    }

    pub(crate) fn send_rtp(&mut self, packet: RtpPacket) {
        let mut packet = packet.to_vec(self.negotiated_extension_ids);

        match &mut self.kind {
            TransportKind::DtlsSrtp { srtp: None, .. } => {
                panic!("Tried to protect RTP on non-ready DTLS-SRTP transport");
            }
            TransportKind::SdesSrtp { outbound, .. }
            | TransportKind::DtlsSrtp {
                srtp: Some((_, outbound)),
                ..
            } => {
                outbound.protect(&mut packet).unwrap();
            }
            _ => (),
        }

        self.events.push_back(TransportEvent::SendData {
            component: Component::Rtp,
            data: packet,
            source: None,
            target: self.remote_rtp_address,
        });
    }

    pub(crate) fn send_rtcp(&mut self, mut packet: Vec<u8>) {
        match &mut self.kind {
            TransportKind::DtlsSrtp { srtp: None, .. } => {
                panic!("Tried to protect RTCP on non-ready DTLS-SRTP transport");
            }
            TransportKind::SdesSrtp { outbound, .. }
            | TransportKind::DtlsSrtp {
                srtp: Some((_, outbound)),
                ..
            } => {
                outbound.protect_rtcp(&mut packet).unwrap();
            }
            _ => (),
        }

        let component = if self.rtcp_mux {
            Component::Rtp
        } else {
            Component::Rtcp
        };

        self.events.push_back(TransportEvent::SendData {
            component,
            data: packet,
            source: None, // TODO: set this according to the transport
            target: self.remote_rtcp_address,
        });
    }

    // Set the a new connection state and emit an event if the state differs from the old one
    fn set_connection_state(&mut self, new: TransportConnectionState) {
        if self.connection_state != new {
            self.events
                .push_back(TransportEvent::TransportConnectionState {
                    old: self.connection_state,
                    new,
                });

            self.connection_state = new;
        }
    }

    pub(crate) fn connection_state(&self) -> TransportConnectionState {
        self.connection_state
    }
}

#[derive(Debug)]
#[must_use]
pub(crate) enum ReceivedPacket {
    Rtp(RtpPacket),
    Rtcp(Vec<u8>),
    TransportSpecific,
}

fn resolve_rtp_and_rtcp_address(
    remote_session_description: &SessionDescription,
    remote_media_description: &MediaDescription,
) -> Result<(SocketAddr, SocketAddr), Error> {
    let connection = remote_media_description
        .connection
        .as_ref()
        .or(remote_session_description.connection.as_ref())
        .unwrap();

    let remote_rtp_address = connection.address.clone();
    let remote_rtp_port = remote_media_description.media.port;

    let (remote_rtcp_address, remote_rtcp_port) =
        rtcp_address_and_port(remote_media_description, connection);

    let remote_rtp_address = resolve_tagged_address(&remote_rtp_address, remote_rtp_port)?;
    let remote_rtcp_address = resolve_tagged_address(&remote_rtcp_address, remote_rtcp_port)?;

    Ok((remote_rtp_address, remote_rtcp_address))
}

fn rtcp_address_and_port(
    remote_media_description: &MediaDescription,
    connection: &Connection,
) -> (TaggedAddress, u16) {
    if remote_media_description.rtcp_mux {
        return (
            connection.address.clone(),
            remote_media_description.media.port,
        );
    }

    if let Some(rtcp_addr) = &remote_media_description.rtcp {
        let address = rtcp_addr
            .address
            .clone()
            .unwrap_or_else(|| connection.address.clone());

        return (address, rtcp_addr.port);
    }

    (
        connection.address.clone(),
        remote_media_description.media.port + 1,
    )
}

fn resolve_tagged_address(address: &TaggedAddress, port: u16) -> io::Result<SocketAddr> {
    // TODO: do not resolve here directly
    match address {
        TaggedAddress::IP4(ipv4_addr) => Ok(SocketAddr::from((*ipv4_addr, port))),
        TaggedAddress::IP4FQDN(bytes_str) => (bytes_str.as_str(), port)
            .to_socket_addrs()?
            .find(SocketAddr::is_ipv4)
            .ok_or_else(|| {
                io::Error::other(format!("Failed to find IPv4 address for {bytes_str}"))
            }),
        TaggedAddress::IP6(ipv6_addr) => Ok(SocketAddr::from((*ipv6_addr, port))),
        TaggedAddress::IP6FQDN(bytes_str) => (bytes_str.as_str(), port)
            .to_socket_addrs()?
            .find(SocketAddr::is_ipv6)
            .ok_or_else(|| {
                io::Error::other(format!("Failed to find IPv6 address for {bytes_str}"))
            }),
    }
}
