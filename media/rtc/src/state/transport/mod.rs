use super::opt_min;
use crate::state::{
    sdp::TransportType,
    transport::{dtls_srtp::DtlsState, packet_kind::PacketKind},
};
use ice::{Component, IceAgent, IceConnectionState, ReceivedPkt};
use rtp::{RtpExtensionIds, RtpPacket};
use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

mod dtls_srtp;
mod event;
mod packet_kind;
mod sdes_srtp;

pub(crate) use dtls_srtp::make_ssl_context;
pub use dtls_srtp::{DtlsHandshakeError, DtlsSetup, DtlsSrtpCreateError, RtpDtlsSrtpTransport};
pub use event::{RtpTransportEvent, TransportConnectionState};
pub use sdes_srtp::RtpSdesSrtpTransport;

pub struct RtpTransport {
    ports: Option<RtpTransportPorts>,
    connectivity: Connectivity,
    rtcp_mux: bool,
    extension_ids: RtpExtensionIds,
    kind: RtpTransportKind,
    connection_state: TransportConnectionState,
    events: VecDeque<RtpTransportEvent>,
}

#[allow(clippy::large_enum_variant)]
pub enum Connectivity {
    Static {
        remote_rtp_address: SocketAddr,
        remote_rtcp_address: SocketAddr,
    },
    Ice(IceAgent),
}

pub enum RtpTransportKind {
    Unencrypted,
    SdesSrtp(RtpSdesSrtpTransport),
    DtlsSrtp(RtpDtlsSrtpTransport),
}

impl RtpTransport {
    pub fn new(
        connectivity: Connectivity,
        rtcp_mux: bool,
        extension_ids: RtpExtensionIds,
        kind: RtpTransportKind,
    ) -> Self {
        RtpTransport {
            ports: None,
            connectivity,
            rtcp_mux,
            extension_ids,
            kind,
            connection_state: TransportConnectionState::New,
            events: VecDeque::new(),
        }
    }

    pub fn set_ports(&mut self, ports: RtpTransportPorts) {
        self.ports = Some(ports)
    }

    #[track_caller]
    pub(crate) fn require_ports(&self) -> &RtpTransportPorts {
        self.ports
            .as_ref()
            .expect("RtpTransports::require_ports called before set_ports")
    }

    pub fn connectivity(&self) -> &Connectivity {
        &self.connectivity
    }

    pub fn connectivity_mut(&mut self) -> &mut Connectivity {
        &mut self.connectivity
    }

    pub fn kind(&self) -> &RtpTransportKind {
        &self.kind
    }

    pub fn kind_mut(&mut self) -> &mut RtpTransportKind {
        &mut self.kind
    }

    pub fn type_(&self) -> TransportType {
        match &self.kind {
            RtpTransportKind::Unencrypted => TransportType::Rtp,
            RtpTransportKind::SdesSrtp(..) => TransportType::SdesSrtp,
            RtpTransportKind::DtlsSrtp(..) => TransportType::DtlsSrtp,
        }
    }

    pub fn extension_ids(&self) -> RtpExtensionIds {
        self.extension_ids
    }

    pub fn timeout(&self, now: Instant) -> Option<Duration> {
        let mut timeout = None;

        match &self.kind {
            RtpTransportKind::Unencrypted => {}
            RtpTransportKind::SdesSrtp(..) => {}
            RtpTransportKind::DtlsSrtp(rtp_dtls_srtp_transport) => {
                timeout = opt_min(timeout, rtp_dtls_srtp_transport.timeout());
            }
        }

        match &self.connectivity {
            Connectivity::Static { .. } => {}
            Connectivity::Ice(ice_agent) => timeout = opt_min(timeout, ice_agent.timeout(now)),
        }

        timeout
    }

    pub fn poll(&mut self, now: Instant) {
        // Poll ICE
        if let Connectivity::Ice(ice_agent) = &mut self.connectivity {
            ice_agent.poll(now);

            if let Some(event) = ice_agent.pop_event().and_then(ice_to_transport_event) {
                self.events.push_back(event);

                match ice_agent.connection_state() {
                    IceConnectionState::New => {}
                    IceConnectionState::Checking => {}
                    IceConnectionState::Connected => {
                        self.update_connection_state_on_ice_connected()
                    }
                    IceConnectionState::Failed => {
                        self.set_connection_state(TransportConnectionState::Failed);
                    }
                    IceConnectionState::Disconnected => {
                        // unclear if the transport state should change here, since this state may be temporary
                    }
                }
            }
        } else {
            self.update_connection_state_on_ice_connected();
        }

        // Poll DTLS if RTP addr is known
        let (local_rtp_addr, remote_rtp_addr) = match &self.connectivity {
            Connectivity::Static {
                remote_rtp_address, ..
            } => (None, *remote_rtp_address),
            Connectivity::Ice(ice_agent) => {
                let Some((local, remote)) = ice_agent.discovered_addr(Component::Rtp) else {
                    return;
                };

                (Some(local.ip()), remote)
            }
        };

        if let RtpTransportKind::DtlsSrtp(rtp_dtls_srtp_transport) = &mut self.kind {
            rtp_dtls_srtp_transport.handshake().unwrap(); // TODO: handle error

            if let Some(data) = rtp_dtls_srtp_transport.pop_to_send() {
                self.events.push_back(RtpTransportEvent::SendData {
                    component: Component::Rtp,
                    data,
                    source: local_rtp_addr,
                    target: remote_rtp_addr,
                });
            }
        }
    }

    fn update_connection_state_on_ice_connected(&mut self) {
        match &mut self.kind {
            RtpTransportKind::Unencrypted | RtpTransportKind::SdesSrtp(..) => {
                self.set_connection_state(TransportConnectionState::Connected);
            }
            RtpTransportKind::DtlsSrtp(transport) => match transport.state() {
                DtlsState::Accepting | DtlsState::Connecting => {
                    self.set_connection_state(TransportConnectionState::Connecting);
                }
                DtlsState::Connected { .. } => {
                    self.set_connection_state(TransportConnectionState::Connected);
                }
                DtlsState::Failed => {
                    self.set_connection_state(TransportConnectionState::Failed);
                }
            },
        }
    }

    // Set the a new connection state and emit an event if the state differs from the old one
    fn set_connection_state(&mut self, new: TransportConnectionState) {
        if self.connection_state != new {
            self.events
                .push_back(RtpTransportEvent::TransportConnectionState {
                    old: self.connection_state,
                    new,
                });

            self.connection_state = new;
        }
    }

    pub fn pop_event(&mut self) -> Option<RtpTransportEvent> {
        self.events.pop_front()
    }

    pub fn receive(&mut self, mut pkt: ReceivedPkt) -> Option<RtpOrRtcp> {
        match PacketKind::identify(&pkt.data) {
            PacketKind::Rtp => {
                match &mut self.kind {
                    RtpTransportKind::Unencrypted => {}
                    RtpTransportKind::SdesSrtp(rtp_sdes_srtp_transport) => {
                        if let Err(e) = rtp_sdes_srtp_transport.inbound.unprotect(&mut pkt.data) {
                            log::warn!("Failed to unprotect incoming RTP packet, {e}");
                            return None;
                        }
                    }
                    RtpTransportKind::DtlsSrtp(rtp_dtls_srtp_transport) => {
                        if let DtlsState::Connected { inbound, .. } =
                            rtp_dtls_srtp_transport.state()
                        {
                            if let Err(e) = inbound.unprotect(&mut pkt.data) {
                                log::warn!("Failed to unprotect incoming RTP packet, {e}");
                                return None;
                            }
                        } else {
                            log::warn!("Got RTP packet before DTLS connection is complete");
                            return None;
                        }
                    }
                }

                let rtp_packet = match RtpPacket::parse(self.extension_ids, pkt.data) {
                    Ok(rtp_packet) => rtp_packet,
                    Err(e) => {
                        log::warn!("Failed to parse incoming RTP packet, {e}");
                        return None;
                    }
                };

                Some(RtpOrRtcp::Rtp(rtp_packet))
            }
            PacketKind::Rtcp => {
                match &mut self.kind {
                    RtpTransportKind::Unencrypted => {}
                    RtpTransportKind::SdesSrtp(rtp_sdes_srtp_transport) => {
                        if let Err(e) = rtp_sdes_srtp_transport
                            .inbound
                            .unprotect_rtcp(&mut pkt.data)
                        {
                            log::warn!("Failed to unprotect incoming RTCP packet, {e}");
                            return None;
                        }
                    }
                    RtpTransportKind::DtlsSrtp(rtp_dtls_srtp_transport) => {
                        if let DtlsState::Connected { inbound, .. } =
                            rtp_dtls_srtp_transport.state()
                        {
                            if let Err(e) = inbound.unprotect_rtcp(&mut pkt.data) {
                                log::warn!("Failed to unprotect incoming RTCP packet, {e}");
                                return None;
                            }
                        } else {
                            log::warn!("Got RTCP packet before DTLS connection is complete");
                            return None;
                        }
                    }
                }

                Some(RtpOrRtcp::Rtcp(pkt.data))
            }
            PacketKind::Stun => {
                if let Connectivity::Ice(ice_agent) = &mut self.connectivity {
                    ice_agent.receive(pkt);
                }

                None
            }
            PacketKind::Dtls => {
                // We only expect DTLS traffic on the rtp socket
                if pkt.component != Component::Rtp {
                    return None;
                }

                let RtpTransportKind::DtlsSrtp(rtp_dtls_srtp_transport) = &mut self.kind else {
                    log::warn!("Ignoring DTLS packet on non-DTLS transport");
                    return None;
                };

                rtp_dtls_srtp_transport.receive(pkt.data.clone());
                rtp_dtls_srtp_transport.handshake().unwrap();

                // Only try to send data if we know the remote's RTP address
                let (local_rtp_addr, remote_rtp_addr) = match &self.connectivity {
                    Connectivity::Static {
                        remote_rtp_address, ..
                    } => (None, *remote_rtp_address),
                    Connectivity::Ice(ice_agent) => {
                        match ice_agent.discovered_addr(Component::Rtp) {
                            Some((local_rtp_addr, remote_rtp_addr)) => {
                                (Some(local_rtp_addr.ip()), remote_rtp_addr)
                            }
                            None => return None,
                        }
                    }
                };

                while let Some(data) = rtp_dtls_srtp_transport.pop_to_send() {
                    self.events.push_back(RtpTransportEvent::SendData {
                        component: Component::Rtp,
                        data,
                        source: local_rtp_addr,
                        target: remote_rtp_addr,
                    });
                }

                None
            }
            PacketKind::Unknown => {
                // ignore
                None
            }
        }
    }

    pub fn writer(&mut self) -> Option<RtpTransportWriter<'_>> {
        // Check that all addresses are known
        let (local_rtp_addr, local_rtcp_addr, remote_rtp_addr, remote_rtcp_addr) =
            match &self.connectivity {
                Connectivity::Static {
                    remote_rtp_address,
                    remote_rtcp_address,
                } => (None, None, *remote_rtp_address, *remote_rtcp_address),
                Connectivity::Ice(ice_agent) => {
                    let (local_rtp_address, remote_rtp_address) = ice_agent
                        .discovered_addr(Component::Rtp)
                        .map(|(local, remote)| (Some(local), remote))?;

                    if self.rtcp_mux {
                        (
                            local_rtp_address,
                            local_rtp_address,
                            remote_rtp_address,
                            remote_rtp_address,
                        )
                    } else {
                        let (local_rtcp_address, remote_rtcp_address) = ice_agent
                            .discovered_addr(Component::Rtcp)
                            .map(|(local, remote)| (Some(local), remote))?;

                        (
                            local_rtp_address,
                            local_rtcp_address,
                            remote_rtp_address,
                            remote_rtcp_address,
                        )
                    }
                }
            };

        Some(RtpTransportWriter {
            transport: self,
            local_rtp_addr: local_rtp_addr.map(|addr| addr.ip()),
            local_rtcp_addr: local_rtcp_addr.map(|addr| addr.ip()),
            remote_rtp_addr,
            remote_rtcp_addr,
        })
    }
}

pub enum RtpOrRtcp {
    Rtp(RtpPacket),
    Rtcp(Vec<u8>),
}

/// Local UDP port of an RtpTransport
#[derive(Debug, Clone, Copy)]
pub struct RtpTransportPorts {
    pub(crate) rtp: u16,
    pub(crate) rtcp: Option<u16>,
}

impl RtpTransportPorts {
    pub fn new(rtp: u16, rtcp: u16) -> Self {
        Self {
            rtp,
            rtcp: Some(rtcp),
        }
    }

    pub fn mux(port: u16) -> Self {
        Self {
            rtp: port,
            rtcp: None,
        }
    }
}

pub(crate) fn ice_to_transport_event(event: ice::IceEvent) -> Option<RtpTransportEvent> {
    match event {
        ice::IceEvent::GatheringStateChanged { old, new } => {
            Some(RtpTransportEvent::IceGatheringState { old, new })
        }
        ice::IceEvent::ConnectionStateChanged { old, new } => {
            Some(RtpTransportEvent::IceConnectionState { old, new })
        }
        ice::IceEvent::DiscoveredAddr { .. } => {
            // TODO: currently not using this event
            None
        }
        ice::IceEvent::SendData {
            component,
            data,
            source,
            target,
        } => Some(RtpTransportEvent::SendData {
            component,
            data,
            source,
            target,
        }),
    }
}

pub struct RtpTransportWriter<'a> {
    transport: &'a mut RtpTransport,
    local_rtp_addr: Option<IpAddr>,
    local_rtcp_addr: Option<IpAddr>,
    remote_rtp_addr: SocketAddr,
    remote_rtcp_addr: SocketAddr,
}

impl RtpTransportWriter<'_> {
    pub fn send_rtp(&mut self, rtp_packet: RtpPacket) {
        let mut data = rtp_packet.to_vec(self.transport.extension_ids);

        match &mut self.transport.kind {
            RtpTransportKind::Unencrypted => {}
            RtpTransportKind::SdesSrtp(rtp_sdes_srtp_transport) => {
                rtp_sdes_srtp_transport.outbound.protect(&mut data).unwrap()
            }
            RtpTransportKind::DtlsSrtp(rtp_dtls_srtp_transport) => {
                let DtlsState::Connected { outbound, .. } = rtp_dtls_srtp_transport.state() else {
                    return; // unreachable
                };

                outbound.protect(&mut data).unwrap()
            }
        }

        self.transport
            .events
            .push_back(RtpTransportEvent::SendData {
                component: Component::Rtp,
                data,
                source: self.local_rtp_addr,
                target: self.remote_rtp_addr,
            });
    }

    pub fn send_rctp(&mut self, mut rtcp_packet: Vec<u8>) {
        match &mut self.transport.kind {
            RtpTransportKind::Unencrypted => {}
            RtpTransportKind::SdesSrtp(rtp_sdes_srtp_transport) => rtp_sdes_srtp_transport
                .outbound
                .protect(&mut rtcp_packet)
                .unwrap(),
            RtpTransportKind::DtlsSrtp(rtp_dtls_srtp_transport) => {
                let DtlsState::Connected { outbound, .. } = rtp_dtls_srtp_transport.state() else {
                    return; // unreachable
                };

                outbound.protect_rtcp(&mut rtcp_packet).unwrap()
            }
        }

        self.transport
            .events
            .push_back(RtpTransportEvent::SendData {
                component: Component::Rtp,
                data: rtcp_packet,
                source: self.local_rtcp_addr,
                target: self.remote_rtcp_addr,
            });
    }
}
