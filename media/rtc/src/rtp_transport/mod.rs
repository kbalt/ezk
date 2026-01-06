//! # RTP transport with optional ICE & SRTP protection
//!
//! See [`RtpTransport`].
//!
//! It is intended to be used alongside [`RtpSession`](crate::rtp_session::RtpSession).
//!
//! # Supported transports
//!
//! - Raw RTP without any protection [`RtpTransportKind::Unencrypted`]
//! - SRTP with key exchange via SDP [`RtpSdesSrtpTransport`]
//! - SRTP with key exchange via DTLS handshake [`RtpDtlsSrtpTransport`]

use super::opt_min;
use crate::{
    Mtu,
    rtp_transport::{dtls_srtp::DtlsState, packet_kind::PacketKind},
    sdp::TransportType,
};
use ice::{Component, IceAgent, IceConnectionState, IceGatheringState, ReceivedPkt};
use rtp::{RtpExtensionIds, RtpPacket};
use srtp::SrtpError;
use std::{
    collections::VecDeque,
    net::{IpAddr, SocketAddr},
    time::{Duration, Instant},
};

mod dtls_srtp;
mod event;
mod packet_kind;
mod sdes_srtp;

pub use dtls_srtp::{DtlsHandshakeError, DtlsSetup, DtlsSrtpCreateError, RtpDtlsSrtpTransport};
pub use event::{RtpTransportEvent, TransportConnectionState};
pub use sdes_srtp::RtpSdesSrtpTransport;

/// A RTP transport. Manages RTP/RTCP protection, RTP extension ids and path to peer discovery (ICE)
pub struct RtpTransport {
    ports: Option<RtpTransportPorts>,
    connectivity: Connectivity,
    rtcp_mux: bool,
    extension_ids: RtpExtensionIds,
    kind: RtpTransportKind,
    connection_state: TransportConnectionState,
    events: VecDeque<RtpTransportEvent>,
}

/// How the RTP transport finds it path to its peer
#[allow(clippy::large_enum_variant)]
pub enum Connectivity {
    /// The peer's RTP/RTCP address was extracted from SDP
    Static {
        remote_rtp_address: SocketAddr,
        remote_rtcp_address: SocketAddr,
    },
    /// The connection to the transport's peer is discovered via ICE
    Ice(IceAgent),
}

/// The kind of transport thats used to protect RTP
pub enum RtpTransportKind {
    /// RTP is sent plain via UDP
    Unencrypted,
    /// RTP is sent protected as SRTP, which was setup via SDP
    SdesSrtp(RtpSdesSrtpTransport),
    /// RTP is sent protected as SRTP, which was setup via a DTLS handshake
    DtlsSrtp(RtpDtlsSrtpTransport),
}

impl RtpTransport {
    /// Create a new RTP transport. Cannot be used until [`set_ports`](Self::set_ports) has been called.
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

    /// Returns if rtcp-mux has been negotiated
    pub fn rtcp_mux(&self) -> bool {
        self.rtcp_mux
    }

    /// Must be called after one or two UDP sockets have been created for this transport.
    ///
    /// The number of sockets depends on the `rtcp-mux` parameter given in [`new`](Self::new).
    pub fn set_ports(&mut self, ports: RtpTransportPorts) {
        self.ports = Some(ports)
    }

    #[track_caller]
    pub(crate) fn require_ports(&self) -> &RtpTransportPorts {
        self.ports
            .as_ref()
            .expect("RtpTransports::require_ports called before set_ports")
    }

    /// Returns a reference to the transport's `Connectivity`
    pub fn connectivity(&self) -> &Connectivity {
        &self.connectivity
    }

    /// Returns a mutable reference to the transport's `Connectivity`
    ///
    /// Changing the variant of `Connectivity` or the ICE agent is not recommended, as it may cause some odd behavior
    /// and possibly trigger a panic.
    pub fn connectivity_mut(&mut self) -> &mut Connectivity {
        &mut self.connectivity
    }

    /// Returns a reference to the transport's `RtpTransportKind`
    pub fn kind(&self) -> &RtpTransportKind {
        &self.kind
    }

    /// Returns a mutable reference to the transport's `RtpTransportKind`
    ///
    /// Changing the variant of `RtpTransportKind` is not recommended, as it may cause some odd behavior and possibly
    /// trigger a panic.
    pub fn kind_mut(&mut self) -> &mut RtpTransportKind {
        &mut self.kind
    }

    pub(crate) fn type_(&self) -> TransportType {
        match &self.kind {
            RtpTransportKind::Unencrypted => TransportType::Rtp,
            RtpTransportKind::SdesSrtp(..) => TransportType::SdesSrtp,
            RtpTransportKind::DtlsSrtp(..) => TransportType::DtlsSrtp,
        }
    }

    /// Returns the transports' RTP extension ids. These are set in [`new`](Self::new).
    pub fn extension_ids(&self) -> RtpExtensionIds {
        self.extension_ids
    }

    /// Returns the given mtu with transport specific overhead added
    pub fn apply_overhead(&self, mtu: Mtu) -> Mtu {
        match &self.kind {
            RtpTransportKind::Unencrypted => mtu,
            RtpTransportKind::SdesSrtp(..) | RtpTransportKind::DtlsSrtp(..) => {
                mtu.with_srtp_overhead()
            }
        }
    }

    /// Returns the duration after `now` at which to poll this RTP transport again.
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

    /// Poll the transport. This function has to be called only once. Afterwards events can be processed using
    /// [`pop_event`](Self::pop_event).
    ///
    /// To find out when to poll again use [`timeout`](Self::timeout).
    pub fn poll(&mut self, now: Instant) {
        // Poll ICE
        if let Connectivity::Ice(ice_agent) = &mut self.connectivity {
            ice_agent.poll(now);

            while let Some(event) = ice_agent.pop_event() {
                if let Some(event) = ice_to_transport_event(event) {
                    self.events.push_back(event);
                }
            }

            match ice_agent.connection_state() {
                IceConnectionState::New => {}
                IceConnectionState::Checking => {}
                IceConnectionState::Connected => {}
                IceConnectionState::Failed => {
                    self.set_connection_state(TransportConnectionState::Failed);
                }
                IceConnectionState::Disconnected => {
                    // unclear if the transport state should change here, since this state may be temporary
                }
            }
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
            if let Err(e) = rtp_dtls_srtp_transport.handshake() {
                log::warn!("DTLS handshake failed: {e:?}");
            }

            if let Some(data) = rtp_dtls_srtp_transport.pop_to_send() {
                self.events.push_back(RtpTransportEvent::SendData {
                    component: Component::Rtp,
                    data,
                    source: local_rtp_addr,
                    target: remote_rtp_addr,
                });
            }
        }

        self.evaluate_transport_connection_state();
    }

    fn evaluate_transport_connection_state(&mut self) {
        match &mut self.kind {
            RtpTransportKind::Unencrypted | RtpTransportKind::SdesSrtp(..) => {
                self.set_connection_state(TransportConnectionState::Connected);
            }
            RtpTransportKind::DtlsSrtp(transport) => match transport.state_mut() {
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

    /// Returns the current transport connection state
    pub fn connection_state(&self) -> TransportConnectionState {
        self.connection_state
    }

    /// Returns the current ICE gathering state if ICE is used
    pub fn ice_gathering_state(&self) -> Option<IceGatheringState> {
        match &self.connectivity {
            Connectivity::Static { .. } => None,
            Connectivity::Ice(agent) => Some(agent.gathering_state()),
        }
    }

    /// Returns the current ICE connection state if ICE is used
    pub fn ice_connection_state(&self) -> Option<IceConnectionState> {
        match &self.connectivity {
            Connectivity::Static { .. } => None,
            Connectivity::Ice(agent) => Some(agent.connection_state()),
        }
    }

    /// Returns the next event from the internal event queue
    pub fn pop_event(&mut self) -> Option<RtpTransportEvent> {
        self.events.pop_front()
    }

    /// Hand of a received packet to the transport.
    ///
    /// May return a received and unprotected RTP or RTCP packet.
    #[must_use]
    pub fn receive(&mut self, now: Instant, mut pkt: ReceivedPkt) -> Option<RtpOrRtcp> {
        match PacketKind::identify(&pkt.data) {
            PacketKind::Rtp => {
                match &mut self.kind {
                    RtpTransportKind::Unencrypted => {}
                    RtpTransportKind::SdesSrtp(rtp_sdes_srtp_transport) => {
                        if let Err(e) = rtp_sdes_srtp_transport.inbound.unprotect_rtp(&mut pkt.data)
                        {
                            log::warn!("Failed to unprotect incoming RTP packet, {e}");
                            return None;
                        }
                    }
                    RtpTransportKind::DtlsSrtp(rtp_dtls_srtp_transport) => {
                        if let DtlsState::Connected { inbound, .. } =
                            rtp_dtls_srtp_transport.state_mut()
                        {
                            if let Err(e) = inbound.unprotect_rtp(&mut pkt.data) {
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
                            rtp_dtls_srtp_transport.state_mut()
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
                    ice_agent.receive(now, pkt);
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
                if let Err(e) = rtp_dtls_srtp_transport.handshake() {
                    log::warn!("DTLS handshake failed: {e:?}");
                }

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

    /// Try to create a [`RtpTransportWriter`].
    ///
    /// This will always return `Some` when connectivity is `Static`.
    ///
    /// Otherwise ICE needs to have a valid pair before this returns `Some`.
    ///
    /// Packets written to the writer will be turned into [`SendData`](RtpTransportEvent::SendData) events.
    pub fn writer(&mut self) -> Option<RtpTransportWriter<'_>> {
        // Check that all addresses are known
        let (local_rtp_addr, local_rtcp_addr, remote_rtp_addr, remote_rtcp_addr) =
            self.local_and_remote_addrs()?;

        Some(RtpTransportWriter {
            transport: self,
            local_rtp_addr: local_rtp_addr.map(|addr| addr.ip()),
            local_rtcp_addr: local_rtcp_addr.map(|addr| addr.ip()),
            remote_rtp_addr,
            remote_rtcp_addr,
        })
    }

    // TODO: used to detect if the transport is ready to send/receive, so naming isn't quite right
    pub(crate) fn local_and_remote_addrs(
        &self,
    ) -> Option<(
        Option<SocketAddr>,
        Option<SocketAddr>,
        SocketAddr,
        SocketAddr,
    )> {
        // Test that connectivity is setup (primarily ICE)
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

        // Underlying transport must be connected as well
        match &self.kind {
            RtpTransportKind::Unencrypted | RtpTransportKind::SdesSrtp(..) => {}
            RtpTransportKind::DtlsSrtp(dtls) => {
                if !matches!(dtls.state(), DtlsState::Connected { .. }) {
                    return None;
                }
            }
        }

        Some((
            local_rtp_addr,
            local_rtcp_addr,
            remote_rtp_addr,
            remote_rtcp_addr,
        ))
    }
}

/// Either a RTP or RTCP packet.
///
/// Returned by [`RtpTransport::receive`].
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
    /// Two separate UDP socket are used for RTP and RTCP
    pub fn new(rtp: u16, rtcp: u16) -> Self {
        Self {
            rtp,
            rtcp: Some(rtcp),
        }
    }

    /// A single UDP socket is used for both RTP and RTCP (`rtcp-mux` is set)
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

/// Temporary type which allows writing RTP and RTCP packets to a transport
pub struct RtpTransportWriter<'a> {
    transport: &'a mut RtpTransport,
    local_rtp_addr: Option<IpAddr>,
    local_rtcp_addr: Option<IpAddr>,
    remote_rtp_addr: SocketAddr,
    remote_rtcp_addr: SocketAddr,
}

impl RtpTransportWriter<'_> {
    /// Send a RTP packet using the transport
    pub fn send_rtp(&mut self, rtp_packet: RtpPacket) -> Result<(), SrtpError> {
        let mut data = rtp_packet.to_vec(self.transport.extension_ids);

        match &mut self.transport.kind {
            RtpTransportKind::Unencrypted => {}
            RtpTransportKind::SdesSrtp(rtp_sdes_srtp_transport) => {
                rtp_sdes_srtp_transport.outbound.protect_rtp(&mut data)?;
            }
            RtpTransportKind::DtlsSrtp(rtp_dtls_srtp_transport) => {
                let DtlsState::Connected { outbound, .. } = rtp_dtls_srtp_transport.state_mut()
                else {
                    unreachable!("RtpTransportWriter is only created when DtlsState is Connected");
                };

                outbound.protect_rtp(&mut data)?;
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

        Ok(())
    }

    /// Send a RTCP packet using the transport
    pub fn send_rctp(&mut self, mut rtcp_packet: Vec<u8>) -> Result<(), SrtpError> {
        match &mut self.transport.kind {
            RtpTransportKind::Unencrypted => {}
            RtpTransportKind::SdesSrtp(rtp_sdes_srtp_transport) => {
                rtp_sdes_srtp_transport
                    .outbound
                    .protect_rtcp(&mut rtcp_packet)?;
            }
            RtpTransportKind::DtlsSrtp(rtp_dtls_srtp_transport) => {
                let DtlsState::Connected { outbound, .. } = rtp_dtls_srtp_transport.state_mut()
                else {
                    unreachable!("RtpTransportWriter is only created when DtlsState is Connected");
                };

                outbound.protect_rtcp(&mut rtcp_packet)?;
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

        Ok(())
    }
}
