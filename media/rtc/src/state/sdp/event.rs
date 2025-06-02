use std::net::{IpAddr, SocketAddr};

use crate::state::{
    sdp::{NegotiatedCodec, TransportId, local_media::LocalMediaId, media::MediaId},
    transport::TransportConnectionState,
};
use ice::{Component, IceConnectionState, IceGatheringState};
use rtp::RtpPacket;
use sdp_types::Direction;

/// New media line was added to the session
#[derive(Debug)]
pub struct MediaAdded {
    pub id: MediaId,
    pub transport_id: TransportId,
    pub local_media_id: LocalMediaId,
    pub direction: Direction,
    pub codec: NegotiatedCodec,
}

/// Existing media has changed
#[derive(Debug)]
pub struct MediaChanged {
    pub id: MediaId,
    pub old_direction: Direction,
    pub new_direction: Direction,
}

/// The gathering state of the ICE agent used by the transport changed state
///
/// This event will only trigger on transports which use an ICE agent
#[derive(Debug)]
pub struct IceGatheringStateChanged {
    pub transport_id: TransportId,
    pub old: IceGatheringState,
    pub new: IceGatheringState,
}

/// The connection state of the ICE agent used by the transport changed state
///
/// This event will only trigger on transports which use an ICE agent
#[derive(Debug)]
pub struct IceConnectionStateChanged {
    pub transport_id: TransportId,
    pub old: IceConnectionState,
    pub new: IceConnectionState,
}

/// The transport's connection state changed.
///
/// Note that not all states are reachable depending on the transport kind (RTP, SDES-RTP or DTLS-SRTP).
#[derive(Debug)]
pub struct TransportConnectionStateChanged {
    pub transport_id: TransportId,
    pub old: TransportConnectionState,
    pub new: TransportConnectionState,
}

/// Session event returned by [`SdpSession::pop_event`](crate::SdpSession::pop_event)
#[derive(Debug)]
pub enum SdpSessionEvent {
    /// See [`MediaAdded`]
    MediaAdded(MediaAdded),
    /// See [`MediaChanged`]
    MediaChanged(MediaChanged),
    /// Media was removed from the session
    MediaRemoved(MediaId),
    /// See [`IceGatheringStateChanged`]
    IceGatheringState(IceGatheringStateChanged),
    /// See [`IceConnectionStateChanged`]
    IceConnectionState(IceConnectionStateChanged),
    /// See [`TransportConnectionStateChanged`]
    TransportConnectionState(TransportConnectionStateChanged),

    /// Send data
    SendData {
        transport_id: TransportId,
        component: Component,
        data: Vec<u8>,
        /// The local IP address to use to send the data
        source: Option<IpAddr>,
        target: SocketAddr,
    },

    /// Receive RTP on a track
    ReceiveRTP {
        media_id: MediaId,
        rtp_packet: RtpPacket,
    },
}

/// Transport changes that have to be made before continuing with SDP negotiation.
/// These have to be handled before creating an SDP offer or answer.
pub enum TransportChange {
    /// The transport requests it's own UDP socket to be used
    ///
    /// The port of the socket must be reported using [`SessionState::set_transport_ports`](super::SessionState::set_transport_ports)
    CreateSocket(TransportId),
    /// Request for two UDP sockets to be created. One for RTP and RTCP each.
    /// Ideally the RTP port is an even port and the RTCP port is RTP port + 1
    ///
    /// The ports of the sockets must reported using [`SessionState::set_transport_ports`](super::SessionState::set_transport_ports)
    CreateSocketPair(TransportId),
    /// Remove the resources associated with the transport. Any pending data should still be sent.
    Remove(TransportId),
    /// Remove the RTCP socket of the given transport.
    RemoveRtcpSocket(TransportId),
}
