use crate::{
    sdp::{TransportId, local_media::LocalMediaId, media::MediaId},
    rtp_transport::TransportConnectionState,
};
use ice::{Component, IceConnectionState, IceGatheringState};
use rtp::RtpPacket;
use sdp_types::Direction;
use std::{
    borrow::Cow,
    net::{IpAddr, SocketAddr},
};

/// New media stream was added to the session
#[derive(Debug)]
pub struct MediaAdded {
    /// Internal opaque id to reference the newly added media. Used in the [`SdpSession`](super::SdpSession)'s API.
    ///
    /// May or may not reflect the `mid` of the media.
    pub id: MediaId,
    /// Opaque id of the transport used for the media
    pub transport_id: TransportId,
    /// ID of the local media-type configuration
    pub local_media_id: LocalMediaId,
    /// Local SDP direction used for the media, should be used to find out if theres a receiver or sender.
    pub direction: Direction,
    /// The negotiated codec configuration
    pub codec: NegotiatedCodec,
}

/// Part of the [`MediaAdded`] event.
///
/// Contains the send & receive Codec information of the media stream
#[derive(Debug, Clone)]
pub struct NegotiatedCodec {
    /// Payload type which must be used when sending media with this codec
    pub send_pt: u8,
    /// Payload type expected in the received RTP packets
    pub recv_pt: u8,
    /// Encoding name of the codec
    pub name: Cow<'static, str>,
    /// Clock-rate of the codec
    pub clock_rate: u32,
    /// Number of channels of the codec (usually only used for audio)
    pub channels: Option<u32>,
    /// FMTP line set in the local SDP. Sets expectations for the data that is received from the peer.
    pub send_fmtp: Option<String>,
    /// FMTP line set in the remote SDP. Should be used to configure the local encoder.
    pub recv_fmtp: Option<String>,
    /// Optional DTMF configuration if configured and then successfully negotiated.
    pub dtmf: Option<NegotiatedDtmf>,
}

/// Part of [`MediaAdded`] & [`NegotiatedCodec`]. Contains the configuration for DTMF in a media stream.
#[derive(Debug, Clone)]
pub struct NegotiatedDtmf {
    /// Payload type used for DTMF RTP packets
    pub pt: u8,
    /// FMTP line for telephone-event
    pub fmtp: Option<String>,
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

/// Session event returned by [`SdpSession::pop_event`](super::SdpSession::pop_event)
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
    /// The port of the socket must be reported using [`SdpSession::set_transport_ports`](super::SdpSession::set_transport_ports)
    CreateSocket(TransportId),
    /// Request for two UDP sockets to be created. One for RTP and RTCP each.
    /// Ideally the RTP port is an even port and the RTCP port is RTP port + 1
    ///
    /// The ports of the sockets must reported using [`SdpSession::set_transport_ports`](super::SdpSession::set_transport_ports)
    CreateSocketPair(TransportId),
    /// Remove the resources associated with the transport. Any pending data should still be sent.
    Remove(TransportId),
    /// Remove the RTCP socket of the given transport.
    RemoveRtcpSocket(TransportId),
}
