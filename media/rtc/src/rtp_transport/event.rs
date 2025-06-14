use std::net::{IpAddr, SocketAddr};

use ice::{Component, IceConnectionState, IceGatheringState};

/// Connection state of a transport
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportConnectionState {
    /// The transport has just been created
    New,

    /// # DTLS-SRTP
    ///
    /// DTLS is in the process of negotiating a secure connection and verifying the remote fingerprint.
    Connecting,

    /// # DTLS-SRTP
    ///
    /// DTLS has completed negotiation of a secure connection and verified the remote fingerprint.
    ///
    /// # RTP or SDES-SRTP
    ///
    /// This state is reached as soon as the SDP exchange has concluded or (if used) the ICE agent has established a connection.
    Connected,

    /// # DTLS-SRTP
    ///
    /// The transport has failed as the result of an error (such as receipt of an error alert or failure to validate the remote fingerprint).
    Failed,
}

/// Event produced by various functions in [`RtpTransport`](super::RtpTransport).
#[derive(Debug)]
pub enum RtpTransportEvent {
    /// The ICE candidate gathering state changed.
    IceGatheringState {
        old: IceGatheringState,
        new: IceGatheringState,
    },

    /// The ICE connection gathering state changed.
    IceConnectionState {
        old: IceConnectionState,
        new: IceConnectionState,
    },

    /// The RTP transport connection state changed.
    ///
    /// See [`TransportConnectionState`] for more details.
    TransportConnectionState {
        old: TransportConnectionState,
        new: TransportConnectionState,
    },

    /// The give data needs to be sent
    SendData {
        /// Which component's socket must be used to sent the data. Always [`Component::Rtp`] when `rtcp-mux` is set
        component: Component,

        /// Raw data to be sent via UDP
        data: Vec<u8>,

        /// Local source ip address from which the data should be sent
        source: Option<IpAddr>,

        /// Target destination address where the data must be sent
        target: SocketAddr,
    },
}
