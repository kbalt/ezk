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

#[derive(Debug)]
pub enum RtpTransportEvent {
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
