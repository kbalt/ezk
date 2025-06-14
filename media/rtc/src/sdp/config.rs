use crate::Mtu;
use sdp_types::TransportProtocol;

#[derive(Debug, Default, Clone)]
pub struct SdpSessionConfig {
    /// The default transport to offer the peer
    pub offer_transport: TransportType,
    /// Use ICE when making an offer
    pub offer_ice: bool,
    /// Offer the extended RTP profile for RTCP-based feedback
    pub offer_avpf: bool,
    /// Policy when negotiating RTP & RTCP multiplexing over the same UDP socket
    pub rtcp_mux_policy: RtcpMuxPolicy,
    /// Policy to use when offering bundled media over a single transport
    pub bundle_policy: BundlePolicy,
    /// Maximum allowed UDP payload size
    pub mtu: Mtu,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TransportType {
    /// Unprotected "raw" RTP packets
    Rtp,
    /// SRTP using key exchange over the signaling protocol (SDP)
    SdesSrtp,
    /// SRTP using key exchange over DTLS
    #[default]
    DtlsSrtp,
}

impl TransportType {
    pub(crate) fn sdp_type(&self, use_avpf: bool) -> TransportProtocol {
        if use_avpf {
            match self {
                Self::Rtp => TransportProtocol::RtpAvpf,
                Self::SdesSrtp => TransportProtocol::RtpSavpf,
                Self::DtlsSrtp => TransportProtocol::UdpTlsRtpSavpf,
            }
        } else {
            match self {
                Self::Rtp => TransportProtocol::RtpAvp,
                Self::SdesSrtp => TransportProtocol::RtpSavp,
                Self::DtlsSrtp => TransportProtocol::UdpTlsRtpSavp,
            }
        }
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum RtcpMuxPolicy {
    /// Offer multiplexing RTCP on the RTP port,
    /// but offer a separate port if the peer doesn't support it.
    #[default]
    Negotiate,
    /// Require RTCP muxing, fail if the peer doesn't support it.
    Require,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum BundlePolicy {
    /// Offer media bundling, but have a fallback transport ready if the peer does not support bundling
    #[default]
    MaxCompat,
    /// Require the media to be bundled over a single transport. Fail if the peer does not support bundling.
    MaxBundle,
}
