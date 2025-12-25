use std::time::{Duration, Instant};

/// Statistics about the outbound RTP stream
#[derive(Debug, Clone, Copy)]
pub struct RtpOutboundStats {
    /// Amount RTP payload bytes sent
    pub bytes_sent: u64,

    /// Amount of RTP packets sent
    pub packets_sent: u64,

    /// Amount of RTX payload bytes sent
    pub rtx_bytes_sent: u64,

    /// Amount of RTX packets sent
    pub rtx_packets_sent: u64,

    /// Stats that are dependent on the remote sending a receiver report block
    pub remote: Option<RtpOutboundRemoteStats>,
}

/// Statistics about the outbound RTP stream which rely on the peer sending a RTCP report block in either a RTCP sender- or receiver-report)
#[derive(Debug, Clone, Copy)]
pub struct RtpOutboundRemoteStats {
    /// When these stats were calculated
    pub timestamp: Instant,

    /// Packet loss percentage ranging from 0 to 1.0
    pub loss: f32,

    /// An estimate of the statistical variance of the RTP data packet interarrival time
    pub jitter: Duration,

    /// Estimated round trip time
    pub rtt: Option<Duration>,
}
