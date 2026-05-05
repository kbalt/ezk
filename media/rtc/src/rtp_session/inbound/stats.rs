use std::time::{Duration, Instant};

/// Statistics about the inbound RTP stream
#[derive(Debug, Clone, Copy)]
pub struct RtpInboundStats {
    /// Total packets received & not dropped
    pub packets_received: u64,

    /// Total bytes in RTP payload received
    pub bytes_received: u64,

    /// Total lost packets (not received or dropped)
    pub packets_lost: u64,

    /// Packet loss percentage of the original stream (excluding retransmissions) ranging from 0 to 1.0
    pub loss: f32,

    /// An estimate of the statistical variance of the RTP data packet interarrival time
    pub jitter: Duration,

    /// Stats about retransmissions, None if RTX is not used
    pub rtx: Option<RtpInboundRtxStats>,

    /// Stats that are dependent on the remote sending a sender report
    pub remote: Option<RtpInboundRemoteStats>,
}

#[derive(Debug, Clone, Copy)]
pub struct RtpInboundRtxStats {
    /// Total RTX packets received in time
    pub packets_received_in_time: u64,

    /// Total RTX packets received too late
    pub packets_received_too_late: u64,

    /// Total RTX packets received redudant as the original packet was received
    pub packets_received_redundant: u64,

    /// Total RTX payload bytes received
    pub bytes_received: u64,

    /// RTT derived from time between nacking a packet and receiving a retransmission for it
    pub rtt: Option<Duration>,
}

/// Statistics about the inbound RTP stream which rely on the peer sending a RTCP sender report
#[derive(Debug, Clone, Copy)]
pub struct RtpInboundRemoteStats {
    /// When these stats were calculated
    pub timestamp: Instant,

    /// Amount RTP payload bytes sent
    pub bytes_sent: u32,

    /// Amount of RTP packets sent
    pub packets_sent: u32,
}
