use std::time::Duration;

use crate::rtp_session::inbound::queue::{RtxState, jitter::Jitter, packet_loss::PacketLoss};

/// Mode in which RTP packets are handled by the inbound stream
#[derive(Debug, Clone)]
pub enum RtpInboundQueueMode {
    /// Pass all received packets to the user of the stream immediately without any delay
    ///
    /// When enabled, lost packets will still be NACKed and output out of order.
    Passthrough(RtpInboundPassthroughConfig),

    /// Reorder, deduplicate and attempt to recover missing packets using an internal queue
    SortedQueue(RtpInboundSortedQueueConfig),
}

impl Default for RtpInboundQueueMode {
    fn default() -> Self {
        Self::SortedQueue(RtpInboundSortedQueueConfig::default())
    }
}

impl RtpInboundQueueMode {
    /// Returns (initial nack delay, nack resend delay)
    pub(super) fn nack_timings(&self, rtx: Option<&RtxState>) -> (Duration, Duration) {
        match self {
            RtpInboundQueueMode::Passthrough(config) => config.nack_timings(rtx),
            RtpInboundQueueMode::SortedQueue(config) => config.nack_timings(rtx),
        }
    }
}

/// Configuration for inbound passthrough streams
#[derive(Debug, Clone)]
pub struct RtpInboundPassthroughConfig {
    /// How long to wait before NACKing a gap.
    ///
    /// Default: 5ms
    pub initial_nack_delay: Duration,

    /// How long to wait before re-sending a NACK for a gap.
    ///
    /// This value is only used as fallback, as long as no RTT has been measured.
    ///
    /// Default: 20ms
    pub default_nack_resend_delay: Duration,

    /// Max NACK attempts per missing packet.
    ///
    /// Default: 3
    pub max_nack_attempts: u32,

    /// How long a gap stays open before the packet is declared lost.
    ///
    /// Default: 200ms
    pub nack_window: Duration,
}

impl Default for RtpInboundPassthroughConfig {
    fn default() -> Self {
        RtpInboundPassthroughConfig {
            initial_nack_delay: Duration::from_millis(5),
            default_nack_resend_delay: Duration::from_millis(20),
            max_nack_attempts: 3,
            nack_window: Duration::from_millis(200),
        }
    }
}

impl RtpInboundPassthroughConfig {
    /// Returns (initial nack delay, nack resend delay)
    fn nack_timings(&self, rtx: Option<&RtxState>) -> (Duration, Duration) {
        let rtx_rtt = rtx.and_then(RtxState::rtx_rtt);
        let initial_delay = self.initial_nack_delay;
        let resend_delay = rtx_rtt
            .map(|rtx_rtt| rtx_rtt.nack_resend_delay())
            .unwrap_or(self.default_nack_resend_delay);

        (initial_delay, resend_delay)
    }
}

#[derive(Debug, Clone)]
pub struct RtpInboundSortedQueueConfig {
    /// Queue sizing mode
    ///
    /// Default: Fixed 100ms delay
    pub mode: RtpInboundStreamSortedQueueMode,

    /// How long to wait before NACKing a gap.
    ///
    /// Default: 5ms
    pub initial_nack_delay: Duration,

    /// How long to wait before re-sending a NACK for a gap.
    ///
    /// This value is only used as fallback, as long as no RTT has been measured.
    ///
    /// Default: 20ms
    pub default_nack_resend_delay: Duration,

    /// Maximum amount of NACK attempts to recover a packet
    ///
    /// Default: 3
    pub max_nack_attempts: u32,
}

impl Default for RtpInboundSortedQueueConfig {
    fn default() -> Self {
        Self {
            mode: RtpInboundStreamSortedQueueMode::Fixed(Duration::from_millis(100)),
            initial_nack_delay: Duration::from_millis(5),
            default_nack_resend_delay: Duration::from_millis(20),
            max_nack_attempts: 3,
        }
    }
}

#[derive(Debug, Clone)]
pub enum RtpInboundStreamSortedQueueMode {
    /// Keep packets for a fixed length of time
    Fixed(Duration),

    /// Keep packets for dynamic length of time, which is calculated from
    /// factors like jitter, packet loss & rtt.
    Dynamic(RtpInboundStreamDynamicConfig),
}

#[derive(Debug, Clone)]
pub struct RtpInboundStreamDynamicConfig {
    /// Minimum duration to keep packets
    ///
    /// Default: 10ms
    pub min: Duration,

    /// Maximum duration to keep packets
    ///
    /// Default: 400ms
    pub max: Duration,

    /// Target recovery percentage (between 0 and 1.0)
    ///
    /// Default: 0.99
    pub target_recovery: f32,
}

impl Default for RtpInboundStreamDynamicConfig {
    fn default() -> Self {
        Self {
            min: Duration::from_millis(10),
            max: Duration::from_millis(400),
            target_recovery: 0.99,
        }
    }
}

impl RtpInboundSortedQueueConfig {
    /// Returns (initial nack delay, nack resend delay)
    fn nack_timings(&self, rtx: Option<&RtxState>) -> (Duration, Duration) {
        let rtx_rtt = rtx.and_then(RtxState::rtx_rtt);
        let initial_delay = self.initial_nack_delay;
        let resend_delay = rtx_rtt
            .map(|rtx_rtt| rtx_rtt.nack_resend_delay())
            .unwrap_or(self.default_nack_resend_delay);

        (initial_delay, resend_delay)
    }

    /// Calculates the number of NACK attempts per packets
    pub(super) fn max_nack_attempts(
        &self,
        packet_loss: &PacketLoss,
        rtx: Option<&RtxState>,
    ) -> u32 {
        match &self.mode {
            RtpInboundStreamSortedQueueMode::Fixed(duration) => {
                let nack_resend_delay = if let Some(rtx_rtt) = rtx.and_then(RtxState::rtx_rtt) {
                    rtx_rtt.nack_resend_delay()
                } else {
                    Duration::from_millis(20)
                };

                ((duration.as_nanos() / nack_resend_delay.as_nanos()) as u32)
                    .clamp(1, self.max_nack_attempts)
            }
            RtpInboundStreamSortedQueueMode::Dynamic(config) => {
                let p = packet_loss.get().clamp(0.001, 0.99);
                let n = ((1.0 - config.target_recovery).ln() / p.ln()).ceil() as u32;

                n.clamp(1, self.max_nack_attempts)
            }
        }
    }

    /// Calculates the target delay for the inbound packet queue
    pub(super) fn target_delay(
        &self,
        jitter: &Jitter,
        packet_loss: &PacketLoss,
        rtx: Option<&RtxState>,
    ) -> Duration {
        match &self.mode {
            RtpInboundStreamSortedQueueMode::Fixed(duration) => *duration,
            RtpInboundStreamSortedQueueMode::Dynamic(config) => {
                let mut delay = Duration::from_secs_f64(jitter.get().as_secs_f64() * 2.5);

                if let Some(rtx_rtt) = rtx.and_then(RtxState::rtx_rtt) {
                    delay = delay.max(
                        rtx_rtt.nack_resend_delay() * self.max_nack_attempts(packet_loss, rtx),
                    );
                }

                delay.clamp(config.min, config.max)
            }
        }
    }
}
