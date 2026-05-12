use crate::rtp::ExtendedRtpTimestamp;
use std::time::{Duration, Instant};

/// Jitter samples larger than this (in seconds) are discarded as outliers
/// (e.g. pause/resume, SRTP rekeying, clock discontinuities)
const MAX_VALID_JITTER_SAMPLE: Duration = Duration::from_secs(1);

pub(crate) struct Jitter {
    clock_rate: f64,
    jitter: f64,
}

impl Jitter {
    pub(super) fn new(clock_rate: u32) -> Jitter {
        Jitter {
            clock_rate: clock_rate as f64,
            jitter: 0.0,
        }
    }

    pub(super) fn update(
        &mut self,
        now: Instant,
        timestamp: ExtendedRtpTimestamp,
        last_rtp_instant: Instant,
        last_rtp_timestamp: ExtendedRtpTimestamp,
    ) {
        if timestamp == last_rtp_timestamp {
            return;
        }

        // Rj - Ri
        let recv_delta = (now - last_rtp_instant).as_secs_f64() * self.clock_rate;

        // Sj - Si
        let rtp_ts_delta = timestamp.0 as f64 - last_rtp_timestamp.0 as f64;

        // Discard near zero delta values
        //
        // They usually come from video frames received using GRO or similar, skewing the jitter result
        if recv_delta < 1e-8 || rtp_ts_delta < 1e-8 {
            return;
        }

        // (Rj - Ri) - (Sj - Si)
        let d = (recv_delta - rtp_ts_delta).abs();

        // Discard very large jitter values which can be caused by network interruptions
        // or other unusual scenarios
        if d > MAX_VALID_JITTER_SAMPLE.as_secs_f64() * self.clock_rate {
            return;
        }

        // Trying out 1/64 to avoid shrinking too fast.
        let alpha = if d > self.jitter { 16.0 } else { 64.0 };
        self.jitter += (d - self.jitter) / alpha;
    }

    pub(crate) fn get(&self) -> Duration {
        Duration::from_secs_f64(self.jitter / self.clock_rate)
    }
}
