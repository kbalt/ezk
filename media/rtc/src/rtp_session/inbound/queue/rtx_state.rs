use crate::{rtp::ExtendedSequenceNumber, rtp_session::inbound::stats::RtpInboundRtxStats};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};

/// Maximum number of "lost but NACKed" packet entries to keep around for late-RTX RTT measurement
const MAX_LOST_NACKED: usize = 1024;

#[derive(Debug, Clone, Copy)]
pub(super) struct RtxRtt {
    srtt: Duration,
    variation: Duration,
}

impl RtxRtt {
    pub(super) fn from_first_sample(sample: Duration) -> Self {
        RtxRtt {
            srtt: sample,
            variation: sample / 2,
        }
    }

    pub(super) fn update(&mut self, sample: Duration) {
        let diff = self.srtt.abs_diff(sample);
        self.variation = self.variation * 3 / 4 + diff / 4;
        self.srtt = self.srtt * 7 / 8 + sample / 8;
    }

    /// NACK retransmission delay: `srtt + 1.5 * variation`.
    pub(super) fn nack_resend_delay(&self) -> Duration {
        Duration::from_secs_f64(self.srtt.as_secs_f64() + self.variation.as_secs_f64() * 1.5)
    }
}

/// Shared retransmission tracking used by both inbound stream modes.
///
/// Tracks RTX RTT (RFC 6298 inspired) and exposes RTX statistics.
pub(super) struct RtxState {
    rtt: Option<RtxRtt>,

    /// Sequence numbers that were drained as "lost" but had been NACKed exactly once,
    /// kept to allow RTT measurement when a late retransmission still arrives.
    lost_nacked_packets: VecDeque<(ExtendedSequenceNumber, Instant)>,

    // Stats
    received_in_time: u64,
    received_too_late: u64,
    received_redundant: u64,
    bytes_received: u64,
}

impl RtxState {
    pub(super) fn new() -> Self {
        RtxState {
            rtt: None,
            lost_nacked_packets: VecDeque::new(),
            received_in_time: 0,
            received_too_late: 0,
            received_redundant: 0,
            bytes_received: 0,
        }
    }

    /// Update the RTT estimate with a new sample.
    pub(super) fn update_rtt(&mut self, sample: Duration) {
        match &mut self.rtt {
            Some(rtt) => rtt.update(sample),
            None => self.rtt = Some(RtxRtt::from_first_sample(sample)),
        }
    }

    pub(super) fn rtx_rtt(&self) -> Option<&RtxRtt> {
        self.rtt.as_ref()
    }

    /// Record that a vacant slot is being given up on. If it had been NACKed exactly once,
    /// remember it so a late retransmission can still update the RTT estimate.
    pub(super) fn note_lost_nacked(
        &mut self,
        sequence_number: ExtendedSequenceNumber,
        nacked_at: Instant,
        num_nacks: u32,
    ) {
        if num_nacks != 1 {
            return;
        }

        self.lost_nacked_packets
            .push_back((sequence_number, nacked_at));

        if self.lost_nacked_packets.len() > MAX_LOST_NACKED {
            self.lost_nacked_packets.pop_front();
        }
    }

    /// Record an in-time RTX delivery (gap filled).
    pub(super) fn record_in_time(&mut self, payload_size: usize) {
        self.received_in_time += 1;
        self.bytes_received += payload_size as u64;
    }

    pub(super) fn record_redundant(&mut self) {
        self.received_redundant += 1;
    }

    /// Record a too-late RTX. If the sequence number was previously remembered as a NACKed-once
    /// loss, also use it to update the RTT estimate.
    pub(super) fn record_too_late(
        &mut self,
        sequence_number: ExtendedSequenceNumber,
        now: Instant,
    ) {
        self.received_too_late += 1;

        if let Some(index) = self
            .lost_nacked_packets
            .iter()
            .position(|(seq, _)| *seq == sequence_number)
        {
            let (_, nacked_at) = self.lost_nacked_packets.remove(index).unwrap();
            self.update_rtt(now - nacked_at);
        }
    }

    pub(super) fn stats(&self) -> RtpInboundRtxStats {
        RtpInboundRtxStats {
            packets_received_in_time: self.received_in_time,
            packets_received_too_late: self.received_too_late,
            packets_received_redundant: self.received_redundant,
            bytes_received: self.bytes_received,
            rtt: self.rtt.map(|rtt| rtt.srtt),
        }
    }
}
