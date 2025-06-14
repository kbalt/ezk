use crate::opt_min;

use super::{ntp_timestamp::NtpTimestamp, report::ReportsQueue};
use queue::InboundQueue;
use rtp::{
    RtpPacket, Ssrc,
    rtcp_types::{ReportBlock, SenderReport},
};
use std::time::{Duration, Instant};

mod queue;
mod stats;

pub use stats::{RtpInboundRemoteStats, RtpInboundStats};

/// RTP receive stream
pub struct RtpInboundStream {
    ssrc: Ssrc,
    queue: InboundQueue,
    report_interval: Duration,
    last_report_sent: Option<(Instant, u64)>,
    last_received_sender_report: Option<NtpTimestamp>,

    remote_stats: Option<RtpInboundRemoteStats>,
}

impl RtpInboundStream {
    pub(crate) fn new(ssrc: Ssrc, clock_rate: u32, report_interval: Duration) -> Self {
        RtpInboundStream {
            ssrc,
            queue: InboundQueue::new(clock_rate),
            report_interval,
            last_report_sent: None,
            last_received_sender_report: None,
            remote_stats: None,
        }
    }

    pub(crate) fn timeout(&self, now: Instant) -> Option<Duration> {
        let queue = self.queue.timeout(now);

        let report = self
            .last_report_sent
            .and_then(|(last_report_sent, _)| {
                (last_report_sent + self.report_interval).checked_duration_since(now)
            })
            .unwrap_or_default();

        opt_min(queue, Some(report))
    }

    pub(crate) fn collect_reports(&mut self, now: Instant, reports: &mut ReportsQueue) {
        let make_report = self
            .last_report_sent
            .is_none_or(|(instant, _)| now > instant + self.report_interval);

        if !make_report {
            return;
        }

        let Some(extended_sequence_number) = self.queue.highest_sequence_number_received() else {
            return;
        };

        let (last_sr, delay) = if let Some(last_sr) = self.last_received_sender_report {
            let delay = NtpTimestamp::from_instant(now) - last_sr;
            let delay = (delay.as_seconds_f64() * 65536.0) as u32;

            let last_sr = last_sr.to_fixed_u32();

            (last_sr, delay)
        } else {
            (0, 0)
        };

        let report_block = ReportBlock::builder(self.ssrc.0)
            .fraction_lost((self.packet_loss() * 255.0) as u8)
            .cumulative_lost(self.queue.lost as u32)
            .extended_sequence_number(extended_sequence_number.0 as u32)
            .interarrival_jitter(self.queue.jitter as u32)
            .last_sender_report_timestamp(last_sr)
            .delay_since_last_sender_report_timestamp(delay);

        reports.add_report_block(report_block);

        self.last_report_sent = Some((now, self.queue.lost));
    }

    fn packet_loss(&self) -> f32 {
        let last_lost = self.last_report_sent.map(|(_, lost)| lost).unwrap_or(0);
        let lost_since_last_report = self.queue.lost - last_lost;
        lost_since_last_report as f32 / (self.queue.received + lost_since_last_report) as f32
    }

    pub(crate) fn handle_sender_report(&mut self, now: Instant, sender_report: &SenderReport) {
        self.last_received_sender_report = Some(NtpTimestamp::from_instant(now));

        self.remote_stats = Some(RtpInboundRemoteStats {
            timestamp: now,
            bytes_sent: sender_report.octet_count(),
            packets_sent: sender_report.packet_count(),
        });
    }

    /// Hand of the given RTP packet to the RTP receive stream
    ///
    /// The stream will internally keep the packet for a short time to perform reordering and deduplication.
    pub fn receive_rtp(&mut self, now: Instant, packet: RtpPacket) {
        self.queue.push(now, packet);
    }

    /// Check for a RTP packet that is ready to be received
    pub(crate) fn pop(&mut self, now: Instant) -> Option<RtpPacket> {
        self.queue.pop(now)
    }

    pub fn stats(&self) -> RtpInboundStats {
        RtpInboundStats {
            packets_received: self.queue.received,
            bytes_received: self.queue.received_bytes,
            packets_lost: self.queue.lost,
            loss: self.packet_loss(),
            jitter: Duration::from_secs_f32(self.queue.jitter / self.queue.clock_rate as f32),
            remote: self.remote_stats,
        }
    }
}
