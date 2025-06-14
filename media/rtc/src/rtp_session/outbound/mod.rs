use crate::opt_min;

use super::{ntp_timestamp::NtpTimestamp, report::ReportsQueue};
use queue::OutboundQueue;
use rtp::{
    RtpPacket, Ssrc,
    rtcp_types::{ReportBlock, SenderReport},
};
use std::time::{Duration, Instant};

mod queue;
mod stats;

pub use stats::{RtpOutboundRemoteStats, RtpOutboundStats};

/// RTP send stream
pub struct RtpOutboundStream {
    ssrc: Ssrc,
    queue: OutboundQueue,

    stats: RtpOutboundStats,

    report_interval: Duration,
    last_report_sent: Option<Instant>,
}

impl RtpOutboundStream {
    pub(crate) fn new(ssrc: Ssrc, clock_rate: u32, report_interval: Duration) -> Self {
        RtpOutboundStream {
            ssrc,
            queue: OutboundQueue::new(clock_rate),
            stats: RtpOutboundStats {
                bytes_sent: 0,
                packets_sent: 0,
                remote: None,
            },
            report_interval,
            last_report_sent: None,
        }
    }

    pub fn ssrc(&self) -> Ssrc {
        self.ssrc
    }

    pub(crate) fn timeout(&self, now: Instant) -> Option<Duration> {
        let queue = self.queue.timeout(now);

        let report = self
            .last_report_sent
            .and_then(|last_report_sent| {
                (last_report_sent + self.report_interval).checked_duration_since(now)
            })
            .unwrap_or_default();

        opt_min(queue, Some(report))
    }

    pub(crate) fn collect_reports(&mut self, now: Instant, reports: &mut ReportsQueue) {
        let make_report = self
            .last_report_sent
            .is_none_or(|instant| now > instant + self.report_interval);

        if !make_report {
            return;
        }

        let Some(rtp_timestamp) = self.queue.instant_to_rtp_timestamp(now) else {
            return;
        };

        let report = SenderReport::builder(self.ssrc.0)
            .ntp_timestamp(NtpTimestamp::from_instant(now).to_fixed_u64())
            .rtp_timestamp(rtp_timestamp.truncated().0)
            .packet_count(self.stats.packets_sent as u32)
            .octet_count(self.stats.bytes_sent as u32);

        reports.add_sender_report(report);
    }

    pub(crate) fn handle_report_block(&mut self, now: Instant, report_block: ReportBlock) {
        let rtt = if let Some(last_report_sent) = self.last_report_sent {
            let now = NtpTimestamp::from_instant(now);
            let lsr = NtpTimestamp::from_instant(last_report_sent);
            let dlsr = NtpTimestamp::from_fixed_u32(
                report_block.delay_since_last_sender_report_timestamp(),
            );

            let rtt = now - lsr - dlsr;

            rtt.to_std_duration()
        } else {
            None
        };

        self.stats.remote = Some(RtpOutboundRemoteStats {
            timestamp: now,
            loss: report_block.fraction_lost() as f32 / 255.0,
            jitter: Duration::from_secs_f32(
                report_block.interarrival_jitter() as f32 / self.queue.clock_rate,
            ),
            rtt,
        });
    }

    /// Queue the RTP packet to be sent.
    ///
    /// The `at` parameter specifies the time when the packet should be sent,
    /// and is used to calculate the RTP timestamp.
    ///
    /// The sequence-number, ssrc and timestamp of the packet are ignored and will be overwritten
    pub fn send_rtp(&mut self, at: Instant, mut packet: RtpPacket) {
        packet.ssrc = self.ssrc;
        self.queue.push(at, packet);
    }

    /// Check for a RTP packet that is ready to be sent
    pub(crate) fn pop(&mut self, now: Instant) -> Option<RtpPacket> {
        let packet = self.queue.pop(now)?;

        self.stats.packets_sent += 1;
        self.stats.bytes_sent += packet.payload.len() as u64;

        Some(packet)
    }

    pub fn stats(&self) -> RtpOutboundStats {
        self.stats
    }
}
