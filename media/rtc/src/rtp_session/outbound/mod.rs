use super::{ntp_timestamp::NtpTimestamp, report::ReportsQueue};
use crate::opt_min;
use bytes::Bytes;
use queue::OutboundQueue;
use rtp::{
    RtpExtensions, RtpPacket, Ssrc,
    rtcp_types::{ReportBlock, SenderReport},
};
use std::time::{Duration, Instant};

mod queue;
mod stats;

pub use stats::{RtpOutboundRemoteStats, RtpOutboundStats};

/// RTP send stream
pub struct RtpOutboundStream {
    queue: OutboundQueue,

    stats: RtpOutboundStats,

    report_interval: Duration,
    last_report_sent: Option<Instant>,
}

impl RtpOutboundStream {
    pub(crate) fn new(
        ssrc: Ssrc,
        clock_rate: u32,
        report_interval: Duration,
        rtx: Option<(u8, Ssrc)>,
    ) -> Self {
        RtpOutboundStream {
            queue: OutboundQueue::new(ssrc, clock_rate, rtx),
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
        self.queue.ssrc
    }

    pub(crate) fn timeout(&self, now: Instant) -> Option<Duration> {
        let queue = self.queue.timeout(now);

        let report = if self.queue.has_received() {
            Some(
                self.last_report_sent
                    .and_then(|last_report_sent| {
                        (last_report_sent + self.report_interval).checked_duration_since(now)
                    })
                    .unwrap_or_default(),
            )
        } else {
            None
        };

        opt_min(queue, report)
    }

    pub(super) fn collect_reports(&mut self, now: Instant, reports: &mut ReportsQueue) {
        let make_report = self
            .last_report_sent
            .is_none_or(|instant| now > instant + self.report_interval);

        if !make_report {
            return;
        }

        let Some(rtp_timestamp) = self.queue.instant_to_rtp_timestamp(now) else {
            return;
        };

        let report = SenderReport::builder(self.queue.ssrc.0)
            .ntp_timestamp(NtpTimestamp::from_instant(now).to_fixed_u64())
            .rtp_timestamp(rtp_timestamp.truncated().0)
            .packet_count(self.stats.packets_sent as u32)
            .octet_count(self.stats.bytes_sent as u32);

        reports.add_sender_report(report);

        self.last_report_sent = Some(now);
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

    pub(crate) fn handle_nack(&mut self, entries: impl Iterator<Item = u16>) {
        self.queue.handle_nack(entries);
    }

    /// Queue the RTP packet to be sent.
    pub fn send_rtp(&mut self, packet: SendRtpPacket) {
        self.queue.push(packet);
    }

    /// Check for a RTP packet that is ready to be sent
    pub(crate) fn poll(&mut self, now: Instant) -> Option<RtpOutboundStreamEvent> {
        match self.queue.poll(now)? {
            RtpOutboundStreamEvent::SendRtpPacket { rtp_packet, is_rtx } => {
                if !is_rtx {
                    self.stats.packets_sent += 1;
                    self.stats.bytes_sent += rtp_packet.payload.len() as u64;
                }

                Some(RtpOutboundStreamEvent::SendRtpPacket { rtp_packet, is_rtx })
            }
        }
    }

    pub fn stats(&self) -> RtpOutboundStats {
        self.stats
    }
}

#[derive(Debug)]
pub enum RtpOutboundStreamEvent {
    SendRtpPacket { rtp_packet: RtpPacket, is_rtx: bool },
}

/// Outbound RTP packet builder
pub struct SendRtpPacket {
    send_at: Instant,
    media_time: Instant,
    pt: u8,
    marker: bool,
    extensions: RtpExtensions,
    payload: Bytes,
}

impl SendRtpPacket {
    /// Create a RTP packet to be sent
    ///
    /// `media_time` will be used to calculate the packet's timestamp.
    ///
    /// To delay sending the packet use [`SendRtpPacket::send_at`].
    pub fn new(media_time: Instant, pt: u8, payload: Bytes) -> Self {
        Self {
            send_at: media_time,
            media_time,
            pt,
            marker: false,
            extensions: RtpExtensions::default(),
            payload,
        }
    }

    /// Set all extension values for this RTP packet
    pub fn with_extensions(self, extensions: RtpExtensions) -> Self {
        Self { extensions, ..self }
    }

    /// Set a timestamp at which the packet should be sent
    ///
    /// If the timestamp is in the past, the packet will be sent instantly.
    pub fn send_at(self, at: Instant) -> Self {
        Self {
            send_at: at,
            ..self
        }
    }

    /// Set the marker bit of the RTP header
    pub fn marker(self, marker: bool) -> Self {
        Self { marker, ..self }
    }
}
