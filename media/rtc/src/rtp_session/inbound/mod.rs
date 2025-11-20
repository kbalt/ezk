use crate::opt_min;

use super::{ntp_timestamp::NtpTimestamp, report::ReportsQueue};
use queue::InboundQueue;
use rtp::{
    RtpPacket, Ssrc,
    rtcp_types::{Fir, PayloadFeedback, Pli, ReportBlock, SenderReport},
};
use std::time::{Duration, Instant};

mod queue;
mod stats;

pub use stats::{RtpInboundRemoteStats, RtpInboundStats};

/// Minimum interval in which FIR/PLI requests can be sent
const RTCP_FEEDBACK_COOLDOWN: Duration = Duration::from_millis(500);

/// RTP receive stream
pub struct RtpInboundStream {
    ssrc: Ssrc,
    queue: InboundQueue,
    report_interval: Duration,
    last_report_sent: Option<(Instant, u64)>,
    last_received_sender_report: Option<NtpTimestamp>,

    remote_stats: Option<RtpInboundRemoteStats>,

    emit_nack: bool,

    // RTCP feedback NACK PLI
    want_nack_pli: bool,
    last_nack_pli: Option<Instant>,

    // RTCP feedback CCM FIR
    want_ccm_fir: bool,
    next_fir_seq: u8,
    last_ccm_fir: Option<Instant>,
}

impl RtpInboundStream {
    pub(crate) fn new(
        pt: u8,
        ssrc: Ssrc,
        clock_rate: u32,
        report_interval: Duration,
        emit_nack: bool,
    ) -> Self {
        RtpInboundStream {
            ssrc,
            queue: InboundQueue::new(pt, ssrc, clock_rate),
            report_interval,
            last_report_sent: None,
            last_received_sender_report: None,
            remote_stats: None,

            emit_nack,
            want_nack_pli: false,

            last_nack_pli: None,
            want_ccm_fir: false,
            next_fir_seq: rand::random(),
            last_ccm_fir: None,
        }
    }

    pub fn request_nack_pli(&mut self) {
        self.want_nack_pli = true
    }

    pub fn request_ccm_fir(&mut self) {
        self.want_ccm_fir = true
    }

    pub(crate) fn timeout(&self, now: Instant) -> Option<Duration> {
        let mut timeout = self.queue.timeout_receive(now);

        if self.emit_nack {
            timeout = opt_min(timeout, self.queue.timeout_nack(now));
        }

        let report = if self.queue.highest_sequence_number_received().is_some() {
            let report_interval = self
                .last_report_sent
                .and_then(|(last_report_sent, _)| {
                    (last_report_sent + self.report_interval).checked_duration_since(now)
                })
                .unwrap_or_default();

            let nack_pli = self
                .last_nack_pli
                .map(|ts| (ts + RTCP_FEEDBACK_COOLDOWN).saturating_duration_since(now))
                .filter(|_| self.want_nack_pli);

            let ccm_fir = self
                .last_ccm_fir
                .map(|ts| (ts + RTCP_FEEDBACK_COOLDOWN).saturating_duration_since(now))
                .filter(|_| self.want_ccm_fir);

            opt_min(Some(report_interval), opt_min(nack_pli, ccm_fir))
        } else {
            None
        };

        opt_min(timeout, report)
    }

    pub(super) fn collect_reports(
        &mut self,
        now: Instant,
        fallback_sender_ssrc: Ssrc,
        reports: &mut ReportsQueue,
    ) {
        if self.emit_nack
            && let Some(nack) = self.queue.poll_nack(now)
        {
            reports.add_payload_feedback(
                PayloadFeedback::builder_owned(nack)
                    .media_ssrc(self.ssrc.0)
                    .sender_ssrc(fallback_sender_ssrc.0),
            );
        }

        if self.want_nack_pli {
            let cooldown_elapsed = self
                .last_nack_pli
                .is_none_or(|i| i + RTCP_FEEDBACK_COOLDOWN <= now);

            if cooldown_elapsed {
                self.want_nack_pli = false;
                self.last_nack_pli = Some(now);
                reports.add_payload_feedback(
                    PayloadFeedback::builder_owned(Pli::builder())
                        .media_ssrc(self.ssrc.0)
                        .sender_ssrc(fallback_sender_ssrc.0),
                );
            }
        }

        if self.want_ccm_fir {
            let cooldown_elapsed = self
                .last_ccm_fir
                .is_none_or(|i| i + RTCP_FEEDBACK_COOLDOWN <= now);

            if cooldown_elapsed {
                self.want_ccm_fir = false;
                self.last_ccm_fir = Some(now);

                reports.add_payload_feedback(
                    PayloadFeedback::builder_owned(
                        Fir::builder().add_ssrc(self.ssrc.0, self.next_fir_seq),
                    )
                    .sender_ssrc(fallback_sender_ssrc.0),
                );

                self.next_fir_seq = self.next_fir_seq.wrapping_add(1);
            }
        }

        // When emitting feedback packets & reduced size RTCP is not supported:
        // Emit a receiver report so the ReportsQueue can generate a valid RTCP packet
        let receiver_report_for_feedback = reports.has_feedback() && !reports.rtcp_rsize();

        let report_interval_elapsed = self
            .last_report_sent
            .is_none_or(|(instant, _)| now > instant + self.report_interval);

        let make_report = receiver_report_for_feedback || report_interval_elapsed;

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

    /// Hand the given RTP packet to the RTP receive stream
    ///
    /// The stream will internally keep the packet for a short time to perform reordering and deduplication.
    pub fn receive_rtp(&mut self, now: Instant, packet: RtpPacket) {
        self.queue.push(now, packet);
    }

    /// Hand off a RTX (retransmission) rtp packet to the RTP receive stream
    pub fn receive_rtx(&mut self, packet: RtpPacket) {
        self.queue.push_rtx(packet)
    }

    /// Check for a RTP packet that is ready to be received
    pub(crate) fn poll(&mut self, now: Instant) -> Option<RtpInboundStreamEvent> {
        let (rtp_packet, received_at) = self.queue.poll(now)?;

        Some(RtpInboundStreamEvent::ReceiveRtpPacket {
            received_at,
            rtp_packet,
        })
    }

    pub fn stats(&self) -> RtpInboundStats {
        RtpInboundStats {
            packets_received: self.queue.received,
            bytes_received: self.queue.received_bytes,
            packets_lost: self.queue.lost,
            loss: self.packet_loss(),
            jitter: Duration::from_secs_f64(self.queue.jitter / self.queue.clock_rate as f64),
            remote: self.remote_stats,
        }
    }
}

pub enum RtpInboundStreamEvent {
    ReceiveRtpPacket {
        received_at: Option<Instant>,
        rtp_packet: RtpPacket,
    },
}
