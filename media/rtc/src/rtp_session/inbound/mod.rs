use super::{ntp_timestamp::NtpTimestamp, report::ReportsQueue};
use crate::{
    opt_min,
    rtp::{RtpPacket, RtpTimestamp, Ssrc},
};
use queue::InboundQueue;
use rtcp_types::{Fir, PayloadFeedback, Pli, ReportBlock, SenderReport, TransportFeedback};
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
    media_time_ref: Option<MediaTimeRef>,

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

/// Reference NTP timestamp & RTP timestamp used to create a media time for incoming packets
struct MediaTimeRef {
    /// The first few packets, before a SR with a NTP timestamp is received, will have a guesstimated `media_time`
    ///
    /// RTP & NTP timestamp are taken from the first RTP packet instead. (where the NTP packet is the received timestamp)
    is_sender_report: bool,
    rtp_timestamp: RtpTimestamp,
    ntp_timestamp: NtpTimestamp,
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
            media_time_ref: None,
            remote_stats: None,

            emit_nack,
            want_nack_pli: false,

            last_nack_pli: None,
            want_ccm_fir: false,
            next_fir_seq: rand::random(),
            last_ccm_fir: None,
        }
    }

    pub fn ssrc(&self) -> Ssrc {
        self.ssrc
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
            reports.add_transport_feedback(
                TransportFeedback::builder_owned(nack)
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

        let (last_sr, delay) = if let Some(sr) = &self.media_time_ref
            && sr.is_sender_report
        {
            let delay = NtpTimestamp::from_instant(now) - sr.ntp_timestamp;
            let delay = (delay.as_seconds_f64() * 65536.0) as u32;

            let last_sr = sr.ntp_timestamp.to_fixed_u32();

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
        self.media_time_ref = Some(MediaTimeRef {
            is_sender_report: true,
            rtp_timestamp: RtpTimestamp(sender_report.rtp_timestamp()),
            ntp_timestamp: NtpTimestamp::from_fixed_u64(sender_report.ntp_timestamp()),
        });

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
        let mut packets = smallvec::SmallVec::new();

        while let Some((rtp_packet, received_at)) = self.queue.poll(now) {
            let media_time_ref = self.media_time_ref.get_or_insert_with(|| MediaTimeRef {
                is_sender_report: false,
                rtp_timestamp: rtp_packet.timestamp,
                ntp_timestamp: NtpTimestamp::from_instant(
                    received_at.expect("first rtp packet MUST have received_at as Some"),
                ),
            });

            let diff = rtp_packet
                .timestamp
                .0
                .wrapping_sub(media_time_ref.rtp_timestamp.0)
                .cast_signed();

            let secs_diff = diff as f64 / self.queue.clock_rate as f64;
            let media_time =
                media_time_ref.ntp_timestamp.to_instant() + time::Duration::seconds_f64(secs_diff);

            packets.push(RtpInboundPacket {
                received_at,
                media_time,
                rtp_packet,
            });
        }

        if packets.is_empty() {
            return None;
        }

        Some(RtpInboundStreamEvent::ReceiveRtpPackets(packets))
    }

    pub fn stats(&self) -> RtpInboundStats {
        RtpInboundStats {
            packets_received: self.queue.received,
            bytes_received: self.queue.received_bytes,
            rtx_packets_received_in_time: self.queue.rtx_received_in_time,
            rtx_packets_received_too_late: self.queue.rtx_received_too_late,
            rtx_packets_received_redundant: self.queue.rtx_received_redundant,
            rtx_bytes_received: self.queue.rtx_bytes_received,
            packets_lost: self.queue.lost,
            loss: self.packet_loss(),
            jitter: Duration::from_secs_f64(self.queue.jitter / self.queue.clock_rate as f64),
            remote: self.remote_stats,
        }
    }
}

pub enum RtpInboundStreamEvent {
    ReceiveRtpPackets(smallvec::SmallVec<[RtpInboundPacket; 1]>),
}

#[derive(Debug)]
pub struct RtpInboundPacket {
    /// Timestamp at which the packet was received, none if the packet was a retransmission
    pub received_at: Option<Instant>,
    /// Media time derived from RTCP SR reports and their NTP timestamp
    ///
    /// Must only be compared to other `media_time` instants.
    pub media_time: Instant,
    pub rtp_packet: RtpPacket,
}
