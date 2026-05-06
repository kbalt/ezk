use crate::{
    rtp::{ExtendedRtpTimestamp, ExtendedSequenceNumber, RtpPacket, SequenceNumber, Ssrc},
    rtp_session::inbound::{
        queue::{
            config::RtpInboundQueueMode, jitter::Jitter, packet_gaps::PacketGaps,
            packet_loss::PacketLoss, rtx_state::RtxState,
        },
        stats::RtpInboundRtxStats,
    },
};
use rtcp_types::NackBuilder;
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};
use time::ext::InstantExt as _;

pub(super) mod config;
mod jitter;
mod packet_gaps;
mod packet_loss;
mod rtx_state;

/// Maximum number of received entries to keep in buffer to avoid excessive memory usage
const MAX_ENTRIES: usize = 1024;

/// Dynamically sized inbound buffer.
///
/// Resizes on every received packet based on current jitter and
/// round trip time derived from RTX retransmissions (when enabled).
pub(crate) struct Queue {
    config: RtpInboundQueueMode,

    /// Payload type of the "main" media received over this ssrc
    ///
    /// Used to reassign the payload type of retransmitted packets back to the media type
    pub(crate) pt: u8,

    /// SSRC of the receiving RTP stream
    pub(crate) ssrc: Ssrc,

    /// Clock rate of the media received, used convert the RTP timestamp to wall time
    pub(crate) clock_rate: u32,

    /// Sorted (by sequence number) queue of received packets
    queue: VecDeque<QueueEntry>,

    /// Tracks missing sequence numbers and their NACK state.
    gaps: PacketGaps,

    /// Track the last received RTP packet
    last_rtp_received: Option<(Instant, ExtendedRtpTimestamp, ExtendedSequenceNumber)>,
    /// Track the latest sequence number returned via [`SortedQueue::poll`], to drop late packets
    last_sequence_number_returned: Option<ExtendedSequenceNumber>,

    rtx: Option<RtxState>,

    /// num packets dropped due to being duplicate, too late or the receiver falling behind
    pub(crate) dropped: u64,
    pub(crate) received: u64,
    pub(crate) received_bytes: u64,

    /// packets that were never received
    pub(crate) lost: u64,
    pub(crate) jitter: Jitter,
    pub(crate) packet_loss: PacketLoss,
}

struct QueueEntry {
    /// Instant the packet was received. None if it was a retransmission to keep it out of RTP statistics.
    received_at: Option<Instant>,
    timestamp: ExtendedRtpTimestamp,
    sequence_number: ExtendedSequenceNumber,
    packet: RtpPacket,
}

impl Queue {
    pub(crate) fn new(
        config: RtpInboundQueueMode,
        pt: u8,
        ssrc: Ssrc,
        clock_rate: u32,
        has_rtx: bool,
    ) -> Self {
        Queue {
            config,
            pt,
            ssrc,
            clock_rate,
            queue: VecDeque::new(),
            gaps: PacketGaps::new(),
            last_rtp_received: None,
            last_sequence_number_returned: None,
            rtx: has_rtx.then(RtxState::new),
            dropped: 0,
            received: 0,
            received_bytes: 0,
            lost: 0,
            jitter: Jitter::new(clock_rate),
            packet_loss: PacketLoss::default(),
        }
    }

    pub(crate) fn highest_sequence_number_received(&self) -> Option<ExtendedSequenceNumber> {
        let (_, _, seq) = self.last_rtp_received?;
        Some(seq)
    }

    pub(crate) fn push(&mut self, now: Instant, packet: RtpPacket) {
        let payload_size = packet.payload.len();

        // Update jitter and find extended timestamp & sequence number
        let (timestamp, sequence_number) = match self.last_rtp_received {
            Some((last_rtp_instant, last_rtp_timestamp, last_sequence_number)) => {
                let timestamp = last_rtp_timestamp.guess_extended(packet.timestamp);
                let sequence_number = last_sequence_number.guess_extended(packet.sequence_number);

                self.jitter
                    .update(now, timestamp, last_rtp_instant, last_rtp_timestamp);

                (timestamp, sequence_number)
            }
            None => (
                ExtendedRtpTimestamp(u64::from(packet.timestamp.0)),
                ExtendedSequenceNumber(packet.sequence_number.0.into()),
            ),
        };

        // Decide whether the packet should be added to the queue.
        let add = match &self.config {
            RtpInboundQueueMode::Passthrough(..) => {
                match self.last_rtp_received {
                    Some((_, _, last_seq)) if sequence_number <= last_seq => {
                        // Late packet: only add if it fills a known gap.
                        self.gaps.contains(sequence_number)
                    }
                    _ => true,
                }
            }
            RtpInboundQueueMode::SortedQueue(..) => {
                if let Some(last_returned) = self.last_sequence_number_returned
                    && sequence_number <= last_returned
                {
                    // Packet too late
                    false
                } else if let Some((_, _, last_seq)) = self.last_rtp_received {
                    if sequence_number > last_seq {
                        // New high sequence number: always add
                        true
                    } else {
                        // Late packet: add only if it fills a known gap
                        self.gaps.contains(sequence_number)
                    }
                } else {
                    // First packet
                    true
                }
            }
        };

        if !add {
            self.dropped += 1;
            return;
        }

        // Update tracking state for forward progress only
        if self
            .last_rtp_received
            .is_none_or(|(_, _, last_seq)| sequence_number > last_seq)
        {
            self.last_rtp_received = Some((now, timestamp, sequence_number));
        }

        self.gaps.report_received(sequence_number, now);

        self.insert_sorted(QueueEntry {
            received_at: Some(now),
            timestamp,
            sequence_number,
            packet,
        });

        self.received += 1;
        self.received_bytes += payload_size as u64;
        self.packet_loss.record_received();

        if self.queue.len() > MAX_ENTRIES {
            let dropped = self.queue.pop_front().expect("queue is non-empty");

            self.last_sequence_number_returned = Some(dropped.sequence_number);
            self.gaps.drain_below(dropped.sequence_number, |_, _| {});

            self.dropped += 1;
        }
    }

    fn insert_sorted(&mut self, entry: QueueEntry) {
        let pos = self
            .queue
            .partition_point(|e| e.sequence_number < entry.sequence_number);
        self.queue.insert(pos, entry);
    }

    pub(crate) fn push_rtx(&mut self, now: Instant, rtp_packet: RtpPacket) {
        let Some(rtx) = self.rtx.as_mut() else {
            log::warn!("Got RTX packet on non-rtx inbound-queue");
            return;
        };

        let Some((_, last_rtp_received_timestamp, last_rtp_received_sequence_number)) =
            self.last_rtp_received
        else {
            log::warn!("Got rtx rtp packet before any other packets");
            return;
        };

        let [b0, b1, original_payload @ ..] = &rtp_packet.payload[..] else {
            log::warn!("Got rtx rtp packet with invalid payload");
            return;
        };

        let original_seq_short = SequenceNumber(u16::from_be_bytes([*b0, *b1]));

        let recovered = RtpPacket {
            pt: self.pt,
            sequence_number: original_seq_short,
            ssrc: self.ssrc,
            timestamp: rtp_packet.timestamp,
            marker: rtp_packet.marker,
            extensions: rtp_packet.extensions,
            payload: rtp_packet.payload.slice_ref(original_payload),
        };

        let sequence_number = last_rtp_received_sequence_number.guess_extended(original_seq_short);
        let timestamp = last_rtp_received_timestamp.guess_extended(recovered.timestamp);

        let (gap_exists, rtx_rtt) = self.gaps.report_rtx_received(sequence_number, now);

        if let Some(rtx_rtt) = rtx_rtt {
            rtx.update_rtt(rtx_rtt);
        }

        if gap_exists {
            let payload_size = recovered.payload.len();
            rtx.record_in_time(payload_size);

            self.insert_sorted(QueueEntry {
                received_at: None,
                timestamp,
                sequence_number,
                packet: recovered,
            });
        } else {
            rtx.record_too_late(sequence_number, now);
            rtx.record_redundant();
        }
    }

    /// Returns a list of sequence numbers to NACK
    pub(crate) fn poll_nack(&mut self, now: Instant) -> Option<NackBuilder> {
        // TODO: this is a hack to drain lost packets, but `nack_window` should be used as well
        if let RtpInboundQueueMode::Passthrough(config) = &self.config {
            let drained = self.gaps.drain_lost(config.max_nack_attempts);
            if drained > 0 {
                self.lost += drained;
                self.packet_loss.record_lost(drained);
            }
        };

        let (initial_delay, resend_delay) = self.config.nack_timings(self.rtx.as_ref());

        self.gaps.poll_nacks(now, initial_delay, resend_delay)
    }

    pub(crate) fn poll(&mut self, now: Instant) -> Option<(RtpPacket, Option<Instant>, Duration)> {
        match &self.config {
            RtpInboundQueueMode::Passthrough(config) => {
                let drained = self.gaps.drain_lost(config.max_nack_attempts);
                self.lost += drained;
                self.packet_loss.record_lost(drained);

                let entry = self.queue.pop_front()?;
                self.last_sequence_number_returned = Some(entry.sequence_number);
                Some((entry.packet, entry.received_at, Duration::ZERO))
            }
            RtpInboundQueueMode::SortedQueue(config) => {
                let (last_rtp_received_instant, last_rtp_received_timestamp, _) =
                    self.last_rtp_received?;

                let queue_size =
                    config.target_delay(&self.jitter, &self.packet_loss, self.rtx.as_ref());

                let pop_earliest = now - queue_size;

                // Calculate the maximum RTP timestamp which can be removed from the queue
                let max_timestamp = map_instant_to_rtp_timestamp(
                    last_rtp_received_instant,
                    last_rtp_received_timestamp,
                    self.clock_rate,
                    pop_earliest,
                )?;

                // Front of the queue is always the oldest received packet (queue is sorted).
                let entry = self.queue.front()?;

                // Test the timestamp of the entry against the maximum timestamp and return if it is not old enough
                if entry.timestamp.0 > max_timestamp.0 {
                    return None;
                }

                let entry_seq = entry.sequence_number;

                // Remove all gaps before this packets
                let rtx = &mut self.rtx;
                let lost = self.gaps.drain_below(entry_seq, |seq, nacked_at| {
                    if let Some(rtx) = rtx.as_mut()
                        && let Some((nacked_at, num_nacks)) = nacked_at
                    {
                        rtx.note_lost_nacked(seq, nacked_at, num_nacks);
                    }
                });

                self.lost += lost;
                self.packet_loss.record_lost(lost);

                let entry = self.queue.pop_front().expect("front exists");
                self.last_sequence_number_returned = Some(entry.sequence_number);
                Some((entry.packet, entry.received_at, queue_size))
            }
        }
    }

    pub(crate) fn timeout_receive(&self, now: Instant) -> Option<Duration> {
        match &self.config {
            RtpInboundQueueMode::Passthrough(_config) => {
                if self.queue.is_empty() {
                    None
                } else {
                    Some(Duration::ZERO)
                }
            }
            RtpInboundQueueMode::SortedQueue(config) => {
                let (last_rtp_received_instant, last_rtp_received_timestamp, _) =
                    self.last_rtp_received?;
                let earliest_timestamp = self.queue.front()?.timestamp;

                let delta = last_rtp_received_timestamp.0 as f64 - earliest_timestamp.0 as f64;
                let delta = Duration::from_secs_f64(delta.max(0.0) / self.clock_rate as f64);

                let queue_size =
                    config.target_delay(&self.jitter, &self.packet_loss, self.rtx.as_ref());
                let instant = (last_rtp_received_instant - delta) + queue_size;

                Some(
                    instant
                        .checked_duration_since(now)
                        .unwrap_or(Duration::ZERO),
                )
            }
        }
    }

    pub(crate) fn timeout_nack(&self, now: Instant) -> Option<Duration> {
        let (initial_delay, resend_delay) = self.config.nack_timings(self.rtx.as_ref());
        self.gaps.timeout_nacks(now, initial_delay, resend_delay)
    }

    pub(crate) fn rtx_stats(&self) -> Option<RtpInboundRtxStats> {
        self.rtx.as_ref().map(RtxState::stats)
    }
}

fn map_instant_to_rtp_timestamp(
    reference_instant: Instant,
    reference_timestamp: ExtendedRtpTimestamp,
    clock_rate: u32,
    instant: Instant,
) -> Option<ExtendedRtpTimestamp> {
    let delta = instant.signed_duration_since(reference_instant);
    let delta_in_rtp_timesteps = (delta.as_seconds_f64() * clock_rate as f64) as i64;

    u64::try_from(reference_timestamp.0 as i64 + delta_in_rtp_timesteps)
        .ok()
        .map(ExtendedRtpTimestamp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        rtp::{RtpExtensions, RtpTimestamp, SequenceNumber, Ssrc},
        rtp_session::RtpInboundSortedQueueConfig,
    };
    use bytes::Bytes;

    fn make_packet(seq: u16, ts: u32) -> RtpPacket {
        RtpPacket {
            pt: 0,
            sequence_number: SequenceNumber(seq),
            ssrc: Ssrc(0),
            timestamp: RtpTimestamp(ts),
            marker: false,
            extensions: RtpExtensions::default(),
            payload: Bytes::new(),
        }
    }

    fn make_queue() -> Queue {
        Queue::new(
            RtpInboundQueueMode::SortedQueue(RtpInboundSortedQueueConfig::default()),
            0,
            Ssrc(0),
            1000,
            false,
        )
    }

    #[test]
    fn test_map_instant_to_rtp_timestamp() {
        let reference_instant = Instant::now();
        let reference_timestamp = ExtendedRtpTimestamp(1000);
        let clock_rate = 1000;

        assert_eq!(
            map_instant_to_rtp_timestamp(
                reference_instant,
                reference_timestamp,
                clock_rate,
                reference_instant + Duration::from_millis(1000)
            ),
            Some(ExtendedRtpTimestamp(2000))
        );

        assert_eq!(
            map_instant_to_rtp_timestamp(
                reference_instant,
                reference_timestamp,
                clock_rate,
                reference_instant - Duration::from_millis(1000)
            ),
            Some(ExtendedRtpTimestamp(0))
        );

        assert_eq!(
            map_instant_to_rtp_timestamp(
                reference_instant,
                reference_timestamp,
                clock_rate,
                reference_instant - Duration::from_millis(2000)
            ),
            None,
        );
    }

    #[test]
    fn it_reorders() {
        let mut jb = make_queue();
        let queue_size = RtpInboundSortedQueueConfig::default().target_delay(
            &jb.jitter,
            &jb.packet_loss,
            jb.rtx.as_ref(),
        );

        let now = Instant::now();

        jb.push(now + Duration::from_millis(100), make_packet(1, 100));
        assert_eq!(jb.queue.len(), 1);
        jb.push(now + Duration::from_millis(400), make_packet(4, 400));
        assert_eq!(jb.queue.len(), 2);

        jb.push(now + Duration::from_millis(300), make_packet(3, 300));
        assert_eq!(jb.queue.len(), 3);

        assert!(
            jb.poll(now + Duration::from_millis(100) + queue_size / 2)
                .is_none()
        );
        assert_eq!(
            jb.poll(now + Duration::from_millis(100) + queue_size)
                .unwrap()
                .0
                .sequence_number
                .0,
            1
        );
        assert_eq!(
            jb.poll(now + Duration::from_millis(300) + queue_size)
                .unwrap()
                .0
                .sequence_number
                .0,
            3
        );
        assert_eq!(
            jb.poll(now + Duration::from_millis(400) + queue_size)
                .unwrap()
                .0
                .sequence_number
                .0,
            4
        );
        assert_eq!(jb.lost, 1)
    }

    #[test]
    fn sequence_rollover() {
        let mut jb = make_queue();
        let queue_size = RtpInboundSortedQueueConfig::default().target_delay(
            &jb.jitter,
            &jb.packet_loss,
            jb.rtx.as_ref(),
        );

        let now = Instant::now();

        const BASE_SEQ: u16 = 65530;

        for i in 0..10 {
            jb.push(
                now + Duration::from_millis(i * 10),
                make_packet(BASE_SEQ.wrapping_add(i as u16), (i * 10) as u32),
            );
        }

        assert_eq!(jb.queue.len(), 10);

        for i in 0..10 {
            let packet = jb
                .poll(now + Duration::from_millis(i * 10) + queue_size)
                .unwrap()
                .0;

            assert_eq!(packet.sequence_number.0, BASE_SEQ.wrapping_add(i as u16));
        }
    }
}
