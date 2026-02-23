use crate::{opt_min, rtp_session::inbound::stats::RtpInboundRtxStats};
use rtp::{
    ExtendedRtpTimestamp, ExtendedSequenceNumber, RtpPacket, SequenceNumber, Ssrc,
    rtcp_types::NackBuilder,
};
use std::{
    cmp::{self, Ordering},
    collections::VecDeque,
    fmt,
    time::{Duration, Instant},
};
use time::ext::InstantExt as _;

/// Fixed size of the jitter buffer
const INITIAL_BUFFER_DURATION: Duration = Duration::from_millis(50);

/// Time to wait before generating a NACK packet
const NACK_DELAY: Duration = Duration::from_millis(5);

/// Maximum number of entries to keep in buffer to avoid excessive memory usage
const MAX_ENTRIES: usize = 1024;

/// Maximum queue duration to prevent runaway jitter from inflating the buffer
const MAX_QUEUE_DURATION: Duration = Duration::from_secs(4);

/// Jitter samples larger than this (in seconds) are discarded as outliers
/// (e.g. pause/resume, SRTP rekeying, clock discontinuities)
const MAX_VALID_JITTER_SAMPLE: Duration = Duration::from_secs(1);

/// Dynamically sized inbound buffer.
///
/// Resizes on every received packet based on current jitter and
/// round trip time derived from RTX retransmissions (when enabled).
pub(crate) struct InboundQueue {
    /// Payload type of the "main" media received over this ssrc
    ///
    /// Used to reassign the payload type of retransmitted packets back to the media type
    pub(crate) pt: u8,

    /// SSRC of the receiving RTP stream
    pub(crate) ssrc: Ssrc,

    /// Clock rate of the media received, used convert the RTP timestamp to wall time
    pub(crate) clock_rate: u32,

    queue: VecDeque<QueueEntry>,
    queue_size: Duration,

    /// Track the last received RTP packet
    last_rtp_received: Option<(Instant, ExtendedRtpTimestamp, ExtendedSequenceNumber)>,
    /// Track the latest sequence number, to drop late packets
    last_sequence_number_returned: Option<ExtendedSequenceNumber>,

    rtx: Option<Rtx>,

    /// num packets dropped due to being duplicate, too late or the receiver falling behind
    pub(crate) dropped: u64,
    pub(crate) received: u64,
    pub(crate) received_bytes: u64,

    /// packets that were never received
    pub(crate) lost: u64,
    pub(crate) jitter: f64,
}

enum QueueEntry {
    Vacant {
        sequence_number: ExtendedSequenceNumber,
        detected_at: Instant,
        // (timestamp of NACK request, how many nacks have been sent)
        nacked_at: Option<(Instant, u32)>,
    },
    Occupied {
        /// Instant the packet was received. None if it was a retransmission to keep it out of RTP statistics.
        received_at: Option<Instant>,
        timestamp: ExtendedRtpTimestamp,
        sequence_number: ExtendedSequenceNumber,
        packet: RtpPacket,
    },
}

impl QueueEntry {
    fn sequence_number(&self) -> ExtendedSequenceNumber {
        match self {
            QueueEntry::Vacant {
                sequence_number, ..
            } => *sequence_number,
            QueueEntry::Occupied {
                sequence_number, ..
            } => *sequence_number,
        }
    }
}

impl fmt::Debug for QueueEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vacant {
                sequence_number,
                detected_at,
                nacked_at,
            } => f
                .debug_struct("Vacant")
                .field("sequence_number", &sequence_number)
                .field("detected_at", &detected_at)
                .field("nacked_at", &nacked_at)
                .finish(),
            Self::Occupied {
                timestamp: ts,
                sequence_number: seq,
                ..
            } => f
                .debug_struct("Occupied")
                .field("ts", ts)
                .field("seq", seq)
                .finish(),
        }
    }
}

struct Rtx {
    rtt: Option<RtxRtt>,

    lost_nacked_packets: VecDeque<(ExtendedSequenceNumber, Instant)>,

    // Stats
    received_in_time: u64,
    received_too_late: u64,
    received_redundant: u64,
    bytes_received: u64,
}

/// Using parts of TCP's retransmission calculation from https://datatracker.ietf.org/doc/html/rfc6298
/// to find a round trip time by measuring the time between NACK and retransmission reception
///
struct RtxRtt {
    /// Smoothed round-trip time
    srtt: Duration,
    /// Round-trip time variation
    variation: Duration,
}

impl Rtx {
    fn update_rtt(&mut self, sample: Duration) {
        match &mut self.rtt {
            Some(RtxRtt { srtt, variation }) => {
                let diff = srtt.abs_diff(sample);

                *variation = *variation * 3 / 4 + diff / 4;
                *srtt = *srtt * 7 / 8 + sample / 8;
            }
            _ => {
                self.rtt = Some(RtxRtt {
                    srtt: sample,
                    variation: sample / 2,
                });
            }
        }
    }
}

impl InboundQueue {
    pub(crate) fn new(pt: u8, ssrc: Ssrc, clock_rate: u32, has_rtx: bool) -> Self {
        InboundQueue {
            pt,
            ssrc,
            clock_rate,
            queue: VecDeque::new(),
            queue_size: INITIAL_BUFFER_DURATION,
            last_rtp_received: None,
            last_sequence_number_returned: None,
            dropped: 0,
            received: 0,
            received_bytes: 0,
            rtx: has_rtx.then_some(Rtx {
                rtt: None,
                lost_nacked_packets: VecDeque::new(),
                received_in_time: 0,
                received_too_late: 0,
                received_redundant: 0,
                bytes_received: 0,
            }),
            lost: 0,
            jitter: 0.0,
        }
    }

    pub(crate) fn highest_sequence_number_received(&self) -> Option<ExtendedSequenceNumber> {
        let (_, _, seq) = self.last_rtp_received?;
        Some(seq)
    }

    pub(crate) fn push(&mut self, now: Instant, packet: RtpPacket) {
        let payload_size = packet.payload.len();

        // Update jitter and find extended timestamp
        let push_result =
            if let Some((last_rtp_instant, last_rtp_timestamp, last_sequence_number)) =
                self.last_rtp_received
            {
                let timestamp = last_rtp_timestamp.guess_extended(packet.timestamp);
                let sequence_number = last_sequence_number.guess_extended(packet.sequence_number);

                self.update_jitter(now, &packet, last_rtp_instant, last_rtp_timestamp);

                self.last_rtp_received = Some((now, timestamp, sequence_number));
                self.push_extended(now, timestamp, sequence_number, packet)
            } else {
                let timestamp = ExtendedRtpTimestamp(u64::from(packet.timestamp.0));
                let sequence_number = ExtendedSequenceNumber(packet.sequence_number.0.into());

                self.last_rtp_received = Some((now, timestamp, sequence_number));
                self.push_extended(now, timestamp, sequence_number, packet)
            };

        match push_result {
            PushResult::Added => {
                self.received += 1;
                self.received_bytes += payload_size as u64;

                if self.queue.len() > MAX_ENTRIES {
                    self.queue.pop_front();
                    self.dropped += 1;
                }
            }
            PushResult::Dropped => {
                self.dropped += 1;
            }
        }
    }

    fn update_jitter(
        &mut self,
        now: Instant,
        packet: &RtpPacket,
        last_rtp_instant: Instant,
        last_rtp_timestamp: ExtendedRtpTimestamp,
    ) {
        // Rj - Ri
        let recv_delta = (now - last_rtp_instant).as_secs_f64() * self.clock_rate as f64;

        // Sj - Si
        let rtp_ts_delta = (packet.timestamp.0 - last_rtp_timestamp.truncated().0) as f64;

        // Discard near zero delta values
        //
        // They usually come from video frames received using GRO or similiar, skewing the jitter result
        if recv_delta < 1e-8 || rtp_ts_delta < 1e-8 {
            return;
        }

        // (Rj - Ri) - (Sj - Si)
        let d = (recv_delta - rtp_ts_delta).abs();

        // Discard very large jitter values which can be caused by network interruptions
        // or other unusual scenarios
        if d > MAX_VALID_JITTER_SAMPLE.as_secs_f64() * self.clock_rate as f64 {
            return;
        }

        // RTP RFC proposes a gain parameter of 1/16 which doesn't adapt to jitter growing fast enough
        //
        // Trying out 1/8 for growing jitter and 1/64 for shrinking,
        // looks more stable and reacts faster to jumps in jitter
        let alpha = if d > self.jitter { 16.0 } else { 64.0 };
        self.jitter += (d - self.jitter) / alpha;

        // Calculate new queue size from jitter + rtx round trip time
        let jitter_queue_req =
            Duration::from_secs_f64(self.jitter.max(0.001) / self.clock_rate as f64 * 1.5);

        let queue_size = if let Some(rtx) = &self.rtx {
            let rtx_budget = if let Some(rtt) = &rtx.rtt {
                NACK_DELAY + rtt.srtt + rtt.variation * 2
            } else {
                INITIAL_BUFFER_DURATION
            };

            cmp::max(jitter_queue_req, rtx_budget)
        } else {
            jitter_queue_req
        };

        self.queue_size = queue_size.min(MAX_QUEUE_DURATION);
    }

    fn push_extended(
        &mut self,
        received_at: Instant,
        timestamp: ExtendedRtpTimestamp,
        sequence_number: ExtendedSequenceNumber,
        packet: RtpPacket,
    ) -> PushResult {
        if let Some(last_sequence_number_returned) = self.last_sequence_number_returned
            && last_sequence_number_returned >= sequence_number
        {
            return PushResult::Dropped;
        }

        // front (1 2 3 4 5 6 7 8 9) back
        let Some(entry) = self.queue.back_mut() else {
            // queue is empty, insert entry and return
            self.queue.push_back(QueueEntry::Occupied {
                received_at: Some(received_at),
                timestamp,
                sequence_number,
                packet,
            });

            return PushResult::Added;
        };

        match entry.sequence_number().cmp(&sequence_number) {
            Ordering::Greater => {
                for entry in self.queue.iter_mut().rev() {
                    if entry.sequence_number() == sequence_number {
                        if matches!(entry, QueueEntry::Vacant { .. }) {
                            *entry = QueueEntry::Occupied {
                                received_at: Some(received_at),
                                timestamp,
                                sequence_number,
                                packet,
                            };
                            return PushResult::Added;
                        } else {
                            return PushResult::Dropped;
                        }
                    }
                }

                PushResult::Dropped
            }
            Ordering::Equal => {
                // last entry is equal, insert if its vacant
                if matches!(entry, QueueEntry::Vacant { .. }) {
                    *entry = QueueEntry::Occupied {
                        received_at: Some(received_at),
                        timestamp,
                        sequence_number,
                        packet,
                    };

                    PushResult::Added
                } else {
                    PushResult::Dropped
                }
            }
            Ordering::Less => {
                let gap = sequence_number.0 - entry.sequence_number().0;
                let entry_seq = entry.sequence_number();

                // Ignore the packet if the gap is too large
                if gap > MAX_ENTRIES as u64 {
                    return PushResult::Dropped;
                }

                for i in 1..gap {
                    let sequence_number = ExtendedSequenceNumber(entry_seq.0 + i);

                    self.queue.push_back(QueueEntry::Vacant {
                        sequence_number,
                        detected_at: received_at,
                        nacked_at: None,
                    });
                }

                self.queue.push_back(QueueEntry::Occupied {
                    received_at: Some(received_at),
                    timestamp,
                    sequence_number,
                    packet,
                });

                PushResult::Added
            }
        }
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

        let sequence_number = SequenceNumber(u16::from_be_bytes([*b0, *b1]));

        let rtp_packet = RtpPacket {
            pt: self.pt,
            sequence_number,
            ssrc: self.ssrc,
            timestamp: rtp_packet.timestamp,
            marker: rtp_packet.marker,
            extensions: rtp_packet.extensions,
            payload: rtp_packet.payload.slice_ref(original_payload),
        };

        let sequence_number = last_rtp_received_sequence_number.guess_extended(sequence_number);
        let timestamp = last_rtp_received_timestamp.guess_extended(rtp_packet.timestamp);

        match self
            .queue
            .iter_mut()
            .enumerate()
            .find(|(_, entry)| entry.sequence_number() == sequence_number)
        {
            Some((_, QueueEntry::Occupied { .. })) => {
                // Retransmission was redundant
                rtx.received_redundant += 1;
            }
            Some((i, QueueEntry::Vacant { nacked_at, .. })) => {
                rtx.received_in_time += 1;
                rtx.bytes_received += rtp_packet.payload.len() as u64;

                if let Some((nacked_at, num_nacks)) = nacked_at
                    && *num_nacks == 1
                {
                    rtx.update_rtt(now - *nacked_at);
                }

                self.queue[i] = QueueEntry::Occupied {
                    received_at: None,
                    timestamp,
                    sequence_number,
                    packet: rtp_packet,
                };
            }
            None => {
                // Retransmission is late
                rtx.received_too_late += 1;

                // Try to update rtt from lost packet
                if let Some((index, (_, nacked_at))) = rtx
                    .lost_nacked_packets
                    .iter()
                    .enumerate()
                    .find(|(_, (seq, ..))| *seq == sequence_number)
                {
                    rtx.update_rtt(now - *nacked_at);
                    rtx.lost_nacked_packets.remove(index);
                }
            }
        }
    }

    fn nack_resend_delay(&self) -> Duration {
        if let Some(rtx) = &self.rtx
            && let Some(rtx_rtt) = &rtx.rtt
        {
            cmp::max(
                Duration::from_secs_f64(
                    rtx_rtt.srtt.as_secs_f64() + rtx_rtt.variation.as_secs_f64() * 2.0,
                ),
                NACK_DELAY,
            )
        } else {
            NACK_DELAY
        }
    }

    /// Returns a list of sequence numbers to NACK
    pub(crate) fn poll_nack(&mut self, now: Instant) -> Option<NackBuilder> {
        let mut nack = NackBuilder::default();
        let mut empty = true;

        let nack_resend_delay = self.nack_resend_delay();

        for entry in &mut self.queue {
            if let QueueEntry::Vacant {
                sequence_number,
                detected_at,
                nacked_at,
            } = entry
            {
                // Don't immediately NACK vacant entries, wait at least NACK_DELAY
                if nacked_at.is_none() && *detected_at + NACK_DELAY > now {
                    continue;
                }

                // Wait NACK_DELAY before sending NACK again for a sequence number
                if let Some((nacked_at, _)) = *nacked_at
                    && (nacked_at + nack_resend_delay) > now
                {
                    continue;
                }

                match nacked_at {
                    Some((nacked_at, n)) => {
                        *nacked_at = now;
                        *n += 1;
                    }
                    None => *nacked_at = Some((now, 1)),
                }

                nack = nack.add_rtp_sequence(sequence_number.truncated().0);
                empty = false;
            }
        }

        if empty {
            return None;
        }

        Some(nack)
    }

    pub(crate) fn poll(&mut self, now: Instant) -> Option<(RtpPacket, Option<Instant>)> {
        let (last_rtp_received_instant, last_rtp_received_timestamp, _) = self.last_rtp_received?;

        let pop_earliest = now - self.queue_size;

        let max_timestamp = map_instant_to_rtp_timestamp(
            last_rtp_received_instant,
            last_rtp_received_timestamp,
            self.clock_rate,
            pop_earliest,
        )?;

        let num_vacant = self.queue.iter().position(|e| match e {
            QueueEntry::Vacant { .. } => false,
            QueueEntry::Occupied { timestamp, .. } => timestamp.0 <= max_timestamp.0,
        })?;

        for _ in 0..num_vacant {
            let Some(QueueEntry::Vacant {
                nacked_at,
                sequence_number,
                ..
            }) = self.queue.pop_front()
            else {
                unreachable!()
            };

            if let Some(rtx) = &mut self.rtx
                && let Some((nacked_at, num_nacks)) = nacked_at
                && num_nacks == 1
            {
                rtx.lost_nacked_packets
                    .push_back((sequence_number, nacked_at));

                if rtx.lost_nacked_packets.len() > 1024 {
                    rtx.lost_nacked_packets.pop_front();
                }
            }
        }

        self.lost += num_vacant as u64;

        match self.queue.pop_front() {
            Some(QueueEntry::Occupied {
                received_at,
                packet,
                sequence_number,
                ..
            }) => {
                self.last_sequence_number_returned = Some(sequence_number);
                Some((packet, received_at))
            }
            _ => {
                log::warn!("InboundQueue::pop() reached unreachable code");
                None
            }
        }
    }

    pub(crate) fn timeout_receive(&self, now: Instant) -> Option<Duration> {
        let (last_rtp_received_instant, last_rtp_received_timestamp, _) = self.last_rtp_received?;
        let earliest_timestamp = self.queue.iter().find_map(|e| match e {
            QueueEntry::Vacant { .. } => None,
            QueueEntry::Occupied { timestamp, .. } => Some(*timestamp),
        })?;

        let delta = last_rtp_received_timestamp.0 - earliest_timestamp.0;
        let delta = Duration::from_secs_f64(delta as f64 / self.clock_rate as f64);

        let instant = (last_rtp_received_instant - delta) + self.queue_size;

        Some(
            instant
                .checked_duration_since(now)
                .unwrap_or(Duration::ZERO),
        )
    }

    pub(crate) fn timeout_nack(&self, now: Instant) -> Option<Duration> {
        let mut timeout = None;
        let nack_resend_delay = self.nack_resend_delay();

        for entry in &self.queue {
            if let QueueEntry::Vacant {
                detected_at,
                nacked_at,
                ..
            } = entry
            {
                let (delay, ts) = match nacked_at {
                    Some((nacked_at, _)) => (nack_resend_delay, *nacked_at),
                    None => (NACK_DELAY, *detected_at),
                };

                timeout = opt_min(timeout, Some((ts + delay).saturating_duration_since(now)));
            }
        }

        timeout
    }

    pub(super) fn rtx_stats(&self) -> Option<RtpInboundRtxStats> {
        self.rtx.as_ref().map(|rtx| RtpInboundRtxStats {
            packets_received_in_time: rtx.received_in_time,
            packets_received_too_late: rtx.received_too_late,
            packets_received_redundant: rtx.received_redundant,
            bytes_received: rtx.bytes_received,
            rtt: rtx.rtt.as_ref().map(|rtt| rtt.srtt),
        })
    }
}

enum PushResult {
    Added,
    Dropped,
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
    use bytes::Bytes;
    use rtp::{RtpExtensions, RtpTimestamp, SequenceNumber, Ssrc};

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
        let mut jb = InboundQueue::new(0, Ssrc(0), 1000, false);

        let now = Instant::now();

        jb.push(now + Duration::from_millis(100), make_packet(1, 100));
        assert_eq!(jb.queue.len(), 1);
        jb.push(now + Duration::from_millis(400), make_packet(4, 400));
        assert_eq!(jb.queue.len(), 4);

        jb.push(now + Duration::from_millis(300), make_packet(3, 300));
        assert_eq!(jb.queue.len(), 4);

        assert!(
            jb.poll(now + Duration::from_millis(100) + jb.queue_size / 2)
                .is_none()
        );
        assert_eq!(
            jb.poll(now + Duration::from_millis(100) + jb.queue_size)
                .unwrap()
                .0
                .sequence_number
                .0,
            1
        );
        assert_eq!(
            jb.poll(now + Duration::from_millis(300) + jb.queue_size)
                .unwrap()
                .0
                .sequence_number
                .0,
            3
        );
        assert_eq!(
            jb.poll(now + Duration::from_millis(400) + jb.queue_size)
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
        let mut jb = InboundQueue::new(0, Ssrc(0), 1000, false);

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
                .poll(now + Duration::from_millis(i * 10) + jb.queue_size)
                .unwrap()
                .0;

            assert_eq!(packet.sequence_number.0, BASE_SEQ.wrapping_add(i as u16));
        }
    }
}
