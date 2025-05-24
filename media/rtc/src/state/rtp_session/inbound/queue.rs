use rtp::{ExtendedRtpTimestamp, ExtendedSequenceNumber, RtpPacket};
use std::{
    cmp::Ordering,
    collections::VecDeque,
    fmt,
    time::{Duration, Instant},
};
use time::ext::InstantExt as _;

const RX_BUFFER_DURATION: Duration = Duration::from_millis(100);

pub(crate) struct InboundQueue {
    max_entries: usize,
    pub(crate) clock_rate: u32,

    queue: VecDeque<QueueEntry>,

    /// Track the last received RTP packet
    last_rtp_received: Option<(Instant, ExtendedRtpTimestamp, ExtendedSequenceNumber)>,
    /// Track the latest sequence number, to drop late packets
    last_sequence_number_returned: Option<ExtendedSequenceNumber>,

    /// num packets dropped due to being duplicate, too late or the receiver falling behind
    pub(crate) dropped: u64,
    pub(crate) received: u64,
    pub(crate) received_bytes: u64,
    /// packets that were never received
    pub(crate) lost: u64,
    pub(crate) jitter: f32,
}

enum QueueEntry {
    Vacant(ExtendedSequenceNumber),
    Occupied {
        timestamp: ExtendedRtpTimestamp,
        sequence_number: ExtendedSequenceNumber,
        packet: RtpPacket,
    },
}

impl QueueEntry {
    fn sequence_number(&self) -> ExtendedSequenceNumber {
        match self {
            QueueEntry::Vacant(sequence_number) => *sequence_number,
            QueueEntry::Occupied {
                sequence_number, ..
            } => *sequence_number,
        }
    }
}

impl fmt::Debug for QueueEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vacant(arg0) => f.debug_tuple("Vacant").field(arg0).finish(),
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

impl InboundQueue {
    pub(crate) fn new(clock_rate: u32) -> Self {
        InboundQueue {
            max_entries: 1000,
            clock_rate,
            queue: VecDeque::new(),
            last_rtp_received: None,
            last_sequence_number_returned: None,
            dropped: 0,
            received: 0,
            received_bytes: 0,
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

                if timestamp > last_rtp_timestamp {
                    // Only update jitter if the timestamp changes

                    // Rj - Ri
                    let a = now - last_rtp_instant;
                    let a = (a.as_secs_f32() * self.clock_rate as f32) as i64;

                    // Sj - Si
                    let b = packet.timestamp.0 as i64 - last_rtp_timestamp.truncated().0 as i64;

                    // (Rj - Ri) - (Sj - Si)
                    let d = a.abs_diff(b);

                    self.jitter = self.jitter + ((d as f32).abs() - self.jitter) / 16.;

                    self.last_rtp_received = Some((now, timestamp, sequence_number));
                }

                self.push_extended(timestamp, sequence_number, packet)
            } else {
                let timestamp = ExtendedRtpTimestamp(packet.timestamp.0.into());
                let sequence_number = ExtendedSequenceNumber(packet.sequence_number.0.into());

                self.last_rtp_received = Some((now, timestamp, sequence_number));

                self.push_extended(timestamp, sequence_number, packet)
            };

        match push_result {
            PushResult::Added => {
                self.received += 1;
                self.received_bytes += payload_size as u64;

                if self.queue.len() > self.max_entries {
                    self.queue.pop_front();
                    self.dropped += 1;
                }
            }
            PushResult::Dropped => {
                self.dropped += 1;
            }
        }
    }

    fn push_extended(
        &mut self,
        timestamp: ExtendedRtpTimestamp,
        sequence_number: ExtendedSequenceNumber,
        packet: RtpPacket,
    ) -> PushResult {
        if let Some(seq) = self.last_sequence_number_returned {
            if seq >= sequence_number {
                return PushResult::Dropped;
            }
        }

        // front (1 2 3 4 5 6 7 8 9) back
        let Some(entry) = self.queue.back_mut() else {
            // queue is empty, insert entry and return
            self.queue.push_back(QueueEntry::Occupied {
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
                        if matches!(entry, QueueEntry::Vacant(..)) {
                            *entry = QueueEntry::Occupied {
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
                if matches!(entry, QueueEntry::Vacant(..)) {
                    *entry = QueueEntry::Occupied {
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
                if gap > self.max_entries as u64 {
                    return PushResult::Dropped;
                }

                for i in 1..gap {
                    self.queue
                        .push_back(QueueEntry::Vacant(ExtendedSequenceNumber(entry_seq.0 + i)));
                }

                self.queue.push_back(QueueEntry::Occupied {
                    timestamp,
                    sequence_number,
                    packet,
                });

                PushResult::Added
            }
        }
    }

    pub(crate) fn pop(&mut self, now: Instant) -> Option<RtpPacket> {
        let (last_rtp_received_instant, last_rtp_received_timestamp, _) = self.last_rtp_received?;

        let pop_earliest = now - RX_BUFFER_DURATION;

        let max_timestamp = map_instant_to_rtp_timestamp(
            last_rtp_received_instant,
            last_rtp_received_timestamp,
            self.clock_rate,
            pop_earliest,
        )?;

        let num_vacant = self.queue.iter().position(|e| match e {
            QueueEntry::Vacant(..) => false,
            QueueEntry::Occupied { timestamp, .. } => timestamp.0 <= max_timestamp.0,
        })?;

        for _ in 0..num_vacant {
            assert!(matches!(
                self.queue.pop_front(),
                Some(QueueEntry::Vacant(..))
            ));
        }

        self.lost += num_vacant as u64;

        match self.queue.pop_front() {
            Some(QueueEntry::Occupied {
                packet,
                sequence_number,
                ..
            }) => {
                self.last_sequence_number_returned = Some(sequence_number);
                Some(packet)
            }
            _ => {
                log::warn!("InboundQueue::pop() reached unreachable code");
                None
            }
        }
    }

    pub(crate) fn timeout(&self, now: Instant) -> Option<Duration> {
        let (last_rtp_received_instant, last_rtp_received_timestamp, _) = self.last_rtp_received?;
        let earliest_timestamp = self.queue.iter().find_map(|e| match e {
            QueueEntry::Vacant(..) => None,
            QueueEntry::Occupied { timestamp, .. } => Some(*timestamp),
        })?;

        let delta = last_rtp_received_timestamp.0 - earliest_timestamp.0;
        let delta = Duration::from_secs_f32(delta as f32 / self.clock_rate as f32);

        let instant = (last_rtp_received_instant - delta) + RX_BUFFER_DURATION;

        Some(
            instant
                .checked_duration_since(now)
                .unwrap_or(Duration::ZERO),
        )
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
    let delta_in_rtp_timesteps = (delta.as_seconds_f32() * clock_rate as f32) as i64;

    u64::try_from(reference_timestamp.0 as i64 - delta_in_rtp_timesteps)
        .ok()
        .map(ExtendedRtpTimestamp)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use rtp::{RtpExtensions, RtpTimestamp, SequenceNumber, Ssrc};

    fn make_packet(seq: u16) -> RtpPacket {
        RtpPacket {
            pt: 0,
            sequence_number: SequenceNumber(seq),
            ssrc: Ssrc(0),
            timestamp: RtpTimestamp(0),
            extensions: RtpExtensions::default(),
            payload: Bytes::new(),
        }
    }

    #[test]
    fn flimsy_test() {
        let mut jb = InboundQueue::new(8000);

        let now = Instant::now();

        jb.push(now + Duration::from_millis(100), make_packet(1));
        assert_eq!(jb.queue.len(), 1);
        jb.push(now + Duration::from_millis(400), make_packet(4));
        assert_eq!(jb.queue.len(), 4);

        jb.push(now + Duration::from_millis(300), make_packet(3));
        assert_eq!(jb.queue.len(), 4);
        assert!(jb.pop(now + Duration::from_millis(99)).is_none());
        assert_eq!(
            jb.pop(now + Duration::from_millis(100))
                .unwrap()
                .sequence_number
                .0,
            1
        );
        assert!(jb.pop(now + Duration::from_millis(200)).is_none());
        assert_eq!(
            jb.pop(now + Duration::from_millis(500))
                .unwrap()
                .sequence_number
                .0,
            3
        );
        assert_eq!(
            jb.pop(now + Duration::from_millis(500))
                .unwrap()
                .sequence_number
                .0,
            4
        );
        assert_eq!(jb.lost, 1)
    }
}
