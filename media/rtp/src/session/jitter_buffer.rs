use crate::{ExtendedRtpTimestamp, ExtendedSequenceNumber, RtpPacket};
use std::{cmp::Ordering, collections::VecDeque, fmt};

/// A queue based jitter buffer
///
/// Front of queue are the oldest packets (lowest sequence number)
/// Back of queue are the newest packets (highest sequence number)
pub(crate) struct JitterBuffer {
    max_entries: usize,
    queue: VecDeque<QueueEntry>,

    /// Track the latest sequence number, to drop late packets
    last_sequence_number_returned: Option<ExtendedSequenceNumber>,

    /// num packets dropped due to being duplicate, too late or the receiver falling behind
    pub(crate) dropped: u64,
    /// num packets received
    pub(crate) received: u64,
    /// num packets not received
    pub(crate) lost: u64,
}

impl fmt::Debug for JitterBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JitterBuffer")
            .field("max_entries", &self.max_entries)
            .field("queue (len)", &self.queue.len())
            .field("dropped", &self.dropped)
            .field("received", &self.received)
            .field("lost", &self.lost)
            .finish()
    }
}

impl Default for JitterBuffer {
    fn default() -> Self {
        JitterBuffer {
            max_entries: 1000,
            queue: VecDeque::new(),
            last_sequence_number_returned: None,
            dropped: 0,
            received: 0,
            lost: 0,
        }
    }
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

impl JitterBuffer {
    pub(crate) fn push(
        &mut self,
        timestamp: ExtendedRtpTimestamp,
        sequence_number: ExtendedSequenceNumber,
        packet: RtpPacket,
    ) {
        if let Some(seq) = self.last_sequence_number_returned {
            if seq >= sequence_number {
                self.dropped += 1;
                return;
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

            return;
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
                        } else {
                            self.dropped += 1;
                        }
                        return;
                    }
                }
            }
            Ordering::Equal => {
                // last entry is equal, insert if its vacant
                if matches!(entry, QueueEntry::Vacant(..)) {
                    *entry = QueueEntry::Occupied {
                        timestamp,
                        sequence_number,
                        packet,
                    };
                } else {
                    self.dropped += 1;
                }
            }
            Ordering::Less => {
                let gap = sequence_number.0 - entry.sequence_number().0;
                let entry_seq = entry.sequence_number();

                for i in 1..gap {
                    self.queue
                        .push_back(QueueEntry::Vacant(ExtendedSequenceNumber(entry_seq.0 + i)));
                }

                self.queue.push_back(QueueEntry::Occupied {
                    timestamp,
                    sequence_number,
                    packet,
                });
            }
        }

        if self.queue.len() > self.max_entries {
            self.queue.pop_front();
            self.dropped += 1;
        }
    }

    pub(crate) fn pop(&mut self, max_timestamp: ExtendedRtpTimestamp) -> Option<RtpPacket> {
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
            _ => unreachable!(),
        }
    }

    pub(crate) fn timestamp_of_earliest_packet(&self) -> Option<ExtendedRtpTimestamp> {
        self.queue.iter().find_map(|e| match e {
            QueueEntry::Vacant(..) => None,
            QueueEntry::Occupied { timestamp: ts, .. } => Some(*ts),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{RtpExtensions, RtpTimestamp, SequenceNumber, Ssrc};
    use bytes::Bytes;

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
        let mut jb = JitterBuffer::default();

        jb.push(
            ExtendedRtpTimestamp(100),
            ExtendedSequenceNumber(1),
            make_packet(1),
        );
        assert_eq!(jb.queue.len(), 1);
        jb.push(
            ExtendedRtpTimestamp(400),
            ExtendedSequenceNumber(4),
            make_packet(4),
        );
        assert_eq!(jb.queue.len(), 4);

        jb.push(
            ExtendedRtpTimestamp(300),
            ExtendedSequenceNumber(3),
            make_packet(3),
        );
        assert_eq!(jb.queue.len(), 4);
        assert_eq!(
            jb.timestamp_of_earliest_packet(),
            Some(ExtendedRtpTimestamp(100))
        );
        assert!(jb.pop(ExtendedRtpTimestamp(99)).is_none());
        assert_eq!(
            jb.pop(ExtendedRtpTimestamp(100)).unwrap().sequence_number.0,
            1
        );
        assert!(jb.pop(ExtendedRtpTimestamp(200)).is_none());
        assert_eq!(
            jb.pop(ExtendedRtpTimestamp(500)).unwrap().sequence_number.0,
            3
        );
        assert_eq!(
            jb.pop(ExtendedRtpTimestamp(500)).unwrap().sequence_number.0,
            4
        );
        assert_eq!(jb.lost, 1)
    }
}
