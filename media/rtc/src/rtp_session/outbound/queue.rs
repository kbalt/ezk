use super::SendRtpPacket;
use bytes::Bytes;
use rtp::{
    ExtendedRtpTimestamp, ExtendedSequenceNumber, RtpExtensions, RtpPacket, RtpTimestamp, Ssrc,
};
use std::{
    collections::BTreeMap,
    time::{Duration, Instant},
};
use time::ext::InstantExt;

pub(crate) struct OutboundQueue {
    pub(crate) clock_rate: f32,

    first_rtp_timestamp: Option<(Instant, ExtendedRtpTimestamp)>,

    // Ever increasing counter used as tie breaker for packets in the queue
    num_packets: u64,
    queue: BTreeMap<QueueKey, QueueEntry>,

    current_sequence_number: ExtendedSequenceNumber,
}

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
struct QueueKey {
    send_at: Instant,
    tie_breaker: u64,
}

struct QueueEntry {
    pt: u8,
    timestamp: RtpTimestamp,
    marker: bool,
    extensions: RtpExtensions,
    payload: Bytes,
}

impl OutboundQueue {
    pub(crate) fn new(clock_rate: u32) -> Self {
        OutboundQueue {
            clock_rate: clock_rate as f32,
            first_rtp_timestamp: None,
            num_packets: 0,
            queue: BTreeMap::new(),
            current_sequence_number: ExtendedSequenceNumber(rand::random_range(0xF..0x7FF)),
        }
    }

    pub(crate) fn instant_to_rtp_timestamp(
        &self,
        instant: Instant,
    ) -> Option<ExtendedRtpTimestamp> {
        let (ref_instant, ref_rtp_timestamp) = self.first_rtp_timestamp?;

        let v = ref_rtp_timestamp.0 as i64
            + (instant.signed_duration_since(ref_instant).as_seconds_f32() * self.clock_rate)
                as i64;

        Some(ExtendedRtpTimestamp(v as u64))
    }

    pub(crate) fn push(
        &mut self,
        SendRtpPacket {
            send_at,
            media_time,
            pt,
            marker,
            extensions,
            payload,
        }: SendRtpPacket,
    ) {
        if self.first_rtp_timestamp.is_none() {
            let first_rtp_timestamp: ExtendedRtpTimestamp =
                ExtendedRtpTimestamp(rand::random_range(0xFF..0xFFFF));
            self.first_rtp_timestamp = Some((media_time, first_rtp_timestamp));
        }

        let timestamp = self
            .instant_to_rtp_timestamp(media_time)
            .expect("just set the first_rtp_timestamp")
            .truncated();

        let tie_breaker = self.num_packets;
        self.num_packets += 1;

        self.queue.insert(
            QueueKey {
                send_at,
                tie_breaker,
            },
            QueueEntry {
                pt,
                timestamp,
                marker,
                extensions,
                payload,
            },
        );
    }

    pub(crate) fn pop(&mut self, now: Instant) -> Option<RtpPacket> {
        let (QueueKey { send_at, .. }, _) = self.queue.first_key_value()?;

        if now < *send_at {
            return None;
        }

        let QueueEntry {
            pt,
            timestamp,
            marker,
            extensions,
            payload,
        } = self
            .queue
            .pop_first()
            .expect("just checked that there's a value in queue")
            .1;

        Some(RtpPacket {
            pt,
            sequence_number: self.current_sequence_number.increase_one(),
            ssrc: Ssrc(0), // set by the stream
            timestamp,
            marker,
            extensions,
            payload,
        })
    }

    pub(crate) fn timeout(&self, now: Instant) -> Option<Duration> {
        Some(
            self.queue
                .first_key_value()?
                .0
                .send_at
                .checked_duration_since(now)
                .unwrap_or_default(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use rtp::RtpTimestamp;

    fn packet(media_time: Instant, pt: u8) -> SendRtpPacket {
        SendRtpPacket::new(media_time, pt, Bytes::new())
    }

    #[test]
    fn it_reorders() {
        let now = Instant::now();

        let mut queue = OutboundQueue::new(1000);
        queue.first_rtp_timestamp = Some((now, ExtendedRtpTimestamp(1000)));

        queue.push(packet(now, 2));
        queue.push(packet(now + Duration::from_millis(10), 3));
        queue.push(packet(now - Duration::from_millis(10), 1));

        assert!(matches!(
            queue.pop(now).unwrap(),
            RtpPacket {
                pt: 1,
                timestamp: RtpTimestamp(990),
                ..
            }
        ));

        assert!(matches!(
            queue.pop(now).unwrap(),
            RtpPacket {
                pt: 2,
                timestamp: RtpTimestamp(1000),
                ..
            }
        ));

        assert!(queue.pop(now).is_none());
        assert!(matches!(
            queue.pop(now + Duration::from_millis(10)),
            Some(RtpPacket {
                pt: 3,
                timestamp: RtpTimestamp(1010),
                ..
            })
        ));

        assert!(queue.pop(now + Duration::from_secs(9999)).is_none());
    }

    #[test]
    fn preserve_insertion_order_on_equal_instant() {
        let now = Instant::now();

        let mut queue = OutboundQueue::new(1000);
        queue.first_rtp_timestamp = Some((now, ExtendedRtpTimestamp(1000)));

        queue.push(packet(now, 1));
        queue.push(packet(now, 1));
        queue.push(packet(now, 1));
        queue.push(packet(now, 1));
        queue.push(packet(now - Duration::from_millis(100), 0));

        let pop1 = queue.pop(now).unwrap();

        assert!(matches!(
            pop1,
            RtpPacket {
                pt: 0,
                timestamp: RtpTimestamp(900),
                ..
            }
        ));
        for _ in 0..4 {
            assert!(matches!(
                queue.pop(now).unwrap(),
                RtpPacket {
                    pt: 1,
                    timestamp: RtpTimestamp(1000),
                    ..
                }
            ));
        }
    }
}
