use rtp::{ExtendedRtpTimestamp, ExtendedSequenceNumber, RtpPacket};
use std::{
    collections::VecDeque,
    time::{Duration, Instant},
};
use time::ext::InstantExt;

pub(crate) struct OutboundQueue {
    pub(crate) clock_rate: f32,

    first_rtp_timestamp: Option<(Instant, ExtendedRtpTimestamp)>,

    queue: VecDeque<(Instant, RtpPacket)>,

    current_sequence_number: ExtendedSequenceNumber,
}

impl OutboundQueue {
    pub(crate) fn new(clock_rate: u32) -> Self {
        Self {
            clock_rate: clock_rate as f32,
            first_rtp_timestamp: None,
            queue: VecDeque::new(),
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

    pub(crate) fn push(&mut self, at: Instant, mut packet: RtpPacket) {
        if self.first_rtp_timestamp.is_none() {
            let first_rtp_timestamp = ExtendedRtpTimestamp(rand::random_range(0xFF..0xFFFF));
            self.first_rtp_timestamp = Some((at, first_rtp_timestamp));
        }

        packet.timestamp = self
            .instant_to_rtp_timestamp(at)
            .expect("just set the first_rtp_timestamp")
            .truncated();

        if let Some(index) = self.queue.iter().position(|(i, _)| *i > at) {
            self.queue.insert(index, (at, packet));
        } else {
            self.queue.push_front((at, packet));
        }
    }

    pub(crate) fn pop(&mut self, now: Instant) -> Option<RtpPacket> {
        let (instant, _) = self.queue.back()?;

        if now > *instant {
            return None;
        }

        let mut packet = self.queue.pop_back().unwrap().1;
        packet.sequence_number = self.current_sequence_number.increase_one();

        Some(packet)
    }

    pub(crate) fn timeout(&self, now: Instant) -> Option<Duration> {
        Some(
            self.queue
                .back()?
                .0
                .checked_duration_since(now)
                .unwrap_or_default(),
        )
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;
    use rtp::{RtpExtensions, RtpTimestamp, SequenceNumber, Ssrc};

    use super::*;

    fn packet(pt: u8) -> RtpPacket {
        RtpPacket {
            pt,
            sequence_number: SequenceNumber(0),
            ssrc: Ssrc(0),
            timestamp: RtpTimestamp(0),
            extensions: RtpExtensions::default(),
            payload: Bytes::default(),
        }
    }

    #[test]
    fn preserve_insertion_order_on_equal_instant() {
        let now = Instant::now();

        let mut queue = OutboundQueue::new(8000);
        queue.first_rtp_timestamp = Some((now, ExtendedRtpTimestamp(0)));

        queue.push(now, packet(1));
        queue.push(now, packet(1));
        queue.push(now, packet(1));
        queue.push(now, packet(1));
        queue.push(now - Duration::from_millis(100), packet(0));

        let pop1 = queue.pop(now).unwrap();
        let pop2 = queue.pop(now).unwrap();

        assert!(matches!(
            pop1,
            RtpPacket {
                pt: 1,
                timestamp: RtpTimestamp(1),
                ..
            }
        ));
        assert!(matches!(
            pop2,
            RtpPacket {
                pt: 0,
                timestamp: RtpTimestamp(1),
                ..
            }
        ));
    }
}
