use crate::rtp_session::outbound::RtpOutboundStreamEvent;

use super::SendRtpPacket;
use bytes::{BufMut, Bytes, BytesMut};
use rtp::{
    ExtendedRtpTimestamp, ExtendedSequenceNumber, RtpExtensions, RtpPacket, RtpTimestamp, Ssrc,
};
use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};
use time::ext::InstantExt;

pub(crate) struct OutboundQueue {
    pub(crate) ssrc: Ssrc,
    pub(crate) clock_rate: f32,

    /// Mapping of a instant to a RTP timestamp. Used to calculate future RTP timestamps
    first_rtp_timestamp: Option<(Instant, ExtendedRtpTimestamp)>,

    /// Ever increasing counter used as tie breaker for packets in the queue
    num_packets: u64,
    /// Outbound packet queue. Sorted by packet send time.
    queue: BTreeMap<QueueKey, QueueEntry>,

    /// Sequence number of the next packet to be sent
    current_sequence_number: ExtendedSequenceNumber,

    /// Retransmission state
    rtx: Option<Rtx>,
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

struct Rtx {
    /// SSRC of the RTX stream
    ssrc: Ssrc,

    /// RTX's payload type
    pt: u8,

    /// Queue of already sent RTP packets
    sent_packets: VecDeque<(RtpPacket, Instant)>,

    /// Determines how long a RTP packet is stored for retransmission before being dropped
    sent_packets_max_size: Duration,

    /// RTP packets that have been queued for retransmission
    retransmit_queue: VecDeque<RtpPacket>,

    /// Sequence number of the next retransmission packet to be sent
    current_sequence_number: ExtendedSequenceNumber,
}

impl OutboundQueue {
    pub(crate) fn new(ssrc: Ssrc, clock_rate: u32, rtx: Option<(u8, Ssrc)>) -> Self {
        OutboundQueue {
            ssrc,
            clock_rate: clock_rate as f32,
            first_rtp_timestamp: None,
            num_packets: 0,
            queue: BTreeMap::new(),
            current_sequence_number: ExtendedSequenceNumber(rand::random_range(0xF..0x7FF)),
            rtx: rtx.map(|(pt, ssrc)| Rtx {
                ssrc,
                pt,
                sent_packets: VecDeque::new(),
                sent_packets_max_size: Duration::from_secs(1),
                retransmit_queue: VecDeque::new(),
                current_sequence_number: ExtendedSequenceNumber(rand::random_range(0xF..0x7FF)),
            }),
        }
    }

    pub(crate) fn has_received(&self) -> bool {
        self.first_rtp_timestamp.is_some()
    }

    pub(crate) fn instant_to_rtp_timestamp(
        &self,
        instant: Instant,
    ) -> Option<ExtendedRtpTimestamp> {
        let (ref_instant, ref_rtp_timestamp) = self.first_rtp_timestamp?;

        let v = ref_rtp_timestamp.0.cast_signed()
            + (instant.signed_duration_since(ref_instant).as_seconds_f32() * self.clock_rate)
                as i64;

        Some(ExtendedRtpTimestamp(v.cast_unsigned()))
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

    pub(crate) fn poll(&mut self, now: Instant) -> Option<RtpOutboundStreamEvent> {
        // Check if there are packets queued for retransmissions
        if let Some(rtx) = &mut self.rtx
            && let Some(mut rtp_packet) = rtx.retransmit_queue.pop_front()
        {
            // Build RTX payload
            let mut payload = BytesMut::new();
            // First 2 byte are the original sequence number
            payload.put_u16(rtp_packet.sequence_number.0);
            payload.extend_from_slice(&rtp_packet.payload);

            rtp_packet.ssrc = rtx.ssrc;
            rtp_packet.pt = rtx.pt;
            rtp_packet.sequence_number = rtx.current_sequence_number.increase_one();
            rtp_packet.payload = payload.freeze();

            return Some(RtpOutboundStreamEvent::SendRtpPacket {
                rtp_packet,
                is_rtx: true,
            });
        }

        // Deque outbound packets
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
        } = self.queue.pop_first()?.1;

        let rtp_packet = RtpPacket {
            pt,
            sequence_number: self.current_sequence_number.increase_one(),
            ssrc: self.ssrc,
            timestamp,
            marker,
            extensions,
            payload,
        };

        // Store packet in sent_packets if configured
        if let Some(rtx) = &mut self.rtx {
            rtx.sent_packets.push_back((rtp_packet.clone(), now));

            // Remove old packets
            while let Some((_, sent_at)) = rtx.sent_packets.front()
                && now.saturating_duration_since(*sent_at) > rtx.sent_packets_max_size
            {
                rtx.sent_packets.pop_front();
            }
        }

        Some(RtpOutboundStreamEvent::SendRtpPacket {
            rtp_packet,
            is_rtx: false,
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

    pub(crate) fn handle_nack(&mut self, entries: impl Iterator<Item = u16>) {
        let Some(rtx) = &mut self.rtx else {
            return;
        };

        for entry in entries {
            if let Some((rtp_packet, _)) = rtx
                .sent_packets
                .iter()
                .find(|x| x.0.sequence_number.0 == entry)
            {
                rtx.retransmit_queue.push_back(rtp_packet.clone());
            }
        }
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

        let mut queue = OutboundQueue::new(Ssrc(0), 1000, None);
        queue.first_rtp_timestamp = Some((now, ExtendedRtpTimestamp(1000)));

        queue.push(packet(now, 2));
        queue.push(packet(now + Duration::from_millis(10), 3));
        queue.push(packet(now - Duration::from_millis(10), 1));

        assert!(matches!(
            queue.poll(now).unwrap(),
            RtpOutboundStreamEvent::SendRtpPacket {
                rtp_packet: RtpPacket {
                    pt: 1,
                    timestamp: RtpTimestamp(990),
                    ..
                },
                ..
            }
        ));

        assert!(matches!(
            queue.poll(now).unwrap(),
            RtpOutboundStreamEvent::SendRtpPacket {
                rtp_packet: RtpPacket {
                    pt: 2,
                    timestamp: RtpTimestamp(1000),
                    ..
                },
                ..
            }
        ));

        assert!(queue.poll(now).is_none());
        assert!(matches!(
            queue.poll(now + Duration::from_millis(10)),
            Some(RtpOutboundStreamEvent::SendRtpPacket {
                rtp_packet: RtpPacket {
                    pt: 3,
                    timestamp: RtpTimestamp(1010),
                    ..
                },
                ..
            })
        ));

        assert!(queue.poll(now + Duration::from_secs(9999)).is_none());
    }

    #[test]
    fn preserve_insertion_order_on_equal_instant() {
        let now = Instant::now();

        let mut queue = OutboundQueue::new(Ssrc(0), 1000, None);
        queue.first_rtp_timestamp = Some((now, ExtendedRtpTimestamp(1000)));

        queue.push(packet(now, 1));
        queue.push(packet(now, 1));
        queue.push(packet(now, 1));
        queue.push(packet(now, 1));
        queue.push(packet(now - Duration::from_millis(100), 0));

        let pop1 = queue.poll(now).unwrap();

        assert!(matches!(
            pop1,
            RtpOutboundStreamEvent::SendRtpPacket {
                rtp_packet: RtpPacket {
                    pt: 0,
                    timestamp: RtpTimestamp(900),
                    ..
                },
                ..
            }
        ));
        for _ in 0..4 {
            assert!(matches!(
                queue.poll(now).unwrap(),
                RtpOutboundStreamEvent::SendRtpPacket {
                    rtp_packet: RtpPacket {
                        pt: 1,
                        timestamp: RtpTimestamp(1000),
                        ..
                    },
                    ..
                }
            ));
        }
    }
}
