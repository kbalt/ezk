use std::{
    collections::{BTreeMap, VecDeque},
    time::{Duration, Instant},
};

use rtp::{
    RtpPacket,
    rtcp_types::{RtcpPacket, TransportFeedback, Twcc, TwccBuilder, TwccPacketStatus},
};
use time::ext::InstantExt;

use crate::{Mtu, rtp_session::ReportsQueue};

/// Maximum size of the `sent_packets` queue
const SENT_PACKETS_MAX_SIZE: Duration = Duration::from_secs(3);

/// Sender side transport-cc state
///
/// Maintains a list of sent packets and consumed transport-cc RTCP feedback
pub(super) struct TwccTxState {
    /// Base time used to calculate deltas from `sent_at` timestamp
    base_time: Instant,

    /// Last feedback packet sequence number received. Used to detect feedback packet loss.
    last_feedback_count: Option<u8>,

    /// Transport wide sequence number to assign the next outbound RTP packet
    next_sequence_number: u16,

    /// List of all sent RTP packets with their planned send timestamp and payload size
    // sent_packets: VecDeque<SentPacket>,
    sent_packets: BTreeMap<u16, SentPacket>,
}

struct SentPacket {
    sequence_number: u16,
    sent_at: Instant,
    size: usize,
    status: Option<SentPacketStatus>,
}

#[derive(Clone, Copy)]
enum SentPacketStatus {
    Lost,
    ReceivedAt(Duration),
}

impl TwccTxState {
    pub(super) fn new() -> TwccTxState {
        TwccTxState {
            base_time: Instant::now(),
            last_feedback_count: None,
            next_sequence_number: 0,
            sent_packets: BTreeMap::new(),
        }
    }

    /// Add a packet which is about to be sent
    pub(super) fn send_packet(&mut self, now: Instant, packet: &mut RtpPacket) {
        packet.extensions.twcc_sequence_number = Some(self.next_sequence_number);

        self.sent_packets.insert(
            self.next_sequence_number,
            SentPacket {
                sequence_number: self.next_sequence_number,
                sent_at: now,
                size: packet.payload.len(),
                status: None,
            },
        );

        self.next_sequence_number = self.next_sequence_number.wrapping_add(1);
    }

    /// Receive transport-cc RTCP feedback
    pub(super) fn receive_feedback(&mut self, now: Instant, feedback: Twcc<'_>) {
        if let Some(last_feedback_count) = self.last_feedback_count
            && feedback.feedback_packet_count() != last_feedback_count.wrapping_add(1)
        {
            log::debug!(
                "Expected twcc feedback count (sequence number) {}, got {}",
                last_feedback_count.wrapping_add(1),
                feedback.feedback_packet_count(),
            );
        }

        self.last_feedback_count = Some(feedback.feedback_packet_count());

        let mut reference_time = feedback.reference_time() as i64 * 64000;
        for result in feedback.packets() {
            let (sequence_number, status) = match result {
                Ok((sequence_number, status)) => (sequence_number, status),
                Err(e) => {
                    log::warn!("Got invalid TWCC packet status {e}");
                    break;
                }
            };

            let Some(sent_packet) = self.sent_packets.get_mut(&sequence_number) else {
                continue;
            };

            match status {
                TwccPacketStatus::NotReceived => {
                    sent_packet.status = Some(SentPacketStatus::Lost);
                }
                TwccPacketStatus::Received { delta } => {
                    reference_time += i64::from(delta) * 250;

                    let received_at =
                        Duration::from_micros(reference_time.abs().try_into().unwrap());

                    sent_packet.status = Some(SentPacketStatus::ReceivedAt(received_at));
                }
            }
        }

        self.sent_packets
            .retain(|_, sent_packet| sent_packet.sent_at > now - SENT_PACKETS_MAX_SIZE);

        self.evaluate();
    }

    // TODO: this function is currently purely cosmetic and just prints some information
    fn evaluate(&self) {
        if self.sent_packets.len() < 2 {
            return;
        }

        let mut lost = 0;

        let (min_seq, _) = self
            .sent_packets
            .iter()
            .min_by_key(|(_, x)| x.sent_at)
            .unwrap();

        let (max_seq, _) = self
            .sent_packets
            .iter()
            .max_by_key(|(_, x)| x.sent_at)
            .unwrap();

        let mut seq = *min_seq;

        while seq != *max_seq {
            let next_seq = seq.wrapping_add(1);

            let lhs = self.sent_packets.get(&seq).unwrap();
            let rhs = self.sent_packets.get(&next_seq).unwrap();

            seq = next_seq;

            let lhs_sent_at = lhs
                .sent_at
                .checked_duration_since(self.base_time)
                .unwrap()
                .as_micros()
                .next_multiple_of(250) as i64;
            let lhs_arrival = match lhs.status {
                Some(SentPacketStatus::ReceivedAt(lhs_arrival)) => lhs_arrival.as_micros() as i64,
                Some(SentPacketStatus::Lost) => {
                    lost += 1;
                    continue;
                }
                None => {
                    continue;
                }
            };

            let rhs_sent_at = rhs
                .sent_at
                .checked_duration_since(self.base_time)
                .unwrap()
                .as_micros()
                .next_multiple_of(250) as i64;
            let rhs_arrival = match rhs.status {
                Some(SentPacketStatus::ReceivedAt(rhs_arrival)) => rhs_arrival.as_micros() as i64,
                Some(SentPacketStatus::Lost) => {
                    continue;
                }
                None => {
                    continue;
                }
            };

            let lhs_d = lhs_arrival - lhs_sent_at;
            let rhs_d = rhs_arrival - rhs_sent_at;

            let d = lhs_d - rhs_d;

            {
                //TODO: doesn't really need a loop. The delta can be cached in SentPacket and the lowest delta can be stored globally with an index/seq and updated when needed?
                let d_min = self
                    .sent_packets
                    .iter()
                    .filter(|(_, sent_packet)| sent_packet.sent_at < lhs.sent_at)
                    .filter_map(|(_, sent_packet)| match sent_packet.status? {
                        SentPacketStatus::Lost => None,
                        SentPacketStatus::ReceivedAt(duration) => Some(
                            sent_packet
                                .sent_at
                                .duration_since(self.base_time)
                                .as_micros() as i64
                                - duration.as_micros() as i64,
                        ),
                    })
                    .min();

                let q = if let Some(d_min) = d_min {
                    (lhs_arrival - lhs_sent_at) - d_min
                } else {
                    i64::MIN
                };

                log::trace!(
                    "sequence_number: {:5?} | sent_at: {lhs_sent_at:12?} | arrival: {lhs_arrival:?} | lhs_d: {lhs_d:} | rhs_d: {rhs_d:} | d: {d:8?} | q: {q:8?}",
                    lhs.sequence_number
                );
            }
        }

        let Some(min) = self
            .sent_packets
            .values()
            .find(|x| x.status.is_some())
            .map(|x| x.sent_at)
        else {
            return;
        };

        let Some(max) = self
            .sent_packets
            .values()
            .rev()
            .find(|x| x.status.is_some())
            .map(|x| x.sent_at)
        else {
            return;
        };

        let dur = max - min;

        let recv_size: usize = self
            .sent_packets
            .values()
            .filter_map(|x| match x.status? {
                SentPacketStatus::Lost => None,
                SentPacketStatus::ReceivedAt(..) => Some(x.size),
            })
            .sum();

        let send_size: usize = self
            .sent_packets
            .values()
            .filter_map(|x| {
                x.status?;
                Some(x.size)
            })
            .sum();

        log::debug!(
            "lost: {lost} {}%   window: {dur:?}  bitrate: tx: {:.2}kb/s  rrx: {:.2}kb/s",
            ((lost as f64 / self.sent_packets.len() as f64) * 100.0) as u32,
            (send_size as f64 / dur.as_secs_f64()) / 1000.0 * 8.0,
            (recv_size as f64 / dur.as_secs_f64()) / 1000.0 * 8.0,
        );
    }
}

/// Receiver side transport-cc state
///
/// Inspects received RTP packets and periodically emits RTCP transport-cc feedback packets
pub(super) struct TwccRxState {
    base_time: Instant,
    last_report_sent: Instant,
    report_interval: Duration,

    received_packet_times: VecDeque<(u16, Instant)>,
    last_reported_sequence: Option<u16>,

    feedback_packet_count: u8,
}

impl TwccRxState {
    pub(super) fn new() -> TwccRxState {
        TwccRxState {
            base_time: Instant::now() - Duration::from_millis(64),
            last_report_sent: Instant::now(),
            report_interval: Duration::from_millis(500),
            received_packet_times: VecDeque::new(),
            last_reported_sequence: None,
            feedback_packet_count: 0,
        }
    }

    /// RTP packets are expected to be received deduplicated and reordered with the the original reception timestamp
    pub(super) fn receive_packet(&mut self, received_at: Instant, packet: &RtpPacket) {
        if let Some(sequence_number) = packet.extensions.twcc_sequence_number {
            self.received_packet_times
                .push_back((sequence_number, received_at));
        }
    }

    pub(super) fn timeout(&self, now: Instant) -> Option<Duration> {
        if self.received_packet_times.is_empty() {
            None
        } else {
            Some((self.last_report_sent + self.report_interval).saturating_duration_since(now))
        }
    }

    pub(super) fn poll_reports(&mut self, now: Instant, mtu: Mtu, reports: &mut ReportsQueue) {
        if self.received_packet_times.is_empty()
            || now.saturating_duration_since(self.last_report_sent) < self.report_interval
        {
            return;
        }

        self.last_report_sent = now;

        while !self.received_packet_times.is_empty() {
            let &(first_seq, first_ts) = self.received_packet_times.front().unwrap();
            let min_seq = if let Some(last_reported_sequence) = self.last_reported_sequence {
                last_reported_sequence.wrapping_add(1)
            } else {
                first_seq
            };

            // Align the timestamp to the previous 64ms step
            let first_ts = first_ts.duration_since(self.base_time).as_millis();
            let first_ts_millis = (first_ts / 64) * 64;
            let first_ts = self.base_time + Duration::from_millis(first_ts_millis as u64);

            let status_list = self.drain_status_list(first_ts);
            let mut status_list = &status_list[..];

            let mut base_seq = min_seq;
            while !status_list.is_empty() {
                let twcc_builder = TwccBuilder::new(
                    base_seq,
                    (first_ts_millis / 64) as u32,
                    self.feedback_packet_count,
                    status_list,
                    Some(mtu.for_rtcp_packets() - TransportFeedback::MIN_PACKET_LEN),
                );
                let consumed = twcc_builder.packet_status_count();

                // Write out RTCP packet
                reports.add_transport_feedback(TransportFeedback::builder_owned(twcc_builder));

                // Update feedback packet sequence number
                self.feedback_packet_count = self.feedback_packet_count.wrapping_add(1);

                // Update base sequence number for next feedback packet (if not all status entries have been consumed)
                base_seq = base_seq.wrapping_add(consumed as u16);

                // update status list
                status_list = &status_list[consumed..];
            }
        }
    }

    fn drain_status_list(&mut self, mut previous_received_at: Instant) -> Vec<TwccPacketStatus> {
        let mut status_list = vec![];

        while let Some((sequence_number, received_at)) = self.received_packet_times.pop_front() {
            if let Some(prev_seq) = self.last_reported_sequence {
                for _ in 0..sequence_number.wrapping_sub(prev_seq.wrapping_add(1)) {
                    status_list.push(TwccPacketStatus::NotReceived);
                }
            }

            // Deltas are reported as multiple of 250us. To avoid accumulating error when calculating deltas to previous
            // packets, find the multiple of 250us and put that back as previous timestamp
            let delta = received_at
                .signed_duration_since(previous_received_at)
                .whole_microseconds()
                / 250;

            if delta.is_positive() {
                previous_received_at += Duration::from_micros((delta.unsigned_abs() * 250) as u64);
            } else {
                previous_received_at -= Duration::from_micros((delta.unsigned_abs() * 250) as u64);
            }

            match delta.try_into() {
                Ok(delta) => {
                    status_list.push(TwccPacketStatus::Received { delta });
                }
                Err(_) => {
                    // Delta too large, reinsert and end the current packet
                    self.received_packet_times
                        .push_front((sequence_number, received_at));
                    break;
                }
            }

            self.last_reported_sequence = Some(sequence_number);
        }

        status_list
    }
}
