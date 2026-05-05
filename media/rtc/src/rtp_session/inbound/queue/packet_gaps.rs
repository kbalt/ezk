use crate::{
    opt_min,
    rtp::{ExtendedSequenceNumber, SequenceNumber},
};
use rtcp_types::NackBuilder;
use std::{
    cmp::Ordering,
    collections::VecDeque,
    time::{Duration, Instant},
};

const MAX_GAP_SIZE: u64 = 1000;

/// Tracks not-received packets
pub(super) struct PacketGaps {
    gaps: VecDeque<Gap>,
    highest_received: Option<ExtendedSequenceNumber>,
}

struct Gap {
    sequence_number: ExtendedSequenceNumber,
    detected_at: Instant,
    // (timestamp of NACK request, how many nacks have been sent)
    nacked_at: Option<(Instant, u32)>,
}

impl PacketGaps {
    pub(super) fn new() -> PacketGaps {
        PacketGaps {
            gaps: VecDeque::new(),
            highest_received: None,
        }
    }

    /// Returns true if the given sequence number is currently tracked as a missing gap.
    pub(super) fn contains(&self, sequence_number: ExtendedSequenceNumber) -> bool {
        self.gaps
            .iter()
            .any(|g| g.sequence_number == sequence_number)
    }

    pub(super) fn report_received(
        &mut self,
        sequence_number: ExtendedSequenceNumber,
        received_at: Instant,
    ) {
        let Some(highest_received) = self.highest_received else {
            self.highest_received = Some(sequence_number);
            return;
        };

        match sequence_number.cmp(&highest_received) {
            Ordering::Less => {
                if let Some(pos) = self
                    .gaps
                    .iter()
                    .position(|g| g.sequence_number == sequence_number)
                {
                    self.gaps.remove(pos);
                }
            }
            Ordering::Equal => {
                // Got the same sequence number twice, will be ignored
            }
            Ordering::Greater => {
                self.highest_received = Some(sequence_number);

                let gap = sequence_number.0 - highest_received.0;

                if gap > MAX_GAP_SIZE {
                    // Reset state here
                    self.gaps.clear();
                    self.highest_received = Some(sequence_number);
                    return;
                }

                for i in 1..gap {
                    let sequence_number = ExtendedSequenceNumber(highest_received.0 + i);

                    self.gaps.push_back(Gap {
                        sequence_number,
                        detected_at: received_at,
                        nacked_at: None,
                    });
                }
            }
        }
    }

    /// Report that a RTX packet with the given sequence number was received
    ///
    /// Returns the rtt from NACK sent to `received_at`, if only NACKed once
    pub(super) fn report_rtx_received(
        &mut self,
        sequence_number: ExtendedSequenceNumber,
        received_at: Instant,
    ) -> (bool, Option<Duration>) {
        let Some(pos) = self
            .gaps
            .iter()
            .position(|g| g.sequence_number == sequence_number)
        else {
            return (false, None);
        };

        let gap = self.gaps.remove(pos).expect("pos is valid");

        let rtt = gap
            .nacked_at
            .filter(|(_, count)| *count == 1)
            .map(|(nacked_at, _)| received_at - nacked_at);

        (true, rtt)
    }

    /// Generate a NACK for all gaps that are ready to be NACKed
    pub(super) fn poll_nacks(
        &mut self,
        now: Instant,
        initial_delay: Duration,
        resend_delay: Duration,
    ) -> Option<NackBuilder> {
        let mut nack = Some(NackBuilder::default());
        let mut empty = true;

        self.poll_nacks_inner(now, initial_delay, resend_delay, |seq| {
            empty = false;

            nack = Some(
                nack.take()
                    .expect("nack is always Some")
                    .add_rtp_sequence(seq.0),
            );
        });

        if empty { None } else { nack }
    }

    fn poll_nacks_inner<'a>(
        &mut self,
        now: Instant,
        initial_delay: Duration,
        resend_delay: Duration,
        mut add_seq: impl FnMut(SequenceNumber) + 'a,
    ) {
        for gap in &mut self.gaps {
            // Don't immediately NACK, wait at least initial_delay
            if gap.nacked_at.is_none() && gap.detected_at + initial_delay > now {
                continue;
            }

            // Wait resend_delay before sending NACK again
            if let Some((nacked_at, _)) = gap.nacked_at
                && nacked_at + resend_delay > now
            {
                continue;
            }

            match &mut gap.nacked_at {
                Some((nacked_at, n)) => {
                    *nacked_at = now;
                    *n += 1;
                }
                None => gap.nacked_at = Some((now, 1)),
            }

            add_seq(gap.sequence_number.truncated());
        }
    }

    /// Calculate the next time `poll_nacks` should be called
    pub(super) fn timeout_nacks(
        &self,
        now: Instant,
        initial_delay: Duration,
        resend_delay: Duration,
    ) -> Option<Duration> {
        let mut timeout = None;

        for gap in &self.gaps {
            let (delay, ts) = match gap.nacked_at {
                Some((nacked_at, _)) => (resend_delay, nacked_at),
                None => (initial_delay, gap.detected_at),
            };

            timeout = opt_min(timeout, Some((ts + delay).saturating_duration_since(now)));
        }

        timeout
    }

    /// Remove all gaps with sequence numbers below `seq`, returns the number of removed gaps
    ///
    /// Calls `on_drain` for each removed gap with its sequence number and nack state.
    pub(super) fn drain_below(
        &mut self,
        seq: ExtendedSequenceNumber,
        mut on_drain: impl FnMut(ExtendedSequenceNumber, Option<(Instant, u32)>),
    ) -> u64 {
        let mut count = 0;

        while let Some(gap) = self.gaps.front() {
            if gap.sequence_number >= seq {
                break;
            }

            let gap = self.gaps.pop_front().unwrap();
            on_drain(gap.sequence_number, gap.nacked_at);
            count += 1;
        }

        count
    }

    /// Remove gaps that have exceeded the maximum number of NACK attempts, returns the number of lost packets
    pub(super) fn drain_lost(&mut self, max_nack_attempts: u32) -> u64 {
        let mut lost = 0;

        while let Some(gap) = self.gaps.front() {
            let exceeded = gap
                .nacked_at
                .is_some_and(|(_, count)| count >= max_nack_attempts);

            if !exceeded {
                break;
            }

            self.gaps.pop_front();
            lost += 1;
        }

        lost
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const INITIAL_DELAY: Duration = Duration::from_millis(5);
    const RESEND_DELAY: Duration = Duration::from_millis(50);

    fn seq(n: u64) -> ExtendedSequenceNumber {
        ExtendedSequenceNumber(n)
    }

    /// Collect NACKed sequence numbers as raw u16 values
    fn poll_nacks_collect(
        pg: &mut PacketGaps,
        now: Instant,
        initial_delay: Duration,
        resend_delay: Duration,
    ) -> Vec<u16> {
        let mut seqs = Vec::new();
        pg.poll_nacks_inner(now, initial_delay, resend_delay, |s| seqs.push(s.0));
        seqs
    }

    #[test]
    fn first_packet_sets_highest() {
        let mut pg = PacketGaps::new();
        let now = Instant::now();

        pg.report_received(seq(100), now);

        assert_eq!(pg.highest_received, Some(seq(100)));
        assert_eq!(pg.gaps.len(), 0);
    }

    #[test]
    fn consecutive_packets_no_gaps() {
        let mut pg = PacketGaps::new();
        let now = Instant::now();

        pg.report_received(seq(1), now);
        pg.report_received(seq(2), now);
        pg.report_received(seq(3), now);

        assert_eq!(pg.gaps.len(), 0);
        assert_eq!(pg.highest_received, Some(seq(3)));
    }

    #[test]
    fn skipped_packet_creates_gap() {
        let mut pg = PacketGaps::new();
        let now = Instant::now();

        pg.report_received(seq(1), now);
        pg.report_received(seq(3), now);

        assert_eq!(pg.gaps.len(), 1);
        assert_eq!(pg.gaps[0].sequence_number, seq(2));
    }

    #[test]
    fn large_skip_creates_multiple_gaps() {
        let mut pg = PacketGaps::new();
        let now = Instant::now();

        pg.report_received(seq(1), now);
        pg.report_received(seq(6), now);

        assert_eq!(pg.gaps.len(), 4);
        for (i, gap) in pg.gaps.iter().enumerate() {
            assert_eq!(gap.sequence_number, seq(2 + i as u64));
        }
    }

    #[test]
    fn duplicate_packet_ignored() {
        let mut pg = PacketGaps::new();
        let now = Instant::now();

        pg.report_received(seq(1), now);
        pg.report_received(seq(3), now);
        let gaps_before = pg.gaps.len();

        pg.report_received(seq(3), now);

        assert_eq!(pg.gaps.len(), gaps_before);
        assert_eq!(pg.highest_received, Some(seq(3)));
    }

    #[test]
    fn late_packet_resolves_gap() {
        let mut pg = PacketGaps::new();
        let now = Instant::now();

        pg.report_received(seq(1), now);
        pg.report_received(seq(4), now);

        assert_eq!(pg.gaps.len(), 2);

        pg.report_received(seq(2), now);
        assert_eq!(pg.gaps.len(), 1);
        assert_eq!(pg.gaps[0].sequence_number, seq(3));

        pg.report_received(seq(3), now);
        assert_eq!(pg.gaps.len(), 0);
    }

    #[test]
    fn late_packet_not_in_gaps_is_no_op() {
        let mut pg = PacketGaps::new();
        let now = Instant::now();

        pg.report_received(seq(1), now);
        pg.report_received(seq(3), now);

        // Receiving seq(1) again (already received, less than highest but not in gaps)
        pg.report_received(seq(1), now);
        assert_eq!(pg.gaps.len(), 1);
    }

    #[test]
    fn gap_exceeding_max_resets_state() {
        let mut pg = PacketGaps::new();
        let now = Instant::now();

        pg.report_received(seq(1), now);
        pg.report_received(seq(3), now);

        // Jump beyond MAX_GAP_SIZE
        pg.report_received(seq(MAX_GAP_SIZE + 100), now);

        assert_eq!(pg.gaps.len(), 0);
        assert_eq!(pg.highest_received, Some(seq(MAX_GAP_SIZE + 100)));
    }

    #[test]
    fn nacks_multiple_gaps() {
        let mut pg = PacketGaps::new();
        let t0 = Instant::now();

        pg.report_received(seq(1), t0);
        pg.report_received(seq(5), t0);

        let nacked = poll_nacks_collect(&mut pg, t0 + INITIAL_DELAY, INITIAL_DELAY, RESEND_DELAY);
        assert_eq!(nacked, vec![2, 3, 4]);
    }

    #[test]
    fn nacks_only_pending_after_partial_resolve() {
        let mut pg = PacketGaps::new();
        let t0 = Instant::now();

        pg.report_received(seq(1), t0);
        pg.report_received(seq(5), t0);

        // First NACK all three
        let t1 = t0 + INITIAL_DELAY;
        let nacked = poll_nacks_collect(&mut pg, t1, INITIAL_DELAY, RESEND_DELAY);
        assert_eq!(nacked, vec![2, 3, 4]);

        // Resolve gap 3 via late arrival
        pg.report_received(seq(3), t1);

        // Resend NACK — only 2 and 4 remain
        let t2 = t1 + RESEND_DELAY;
        let nacked = poll_nacks_collect(&mut pg, t2, INITIAL_DELAY, RESEND_DELAY);
        assert_eq!(nacked, vec![2, 4]);
    }

    #[test]
    fn rtx_resolves_gap_and_returns_rtt() {
        let mut pg = PacketGaps::new();
        let t0 = Instant::now();
        let t1 = t0 + Duration::from_millis(10);
        let t2 = t0 + Duration::from_millis(30);

        pg.report_received(seq(1), t0);
        pg.report_received(seq(3), t0);

        // NACK it once
        pg.poll_nacks(t1, Duration::ZERO, RESEND_DELAY);

        // RTX arrives
        let (removed_gap, rtt) = pg.report_rtx_received(seq(2), t2);
        assert!(removed_gap && rtt.is_some());
        // RTT should be ~20ms (t2 - t1)
        let rtt = rtt.unwrap();
        assert!(rtt >= Duration::from_millis(19) && rtt <= Duration::from_millis(21));
        assert_eq!(pg.gaps.len(), 0);
    }

    #[test]
    fn rtx_no_rtt_if_nacked_multiple_times() {
        let mut pg = PacketGaps::new();
        let t0 = Instant::now();

        pg.report_received(seq(1), t0);
        pg.report_received(seq(3), t0);

        // NACK twice
        pg.poll_nacks(
            t0 + Duration::from_millis(10),
            Duration::ZERO,
            Duration::ZERO,
        );
        pg.poll_nacks(
            t0 + Duration::from_millis(20),
            Duration::ZERO,
            Duration::ZERO,
        );

        let (removed_gap, rtt) = pg.report_rtx_received(seq(2), t0 + Duration::from_millis(30));
        // Should be None because nack count > 1
        assert!(removed_gap && rtt.is_none());
    }

    #[test]
    fn rtx_unknown_seq_returns_none() {
        let mut pg = PacketGaps::new();
        let now = Instant::now();

        pg.report_received(seq(1), now);
        pg.report_received(seq(3), now);

        let (removed_gap, rtt) = pg.report_rtx_received(seq(99), now);
        assert!(!removed_gap && rtt.is_none());
        assert_eq!(pg.gaps.len(), 1); // gap 2 still there
    }

    #[test]
    fn no_nacks_when_no_gaps() {
        let mut pg = PacketGaps::new();
        let now = Instant::now();

        pg.report_received(seq(1), now);
        pg.report_received(seq(2), now);

        let nacked = poll_nacks_collect(&mut pg, now, INITIAL_DELAY, RESEND_DELAY);
        assert!(nacked.is_empty());
    }

    #[test]
    fn nack_not_sent_before_initial_delay() {
        let mut pg = PacketGaps::new();
        let t0 = Instant::now();

        pg.report_received(seq(1), t0);
        pg.report_received(seq(3), t0);
        // Before initial delay: no NACK
        let nacked = poll_nacks_collect(
            &mut pg,
            t0 + Duration::from_millis(2),
            INITIAL_DELAY,
            RESEND_DELAY,
        );
        assert!(nacked.is_empty());

        // After initial delay: NACK for seq 2
        let nacked = poll_nacks_collect(&mut pg, t0 + INITIAL_DELAY, INITIAL_DELAY, RESEND_DELAY);
        assert_eq!(nacked, vec![2]);
    }

    #[test]
    fn nack_resend_respects_resend_delay() {
        let mut pg = PacketGaps::new();
        let t0 = Instant::now();

        pg.report_received(seq(1), t0);
        pg.report_received(seq(3), t0);

        // First NACK
        let t1 = t0 + INITIAL_DELAY;
        let nacked = poll_nacks_collect(&mut pg, t1, INITIAL_DELAY, RESEND_DELAY);
        assert_eq!(nacked, vec![2]);

        // Too soon for resend
        let t2 = t1 + Duration::from_millis(10);
        let nacked = poll_nacks_collect(&mut pg, t2, INITIAL_DELAY, RESEND_DELAY);
        assert!(nacked.is_empty());

        // After resend delay
        let t3 = t1 + RESEND_DELAY;
        let nacked = poll_nacks_collect(&mut pg, t3, INITIAL_DELAY, RESEND_DELAY);
        assert_eq!(nacked, vec![2]);
    }

    #[test]
    fn timeout_none_without_gaps() {
        let pg = PacketGaps::new();
        let now = Instant::now();
        assert!(pg.timeout_nacks(now, INITIAL_DELAY, RESEND_DELAY).is_none());
    }

    #[test]
    fn timeout_returns_initial_delay_for_new_gap() {
        let mut pg = PacketGaps::new();
        let t0 = Instant::now();

        pg.report_received(seq(1), t0);
        pg.report_received(seq(3), t0);

        let timeout = pg.timeout_nacks(t0, INITIAL_DELAY, RESEND_DELAY).unwrap();
        assert_eq!(timeout, INITIAL_DELAY);
    }

    #[test]
    fn timeout_returns_resend_delay_after_nack() {
        let mut pg = PacketGaps::new();
        let t0 = Instant::now();

        pg.report_received(seq(1), t0);
        pg.report_received(seq(3), t0);

        // NACK at t1
        let t1 = t0 + INITIAL_DELAY;
        pg.poll_nacks(t1, INITIAL_DELAY, RESEND_DELAY);

        let timeout = pg.timeout_nacks(t1, INITIAL_DELAY, RESEND_DELAY).unwrap();
        assert_eq!(timeout, RESEND_DELAY);
    }

    #[test]
    fn drain_lost_removes_fully_nacked_gaps() {
        let mut pg = PacketGaps::new();
        let t0 = Instant::now();

        pg.report_received(seq(1), t0);
        pg.report_received(seq(4), t0);

        // NACK 3 times with zero delays
        for i in 0..3 {
            let t = t0 + Duration::from_millis(10 * (i + 1));
            pg.poll_nacks(t, Duration::ZERO, Duration::ZERO);
        }

        let lost = pg.drain_lost(3);
        assert_eq!(lost, 2);
        assert_eq!(pg.gaps.len(), 0);
    }

    #[test]
    fn drain_lost_stops_at_non_exhausted_gap() {
        let mut pg = PacketGaps::new();
        let t0 = Instant::now();

        pg.report_received(seq(1), t0);
        pg.report_received(seq(4), t0);

        // NACK both gaps twice (zero delays so both get NACKed each call)
        pg.poll_nacks(
            t0 + Duration::from_millis(1),
            Duration::ZERO,
            Duration::ZERO,
        );
        pg.poll_nacks(
            t0 + Duration::from_millis(2),
            Duration::ZERO,
            Duration::ZERO,
        );

        // Both have nack_count=2, max_nack_attempts=3 → neither drains
        assert_eq!(pg.drain_lost(3), 0);
        assert_eq!(pg.gaps.len(), 2);

        // Resolve gap 3 via late arrival, leaving only gap 2
        pg.report_received(seq(3), t0 + Duration::from_millis(3));
        assert_eq!(pg.gaps.len(), 1);

        // Third NACK on gap 2
        pg.poll_nacks(
            t0 + Duration::from_millis(3),
            Duration::ZERO,
            Duration::ZERO,
        );

        // Gap 2 has 3 nacks → drains. Gap 3 was already resolved.
        assert_eq!(pg.drain_lost(3), 1);
        assert_eq!(pg.gaps.len(), 0);
    }
}
