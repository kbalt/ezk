/// Largest representable 48 bit SRTP packet index
pub(crate) const MAX_RTP_INDEX: u64 = (1 << 48) - 1;

/// Half the sequence number space, the point the index estimation pivots around
const SEQ_NUM_MEDIAN: u64 = 0x8000;

/// Largest representable 31 bit SRTCP index (RFC 3711 section 3.4)
pub(crate) const MAX_RTCP_INDEX: u32 = 0x7fff_ffff;

/// How much of the index space has to be left before a master key counts as expiring
pub(crate) const KEY_SOFT_LIMIT: u64 = 0x1_0000;

/// Per stream SRTP packet index state
///
/// SRTP carries only the low 16 bits of the 48 bit packet index on the wire, so the full
/// index is reconstructed from a rollover counter and the highest sequence number seen so
/// far (RFC 3711 section 3.3.1).
#[derive(Debug, Clone, Default)]
pub(crate) struct RtpIndex {
    roc: u32,
    /// Highest sequence number processed so far, `None` until the first packet
    s_l: Option<u16>,
}

impl RtpIndex {
    /// Reconstruct the full 48 bit index of a packet with sequence number `seq`
    /// (RFC 3711 appendix A)
    ///
    /// Does not modify the state; call [`RtpIndex::commit`] only once the packet is known
    /// to be genuine.
    pub(crate) fn estimate(&self, seq: u16) -> u64 {
        let Some(s_l) = self.s_l else {
            // The first packet defines the starting point, the rollover counter is zero
            return u64::from(seq);
        };

        // While the stored index is still at or below the pivot the estimation below can
        // pick `ROC - 1` and underflow the rollover counter to 0xffffffff, putting the
        // packet at the very top of the index space.
        if (u64::from(self.roc) << 16) | u64::from(s_l) <= SEQ_NUM_MEDIAN {
            return u64::from(seq);
        }

        let seq_i = i32::from(seq);
        let s_l_i = i32::from(s_l);

        let v = if s_l < 32768 {
            if seq_i - s_l_i > 32768 {
                self.roc.wrapping_sub(1)
            } else {
                self.roc
            }
        } else if s_l_i - 32768 > seq_i {
            self.roc.wrapping_add(1)
        } else {
            self.roc
        };

        (u64::from(v) << 16) | u64::from(seq)
    }

    /// Advance the state to account for a processed packet
    pub(crate) fn commit(&mut self, index: u64) {
        let v = (index >> 16) as u32;
        let seq = index as u16;

        match self.s_l {
            None => {
                self.roc = v;
                self.s_l = Some(seq);
            }
            Some(s_l) => {
                if v == self.roc {
                    if seq > s_l {
                        self.s_l = Some(seq);
                    }
                } else if v == self.roc.wrapping_add(1) {
                    self.roc = v;
                    self.s_l = Some(seq);
                }
                // A packet from a previous rollover leaves the state alone
            }
        }
    }

    /// Rollover counter part of a full packet index
    pub(crate) fn roc_of(index: u64) -> u32 {
        (index >> 16) as u32
    }

    /// Full index of the highest packet processed so far, zero before the first packet
    pub(crate) fn current(&self) -> u64 {
        match self.s_l {
            Some(s_l) => (u64::from(self.roc) << 16) | u64::from(s_l),
            None => 0,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn first_packet_starts_at_its_sequence_number() {
        let index = RtpIndex::default();
        assert_eq!(index.estimate(0), 0);

        let index = RtpIndex::default();
        assert_eq!(index.estimate(1234), 1234);
    }

    #[test]
    fn wraparound_increments_the_rollover_counter() {
        let mut index = RtpIndex::default();

        for seq in [65534u16, 65535] {
            let i = index.estimate(seq);
            assert_eq!(i, u64::from(seq), "seq {seq}");
            index.commit(i);
        }

        for (seq, expected) in [(0u16, 65536u64), (1, 65537), (2, 65538)] {
            let i = index.estimate(seq);
            assert_eq!(i, expected, "seq {seq}");
            index.commit(i);
        }

        assert_eq!(RtpIndex::roc_of(index.estimate(3)), 1);
    }

    #[test]
    fn reordered_packet_across_the_wrap_keeps_the_old_rollover_counter() {
        let mut index = RtpIndex::default();

        index.commit(index.estimate(65534));
        let wrapped = index.estimate(1);
        index.commit(wrapped);
        assert_eq!(wrapped, 65537);

        // 65535 arrives late, it belongs to the previous rollover
        assert_eq!(index.estimate(65535), 65535);
    }

    /// A forward jump of more than half the sequence number space, while the stored index
    /// is still low, must not borrow from a zero rollover counter
    #[test]
    fn low_index_forward_jump_keeps_the_rollover_counter_at_zero() {
        let mut index = RtpIndex::default();
        index.commit(index.estimate(1000));

        // 40000 - 1000 is more than 32768, which tips the estimation into picking ROC - 1
        assert_eq!(index.estimate(40000), 40000);
        assert_eq!(RtpIndex::roc_of(index.estimate(40000)), 0);

        // The same holds right at the edge of the guard
        let mut index = RtpIndex::default();
        index.commit(index.estimate(32768));
        assert_eq!(index.estimate(65535), 65535);
    }

    #[test]
    fn the_guard_stops_applying_above_the_pivot() {
        let mut index = RtpIndex::default();
        index.commit(index.estimate(32769));

        // A sequence number far behind now belongs to the next rollover
        assert_eq!(index.estimate(0), 65536);
        assert_eq!(RtpIndex::roc_of(index.estimate(0)), 1);
    }

    #[test]
    fn estimates_never_leave_the_48_bit_index_space() {
        for s_l in [0u16, 1, 1000, 32767, 32768, 32769, 65534, 65535] {
            let mut index = RtpIndex::default();
            index.commit(index.estimate(s_l));

            for seq in [0u16, 1, 1000, 32767, 32768, 32769, 65534, 65535] {
                let estimated = index.estimate(seq);
                assert!(
                    estimated <= MAX_RTP_INDEX,
                    "s_l {s_l} seq {seq} estimated {estimated:#x}"
                );
            }
        }
    }

    #[test]
    fn current_reports_the_highest_index_processed() {
        let mut index = RtpIndex::default();
        assert_eq!(index.current(), 0);

        index.commit(index.estimate(40000));
        assert_eq!(index.current(), 40000);

        for seq in [65535u16, 0, 1] {
            index.commit(index.estimate(seq));
        }
        assert_eq!(index.current(), 65537);
    }

    #[test]
    fn out_of_order_within_a_rollover_does_not_lower_the_high_water_mark() {
        let mut index = RtpIndex::default();

        index.commit(index.estimate(100));
        index.commit(index.estimate(50));

        // s_l stays at 100, so a later 101 is still in the same rollover
        assert_eq!(index.estimate(101), 101);
    }
}
