/// Largest representable 48 bit SRTP packet index
pub(crate) const MAX_RTP_INDEX: u64 = (1 << 48) - 1;

/// Largest representable 31 bit SRTCP index (RFC 3711 section 3.4)
pub(crate) const MAX_RTCP_INDEX: u32 = 0x7fff_ffff;

/// Per stream SRTP packet index state
///
/// SRTP carries only the low 16 bits of the 48 bit packet index on the wire, so both
/// endpoints track a rollover counter and the highest sequence number seen so far and
/// reconstruct the full index from those (RFC 3711 section 3.3.1).
#[derive(Debug, Clone, Default)]
pub(crate) struct RtpIndex {
    roc: u32,
    /// Highest sequence number processed so far, `None` until the first packet
    s_l: Option<u16>,
}

impl RtpIndex {
    /// Reconstruct the full 48 bit index of a packet with sequence number `seq`
    ///
    /// This is the estimation of RFC 3711 appendix A. It does not modify the state, so a
    /// packet that later fails authentication cannot move the rollover counter - call
    /// [`RtpIndex::commit`] only once the packet is known to be genuine.
    pub(crate) fn estimate(&self, seq: u16) -> u64 {
        let Some(s_l) = self.s_l else {
            // The first packet defines the starting point, the rollover counter is zero
            return u64::from(seq);
        };

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

    /// Rollover counter, needed for the SRTP authentication tag (RFC 3711 section 4.2)
    pub(crate) fn roc_of(index: u64) -> u32 {
        (index >> 16) as u32
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

    #[test]
    fn out_of_order_within_a_rollover_does_not_lower_the_high_water_mark() {
        let mut index = RtpIndex::default();

        index.commit(index.estimate(100));
        index.commit(index.estimate(50));

        // s_l stays at 100, so a later 101 is still in the same rollover
        assert_eq!(index.estimate(101), 101);
    }
}
