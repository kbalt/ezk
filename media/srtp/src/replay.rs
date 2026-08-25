use crate::SrtpError;

/// Default replay window size in packets, matching libsrtp
pub(crate) const DEFAULT_WINDOW: u16 = 128;

/// Smallest replay window a caller may ask for (RFC 3711 section 3.3.2)
pub(crate) const MIN_WINDOW: u16 = 64;

/// Largest replay window a caller may ask for
///
/// The index estimation of RFC 3711 appendix A only reaches half the sequence number
/// space in either direction, so a wider window can never be filled by a genuine packet.
pub(crate) const MAX_WINDOW: u16 = 32768;

/// Sliding window replay protection (RFC 3711 section 3.3.2)
///
/// Tracks which packet indices at or below the highest seen index have already been
/// processed. Bit 0 of the bitmap is the highest seen index, bit `n` is `latest - n`.
#[derive(Debug, Clone)]
pub(crate) struct ReplayWindow {
    /// Highest index that has been added, meaningless while `empty` is true
    latest: u64,
    /// One bit per index at or below `latest`
    bitmap: Vec<u64>,
    empty: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        ReplayWindow::new(DEFAULT_WINDOW)
    }
}

impl ReplayWindow {
    /// Create a window covering at least `packets` indices
    ///
    /// The bitmap is made of 64 bit words, so `packets` is rounded up to a multiple of 64.
    pub(crate) fn new(packets: u16) -> Self {
        let words = usize::from(packets).div_ceil(64).max(1);

        Self {
            latest: 0,
            bitmap: vec![0; words],
            empty: true,
        }
    }

    /// Number of indices the window covers
    fn size(&self) -> u64 {
        (self.bitmap.len() * 64) as u64
    }

    /// Check whether `index` may still be processed
    ///
    /// Call this before decrypting, and [`ReplayWindow::add`] only once the packet has
    /// been authenticated, so a forged packet cannot lock out the genuine one.
    pub(crate) fn check(&self, index: u64) -> Result<(), SrtpError> {
        if self.empty || index > self.latest {
            return Ok(());
        }

        let delta = self.latest - index;

        if delta >= self.size() {
            return Err(SrtpError::ReplayOld);
        }

        if self.is_set(delta as usize) {
            return Err(SrtpError::ReplayFail);
        }

        Ok(())
    }

    /// Record `index` as processed
    pub(crate) fn add(&mut self, index: u64) {
        if self.empty {
            self.empty = false;
            self.latest = index;
            self.set(0);
            return;
        }

        if index > self.latest {
            let shift = index - self.latest;
            self.shift_up(shift);
            self.latest = index;
            self.set(0);
        } else {
            let delta = self.latest - index;
            if delta < self.size() {
                self.set(delta as usize);
            }
        }
    }

    fn is_set(&self, bit: usize) -> bool {
        self.bitmap[bit / 64] & (1 << (bit % 64)) != 0
    }

    fn set(&mut self, bit: usize) {
        self.bitmap[bit / 64] |= 1 << (bit % 64);
    }

    /// Move every recorded index `n` bits further from the newest slot
    fn shift_up(&mut self, n: u64) {
        let total = self.size();

        if n >= total {
            self.bitmap.fill(0);
            return;
        }

        let n = n as usize;
        let words = n / 64;
        let bits = n % 64;

        if bits == 0 {
            for i in (words..self.bitmap.len()).rev() {
                self.bitmap[i] = self.bitmap[i - words];
            }
        } else {
            for i in (words..self.bitmap.len()).rev() {
                let low = self.bitmap[i - words] << bits;
                let carry = if i > words {
                    self.bitmap[i - words - 1] >> (64 - bits)
                } else {
                    0
                };
                self.bitmap[i] = low | carry;
            }
        }

        self.bitmap[..words].fill(0);
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn accepts_then_rejects_the_same_index() {
        let mut w = ReplayWindow::new(128);

        assert_eq!(w.check(100), Ok(()));
        w.add(100);
        assert_eq!(w.check(100), Err(SrtpError::ReplayFail));
    }

    #[test]
    fn accepts_out_of_order_within_the_window() {
        let mut w = ReplayWindow::new(128);

        w.add(200);
        for index in 150..200 {
            assert_eq!(w.check(index), Ok(()), "index {index}");
            w.add(index);
            assert_eq!(w.check(index), Err(SrtpError::ReplayFail));
        }
    }

    #[test]
    fn rejects_indices_below_the_window() {
        let mut w = ReplayWindow::new(128);

        w.add(1000);
        assert_eq!(w.check(1000 - 128), Err(SrtpError::ReplayOld));
        assert_eq!(w.check(0), Err(SrtpError::ReplayOld));
        assert_eq!(w.check(1000 - 127), Ok(()));
    }

    #[test]
    fn sliding_the_window_keeps_recorded_indices() {
        let mut w = ReplayWindow::new(128);

        w.add(10);
        w.add(11);
        // Slide by 100, both stay inside the 128 index window
        w.add(111);

        assert_eq!(w.check(10), Err(SrtpError::ReplayFail));
        assert_eq!(w.check(11), Err(SrtpError::ReplayFail));
        assert_eq!(w.check(111), Err(SrtpError::ReplayFail));
        assert_eq!(w.check(12), Ok(()));
    }

    #[test]
    fn sliding_past_the_window_clears_it() {
        let mut w = ReplayWindow::new(128);

        w.add(10);
        w.add(10_000);

        assert_eq!(w.check(10), Err(SrtpError::ReplayOld));
        assert_eq!(w.check(10_000), Err(SrtpError::ReplayFail));
    }

    #[test]
    fn the_window_covers_exactly_the_requested_number_of_packets() {
        for packets in [64u16, 128, 192, 1024, 32768] {
            let mut w = ReplayWindow::new(packets);
            assert_eq!(w.size(), u64::from(packets), "window of {packets}");

            let latest = 1_000_000;
            w.add(latest);

            let oldest_inside = latest - (u64::from(packets) - 1);
            assert_eq!(w.check(oldest_inside), Ok(()), "window of {packets}");
            assert_eq!(
                w.check(oldest_inside - 1),
                Err(SrtpError::ReplayOld),
                "window of {packets}"
            );
        }
    }

    #[test]
    fn a_window_is_rounded_up_to_a_whole_word() {
        assert_eq!(ReplayWindow::new(1).size(), 64);
        assert_eq!(ReplayWindow::new(63).size(), 64);
        assert_eq!(ReplayWindow::new(65).size(), 128);
        // Zero must not produce an empty bitmap, which would panic on indexing
        assert_eq!(ReplayWindow::new(0).size(), 64);
        assert_eq!(ReplayWindow::new(0).check(0), Ok(()));
    }

    #[test]
    fn the_default_window_matches_libsrtp() {
        assert_eq!(ReplayWindow::default().size(), u64::from(DEFAULT_WINDOW));
        assert_eq!(DEFAULT_WINDOW, 128);
    }

    #[test]
    fn shift_across_a_word_boundary() {
        let mut w = ReplayWindow::new(128);

        w.add(0);
        // Bit 0 becomes bit 70, which lives in the second word
        w.add(70);

        assert_eq!(w.check(0), Err(SrtpError::ReplayFail));
        assert_eq!(w.check(70), Err(SrtpError::ReplayFail));
        assert_eq!(w.check(1), Ok(()));
        assert_eq!(w.check(69), Ok(()));
    }
}
