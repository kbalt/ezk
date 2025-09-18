#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameType {
    // Uses previous frames as reference
    P,
    // Uses previous and future frames as reference
    B,
    // Intra frame, standalone complete picture, no references
    I,
    // Intra Frame preceded by a SPS/PPS set. Clears all reference frames
    Idr,
}

/// Describes the pattern in which frames are created
///
/// # Examples
///
/// ```rust
/// # use ezk_h264::encoder::{FrameType, FrameType::*, FrameTypePattern};
/// # fn eval<const N: usize>(pattern: FrameTypePattern) -> [FrameType; N] {
/// #    let mut ret = [P; N];
/// #    let mut n = 0;
/// #    while n < N {
/// #        ret[n] = pattern.frame_type_of_nth_frame(n as _);
/// #        n += 1;
/// #    }
/// #    ret
/// # }
/// // Only create I Frames
/// let pattern = FrameTypePattern { intra_idr_period: 32, intra_period: 1, ip_period: 1 };
/// assert_eq!(eval(pattern), [Idr, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I]);
///
/// // Create I & P Frames
/// let pattern = FrameTypePattern { intra_idr_period: 32, intra_period: 4, ip_period: 1 };
/// assert_eq!(eval(pattern), [Idr, P, P, P, I, P, P, P, I, P, P, P, I, P, P, P]);
///
/// // Insert some IDR frames, required for livestream or video conferences
/// let pattern = FrameTypePattern { intra_idr_period: 8, intra_period: 4, ip_period: 1 };
/// assert_eq!(eval(pattern), [Idr, P, P, P, I, P, P, P, Idr, P, P, P, I, P, P, P]);
///
/// // B frames are only created if `p_period` is specified
/// let pattern = FrameTypePattern { intra_idr_period: 32, intra_period: 8, ip_period: 4 };
/// assert_eq!(eval(pattern), [Idr, B, B, B, P, B, B, B, I, B, B, B, P, B, B, B]);
///
/// // B frames are only created if `p_period` is specified
/// let pattern = FrameTypePattern { intra_idr_period: 8, intra_period: 8, ip_period: 4 };
/// assert_eq!(eval(pattern), [Idr, B, B, B, P, B, B, P, Idr, B, B, B, P, B, B]);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct FramePattern {
    /// Period in which to create IDR-Frames
    ///
    /// Must be a multiple of `i_period` (or `p_period`) if set
    pub intra_idr_period: u32,

    /// Period in which to create I-Frames
    ///
    /// Must be a multiple of `ip_period` if set
    pub intra_period: u32,

    /// How often to insert P-Frames, instead of B-Frames
    ///
    /// B-Frames are not inserted if this is set to `None` or `Some(1)`
    pub ip_period: u32,
}

impl FramePattern {
    // public for doc test
    #[doc(hidden)]
    pub const fn frame_type_of_nth_frame(&self, n: u32) -> FrameType {
        // Always start with an IDR frame
        if n == 0 {
            return FrameType::Idr;
        }

        // Emit IDR frame every idr_period frames
        if n.is_multiple_of(self.intra_idr_period) {
            return FrameType::Idr;
        }

        // Emit I frame every i_period frames
        if n.is_multiple_of(self.intra_period) {
            return FrameType::I;
        }

        // Emit P frame every ip_period frames
        if n.is_multiple_of(self.ip_period) {
            FrameType::P
        } else if (n + 1).is_multiple_of(self.intra_idr_period) {
            // This should have been a B-Frame, but the next on is an IDR Frame.
            // Since B-Frames cannot be used as references for other B-Frames (yet), emit an P-Frame instead.
            FrameType::P
        } else {
            FrameType::B
        }
    }
}
