use crate::{H264Level, H264Profile};
use std::num::NonZeroU32;

/// Generic H.264 encoder config
#[derive(Debug, Clone, Copy)]
pub struct H264EncoderConfig {
    /// H.264 encoding profile to use. Defines the feature-set the encoder may use.
    pub profile: H264Profile,

    /// H264 encoding level. Defines default constraints like frame size, fps and more.
    pub level: H264Level,

    /// Maximum width & height of the image to be encoded.
    ///
    /// This value is only used for the initialization and should represent the largest allowed resolution.
    /// Some encoders will not be able to handle larger resolutions later without being reinitialized.
    pub resolution: (u32, u32),

    /// Expected (maximum) framerate of the video stream
    pub framerate: Option<Framerate>,

    /// Define the range of QP values the encoder is allowed use.
    ///
    /// Allowed values range from 0 to 51, where 0 is the best quality and 51 the worst with the most compression.
    ///
    /// Default should be (17..=28) but manual tuning is recommended!
    ///
    /// Ignored when `rate_control` is `ConstantQuality`
    pub qp: Option<(u8, u8)>,

    /// Pattern of frames to emit
    pub frame_pattern: FramePattern,

    /// Rate control configuration
    pub rate_control: H264RateControlConfig,

    /// Limit the output slice size.
    ///
    /// Required if the packetization mode is SingleNAL which doesn't support fragmentation units.
    pub slice_max_len: Option<usize>,

    /// How slices should be created
    pub slice_mode: SliceMode,

    /// Quality level,
    pub quality_level: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum H264FrameType {
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
/// # use ezk_h264::encoder::config::{H264FrameType, H264FrameType::*, FramePattern};
/// # fn eval<const N: usize>(pattern: FramePattern) -> [H264FrameType; N] {
/// #    let mut ret = [P; N];
/// #    let mut n = 0;
/// #    while n < N {
/// #        ret[n] = pattern.frame_type_of_nth_frame(n as _);
/// #        n += 1;
/// #    }
/// #    ret
/// # }
/// // Only create I Frames
/// let pattern = FramePattern { intra_idr_period: 32, intra_period: 1, ip_period: 1 };
/// assert_eq!(eval(pattern), [Idr, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I]);
///
/// // Create I & P Frames
/// let pattern = FramePattern { intra_idr_period: 32, intra_period: 4, ip_period: 1 };
/// assert_eq!(eval(pattern), [Idr, P, P, P, I, P, P, P, I, P, P, P, I, P, P, P]);
///
/// // Insert some IDR frames, required for livestream or video conferences
/// let pattern = FramePattern { intra_idr_period: 8, intra_period: 4, ip_period: 1 };
/// assert_eq!(eval(pattern), [Idr, P, P, P, I, P, P, P, Idr, P, P, P, I, P, P, P]);
///
/// // B frames are only created if `ip_period` is larger than 1
/// let pattern = FramePattern { intra_idr_period: 32, intra_period: 8, ip_period: 4 };
/// assert_eq!(eval(pattern), [Idr, B, B, B, P, B, B, B, I, B, B, B, P, B, B, B]);
///
/// // Some more IDR frames...
/// let pattern = FramePattern { intra_idr_period: 8, intra_period: 8, ip_period: 4 };
/// assert_eq!(eval(pattern), [Idr, B, B, B, P, B, B, P, Idr, B, B, B, P, B, B]);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct FramePattern {
    /// Period in which to create IDR-Frames
    ///
    /// Must be a multiple of `i_period` (or `p_period`) if set
    pub intra_idr_period: u16,

    /// Period in which to create I-Frames
    ///
    /// Must be a multiple of `ip_period` if set
    pub intra_period: u16,

    /// Period in which to create P-Frames. All other frames are created as B-Frames
    ///
    /// B-Frames are not inserted if this is set to 1
    pub ip_period: u16,
}

impl Default for FramePattern {
    fn default() -> Self {
        Self {
            intra_idr_period: 120,
            intra_period: 60,
            ip_period: 1,
        }
    }
}

impl FramePattern {
    // public for doc test
    #[doc(hidden)]
    pub fn frame_type_of_nth_frame(&self, n: u64) -> H264FrameType {
        // Emit IDR frame every idr_period frames
        if n.is_multiple_of(self.intra_idr_period.into()) {
            return H264FrameType::Idr;
        }

        // Emit I frame every i_period frames
        if n.is_multiple_of(self.intra_period.into()) {
            return H264FrameType::I;
        }

        // Emit P frame every ip_period frames
        if n.is_multiple_of(self.ip_period.into()) {
            H264FrameType::P
        } else if (n + 1).is_multiple_of(self.intra_idr_period.into()) {
            // This should have been a B-Frame, but the next on is an IDR Frame.
            // Since B-Frames cannot be used as references for other B-Frames (yet), emit an P-Frame instead.
            H264FrameType::P
        } else {
            H264FrameType::B
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum H264RateControlConfig {
    /// CBR (Constant Bit Rate)
    ConstantBitRate { bitrate: u32 },

    /// VBR (Variable Bit Rate)
    VariableBitRate {
        average_bitrate: u32,
        max_bitrate: u32,
    },

    /// Constant Quality
    ConstantQuality {
        const_qp: u8,
        max_bitrate: Option<u32>,
    },
}

#[derive(Debug, Clone, Copy)]
pub struct Framerate {
    pub num: u32,
    pub denom: u32,
}

impl Framerate {
    pub const fn from_fps(fps: u32) -> Self {
        Self { num: fps, denom: 1 }
    }
}

/// Defines how slices should be created for a single picture
#[derive(Default, Debug, Clone, Copy)]
pub enum SliceMode {
    #[default]
    /// A single slice per picture
    Picture,

    /// Number of rows per slice
    Rows(NonZeroU32),

    /// Number of macro blocks per slice
    MacroBlocks(NonZeroU32),
}
