use crate::{FmtpOptions, Level, PacketizationMode, Profile, encoder::H264EncoderCapabilities};

/// Generic H.264 encoder config
#[derive(Debug, Clone, Copy)]
pub struct H264EncoderConfig {
    /// H.264 encoding profile to use. Defines the feature-set the encoder may use.
    pub profile: Profile,

    /// H264 encoding level. Defines default constraints like frame size, fps and more.
    pub level: Level,

    /// Maximum width & height of the image to be encoded.
    ///
    /// This value is only used for the initialization and should represent to largest allowed resolution.
    /// Some encoders will not be able to handle larger resolutions later without being reinitialized.
    pub resolution: (u32, u32),

    /// Expected (maximum) framerate of the video stream
    pub framerate: Option<H264FrameRate>,

    /// Define the range of QP values the encoder is allowed use.
    ///
    /// Allowed values range from 0 to 51, where 0 is the best quality and 51 the worst with the most compression.
    ///
    /// Default should be (17..=28) but manual tuning is recommended!
    ///
    /// Ignored when `rate_control` is `ConstantQuality`
    pub qp: Option<(u8, u8)>,

    /// Pattern of frames to emit
    pub frame_pattern: H264FramePattern,

    /// Rate control configuration
    pub rate_control: H264RateControlConfig,

    /// Hint for the encoder what the H.264 stream is used for
    pub usage_hint: H264EncodeUsageHint,

    /// Hint about the video content
    pub content_hint: H264EncodeContentHint,

    /// Hint about the video encode tuning mode to use
    pub tuning_hint: H264EncodeTuningHint,

    /// Limit the output slice size.
    ///
    /// Required if the packetization mode is SingleNAL which doesn't support fragmentation units.
    pub max_slice_len: Option<usize>,

    pub max_l0_p_references: u32,
    pub max_l0_b_references: u32,
    pub max_l1_b_references: u32,

    /// Quality level from
    pub quality_level: u32,
}

impl H264EncoderConfig {
    /// Create a encoder config from the peer's H.264 decoder capabilities, communicated through SDP's fmtp attribute
    pub fn from_fmtp(capabilities: H264EncoderCapabilities, fmtp: FmtpOptions, mtu: usize) -> Self {
        H264EncoderConfig {
            profile: fmtp.profile_level_id.profile,
            level: fmtp.profile_level_id.level,
            resolution: fmtp.max_resolution(1, 1),
            framerate: None,
            qp: None,
            frame_pattern: H264FramePattern {
                intra_idr_period: 60,
                intra_period: 30,
                ip_period: 1,
            },
            rate_control: H264RateControlConfig::ConstantBitRate {
                bitrate: fmtp.max_bitrate(),
            },
            usage_hint: H264EncodeUsageHint::Default,
            content_hint: H264EncodeContentHint::Default,
            tuning_hint: H264EncodeTuningHint::Default,
            max_slice_len: {
                match fmtp.packetization_mode {
                    PacketizationMode::SingleNAL => Some(mtu),
                    PacketizationMode::NonInterleavedMode | PacketizationMode::InterleavedMode => {
                        None
                    }
                }
            },
            max_l0_p_references: capabilities.max_l0_p_references,
            max_l0_b_references: capabilities.max_l0_b_references,
            max_l1_b_references: capabilities.max_l1_b_references,
            quality_level: capabilities.max_quality_level,
        }
    }
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
pub struct H264FramePattern {
    /// Period in which to create IDR-Frames
    ///
    /// Must be a multiple of `i_period` (or `p_period`) if set
    pub intra_idr_period: u16,

    /// Period in which to create I-Frames
    ///
    /// Must be a multiple of `ip_period` if set
    pub intra_period: u16,

    /// How often to insert P-Frames, instead of B-Frames
    ///
    /// B-Frames are not inserted if this is set to `None` or `Some(1)`
    pub ip_period: u16,
}

impl Default for H264FramePattern {
    fn default() -> Self {
        Self {
            intra_idr_period: 90,
            intra_period: 30,
            ip_period: 1,
        }
    }
}

impl H264FramePattern {
    // public for doc test
    #[doc(hidden)]
    pub fn frame_type_of_nth_frame(&self, n: u32) -> H264FrameType {
        // Always start with an IDR frame
        if n == 0 {
            return H264FrameType::Idr;
        }

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
pub struct H264FrameRate {
    pub numerator: u32,
    pub denominator: u32,
}

impl H264FrameRate {
    pub const fn from_fps(fps: u32) -> Self {
        Self {
            numerator: fps,
            denominator: 1,
        }
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub enum H264EncodeUsageHint {
    #[default]
    Default,
    Transcoding,
    Streaming,
    Recording,
    Conferencing,
}

#[derive(Default, Debug, Clone, Copy)]
pub enum H264EncodeContentHint {
    #[default]
    Default,
    Camera,
    Desktop,
    Rendered,
}

#[derive(Default, Debug, Clone, Copy)]
pub enum H264EncodeTuningHint {
    #[default]
    Default,
    HighQuality,
    LowLatency,
    UltraLowLatency,
    Lossless,
}
