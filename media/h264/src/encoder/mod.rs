use crate::{
    Level, Profile,
    fmtp::{FmtpOptions, PacketizationMode},
};

pub mod libva;
#[cfg(feature = "openh264")]
pub mod openh264;

mod frame_pattern;

pub use frame_pattern::{FramePattern, FrameType};

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

/// Generic H.264 encoder config
#[derive(Debug, Clone, Copy)]
pub struct H264EncoderConfig {
    /// H.264 encoding profile to use. Defines the feature-set the encoder may use.
    pub profile: Profile,

    /// H264 encoding level. Defines default constraints like frame size, fps and more.
    pub level: Level,

    /// width & height of the image to be encoded.
    ///
    /// This value is only used for the initialization and should represent to largest allowed resolution.
    /// Some encoders will not be able to handle larger resolutions later without being reinitialized.
    pub resolution: (u32, u32),

    /// Define the range of QP values the encoder is allowed use.
    ///
    /// Allowed values range from 0 to 51, where 0 is the best quality and 51 the worst with the most compression.
    ///
    /// Default is (17..=28) but manual tuning is recommended!
    pub qp: Option<(u32, u32)>,

    /// Pattern of frames to emit
    pub frame_pattern: FramePattern,

    /// Target bitrate in bits/s
    pub bitrate: Option<u32>,

    /// Override the level's maximum bitrate in bits/s
    pub max_bitrate: Option<u32>,

    /// Limit the output slice size.
    ///
    /// Required if the packetization mode is SingleNAL which doesn't support fragmentation units.
    pub max_slice_len: Option<usize>,
}

impl H264EncoderConfig {
    /// Create a encoder config from the peer's H.264 decoder capabilities, communicated through SDP's fmtp attribute
    pub fn from_fmtp(fmtp: FmtpOptions, mtu: usize) -> Self {
        Self {
            profile: fmtp.profile_level_id.profile,
            level: fmtp.profile_level_id.level,
            resolution: fmtp.max_resolution(1, 1),
            qp: None,
            frame_pattern: FramePattern {
                intra_idr_period: 60,
                intra_period: 30,
                ip_period: 1,
            },
            bitrate: None,
            max_bitrate: Some(fmtp.max_bitrate()),
            max_slice_len: {
                match fmtp.packetization_mode {
                    PacketizationMode::SingleNAL => Some(mtu),
                    PacketizationMode::NonInterleavedMode | PacketizationMode::InterleavedMode => {
                        None
                    }
                }
            },
        }
    }
}
