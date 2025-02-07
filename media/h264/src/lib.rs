#![warn(unreachable_pub)]

use profile_level_id::{ParseProfileLevelIdError, ProfileLevelId};
use std::{fmt, num::ParseIntError, str::FromStr};

mod payload;
pub mod profile_level_id;

pub use payload::{
    H264DePayloadError, H264DePayloader, H264DePayloaderOutputFormat, H264Payloader,
};

/// Specifies the RTP packetization mode
#[derive(Default, Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum PacketizationMode {
    /// Each RTP packet contains exactly one H.264 NAL unit.
    /// This mode is the default and best suited for low latency applications like video conferencing
    ///
    /// Encoders must have their NAL unit size limited to the MTU.
    #[default]
    SingleNAL = 0,

    /// Multiple NAL units can be combined into a single RTP packet.
    ///
    /// Uses fragmentation units (FU-A) to split large NAL units across multiple RTP packets
    NonInterleavedMode = 1,

    /// NAL units can be transmitted out of order and reassembled at the receiver.
    /// This mode is designed for environments with higher packet loss and jitter, providing better error resilience.
    ///
    /// Uses Fragmentation Units (FU-A and FU-B) and Aggregation Packets (STAP-B and MTAP) to manage NAL units.
    InterleavedMode = 2,
}

/// H.264 specific format parameters used in SDP negotiation
#[derive(Debug, Default)]
pub struct FmtpOptions {
    /// Indicates the profile and level used for encoding the video stream
    pub profile_level_id: ProfileLevelId,
    /// Whether level asymmetry, i.e., sending media encoded at a
    /// different level in the offerer-to-answerer direction than the
    /// level in the answerer-to-offerer direction, is allowed
    pub level_asymmetry_allowed: bool,
    /// RTP packetization mode
    pub packetization_mode: PacketizationMode,
    /// Maximum macroblock processing rate in macroblocks per second
    pub max_mbps: Option<u32>,
    /// Maximum frame size in macroblocks
    pub max_fs: Option<u32>,
    /// Maximum codec picture buffer size
    pub max_cbp: Option<u32>,
    /// Maximum decoded picture buffer size in frames
    pub max_dpb: Option<u32>,
    /// Maximum video bitrate in kilobits per second
    pub max_br: Option<u32>,
    /// Whether redundant pictures are present in the stream
    pub redundant_pic_cap: bool,
}

/// Failed to parse H.264 fmtp line
#[derive(Debug, thiserror::Error)]
pub enum ParseFmtpOptionsError {
    #[error(transparent)]
    InvalidProfileId(#[from] ParseProfileLevelIdError),
    #[error("encountered non integer value {0}")]
    InvalidValue(#[from] ParseIntError),
}

impl FromStr for FmtpOptions {
    type Err = ParseFmtpOptionsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut options = Self::default();

        for (key, value) in s.split(';').filter_map(|e| e.split_once('=')) {
            let value = value.trim();
            match key {
                "profile-level-id" => options.profile_level_id = value.parse()?,
                "level-asymmetry-allowed" => options.level_asymmetry_allowed = value == "1",
                "packetization-mode" => {
                    options.packetization_mode = match value {
                        "0" => PacketizationMode::SingleNAL,
                        "1" => PacketizationMode::NonInterleavedMode,
                        "2" => PacketizationMode::InterleavedMode,
                        _ => continue,
                    };
                }
                "max-mbps" => options.max_mbps = Some(value.parse()?),
                "max-fs" => options.max_fs = Some(value.parse()?),
                "max-cbp" => options.max_cbp = Some(value.parse()?),
                "max-dpb" => options.max_dpb = Some(value.parse()?),
                "max-br" => options.max_br = Some(value.parse()?),
                "redundant-pic-cap" => options.redundant_pic_cap = value == "1",
                _ => continue,
            }
        }

        Ok(options)
    }
}

impl fmt::Display for FmtpOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self {
            profile_level_id,
            level_asymmetry_allowed,
            packetization_mode,
            max_mbps,
            max_fs,
            max_cbp,
            max_dpb,
            max_br,
            redundant_pic_cap,
        } = self;

        write!(f, "profile-level-id={profile_level_id}")?;

        if *level_asymmetry_allowed {
            write!(f, ";level-asymmetry-allowed=1")?;
        }

        write!(f, ";packetization-mode={}", *packetization_mode as u8)?;

        if let Some(max_mbps) = max_mbps {
            write!(f, ";max-mbps={max_mbps}")?;
        }

        if let Some(max_fs) = max_fs {
            write!(f, ";max-fs={max_fs}")?;
        }

        if let Some(max_cbp) = max_cbp {
            write!(f, ";max-cbp={max_cbp}")?;
        }

        if let Some(max_dpb) = max_dpb {
            write!(f, ";max-dbp={max_dpb}")?;
        }

        if let Some(max_br) = max_br {
            write!(f, ";max-br={max_br}")?;
        }

        if *redundant_pic_cap {
            write!(f, ";redundant-pic-cap=1")?;
        }

        Ok(())
    }
}

/// H.264 encoding profile
#[derive(Debug, Clone, Copy)]
pub enum Profile {
    Baseline,
    Main,
    Extended,
    High,
    High10,
    High422,
    High444Predictive,
    CAVLC444,
}

impl Profile {
    pub fn profile_idc(self) -> u8 {
        match self {
            Profile::Baseline => 66,
            Profile::Main => 77,
            Profile::Extended => 88,
            Profile::High => 100,
            Profile::High10 => 110,
            Profile::High422 => 122,
            Profile::High444Predictive => 244,
            Profile::CAVLC444 => 44,
        }
    }
}

/// H.264 encoding levels with their corresponding capabilities.
#[derive(Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum Level {
    /// Level 1.0: Max resolution 176x144 (QCIF), 15 fps, 64 kbps (Main), 80 kbps (High)
    Level_1_0,
    /// Level 1.B: Specialized low-complexity baseline level.
    Level_1_B,
    /// Level 1.1: Max resolution 176x144 (QCIF), 30 fps, 192 kbps (Main), 240 kbps (High)
    Level_1_1,
    /// Level 1.2: Max resolution 320x240 (QVGA), 30 fps, 384 kbps (Main), 480 kbps (High)
    Level_1_2,
    /// Level 1.3: Reserved in standard, similar to Level 2.0.
    Level_1_3,
    /// Level 2.0: Max resolution 352x288 (CIF), 30 fps, 2 Mbps (Main), 2.5 Mbps (High)
    Level_2_0,
    /// Level 2.1: Max resolution 352x288 (CIF), 30 fps, 4 Mbps (Main), 5 Mbps (High)
    Level_2_1,
    /// Level 2.2: Max resolution 352x288 (CIF), 30 fps, 10 Mbps (Main), 12.5 Mbps (High)
    Level_2_2,
    /// Level 3.0: Max resolution 720x576 (SD), 30 fps, 10 Mbps (Main), 12.5 Mbps (High)
    Level_3_0,
    /// Level 3.1: Max resolution 1280x720 (HD), 30 fps, 14 Mbps (Main), 17.5 Mbps (High)
    Level_3_1,
    /// Level 3.2: Max resolution 1280x720 (HD), 60 fps, 20 Mbps (Main), 25 Mbps (High)
    Level_3_2,
    /// Level 4.0: Max resolution 1920x1080 (Full HD), 30 fps, 20 Mbps (Main), 25 Mbps (High)
    Level_4_0,
    /// Level 4.1: Max resolution 1920x1080 (Full HD), 60 fps, 50 Mbps (Main), 62.5 Mbps (High)
    Level_4_1,
    /// Level 4.2: Max resolution 1920x1080 (Full HD), 120 fps, 100 Mbps (Main), 125 Mbps (High)
    Level_4_2,
    /// Level 5.0: Max resolution 3840x2160 (4K), 30 fps, 135 Mbps (Main), 168.75 Mbps (High)
    Level_5_0,
    /// Level 5.1: Max resolution 3840x2160 (4K), 60 fps, 240 Mbps (Main), 300 Mbps (High)
    Level_5_1,
    /// Level 5.2: Max resolution 4096x2160 (4K Cinema), 60 fps, 480 Mbps (Main), 600 Mbps (High)
    Level_5_2,
    /// Level 6.0: Max resolution 8192x4320 (8K UHD), 30 fps, 240 Mbps (Main), 240 Mbps (High)
    Level_6_0,
    /// Level 6.1: Max resolution 8192x4320 (8K UHD), 60 fps, 480 Mbps (Main), 480 Mbps (High)
    Level_6_1,
    /// Level 6.2: Max resolution 8192x4320 (8K UHD), 120 fps, 800 Mbps (Main), 800 Mbps (High)
    Level_6_2,
}

impl Level {
    /// Returns the level idc as specified in H.264 for this level
    ///
    /// Note that level 1.1 & 1.b have the same value
    pub fn level_idc(self) -> u8 {
        match self {
            Level::Level_1_0 => 10,
            Level::Level_1_B => 11,
            Level::Level_1_1 => 11,
            Level::Level_1_2 => 12,
            Level::Level_1_3 => 13,
            Level::Level_2_0 => 20,
            Level::Level_2_1 => 21,
            Level::Level_2_2 => 22,
            Level::Level_3_0 => 30,
            Level::Level_3_1 => 31,
            Level::Level_3_2 => 32,
            Level::Level_4_0 => 40,
            Level::Level_4_1 => 41,
            Level::Level_4_2 => 42,
            Level::Level_5_0 => 50,
            Level::Level_5_1 => 51,
            Level::Level_5_2 => 52,
            Level::Level_6_0 => 60,
            Level::Level_6_1 => 61,
            Level::Level_6_2 => 62,
        }
    }
}
