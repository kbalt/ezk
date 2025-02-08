#![warn(unreachable_pub)]

use profile_level_id::{ParseProfileLevelIdError, ProfileLevelId};
use std::{cmp::min, fmt, num::ParseIntError, str::FromStr};

pub mod openh264;
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

impl FmtpOptions {
    pub fn max_resolution(&self, num: u32, denom: u32) -> (u32, u32) {
        let max_fs = self
            .max_fs
            .unwrap_or_else(|| self.profile_level_id.level.max_fs())
            // Limit max FS to avoid integer overflows
            .min(8_388_607);

        resolution_from_max_fs(num, denom, max_fs)
    }

    pub fn max_resolution_for_fps(&self, num: u32, denom: u32, fps: u32) -> (u32, u32) {
        let max_mbps = self
            .max_mbps
            .unwrap_or_else(|| self.profile_level_id.level.max_mbps());

        let max_fs = max_mbps / fps;

        resolution_from_max_fs(num, denom, max_fs)
    }

    pub fn max_fps_for_max_resolution(&self) -> u32 {
        let max_fs = self
            .max_fs
            .unwrap_or_else(|| self.profile_level_id.level.max_fs());

        let max_mbps = self
            .max_mbps
            .unwrap_or_else(|| self.profile_level_id.level.max_mbps());

        max_mbps / max_fs
    }

    pub fn max_fps_for_resolution(&self, width: u32, height: u32) -> u32 {
        let max_mbps = self
            .max_mbps
            .unwrap_or_else(|| self.profile_level_id.level.max_mbps());

        let frame_size = (width * height) / 256;

        max_mbps / frame_size
    }

    pub fn max_bitrate(&self) -> u32 {
        self.max_br
            .unwrap_or_else(|| self.profile_level_id.level.max_br())
    }
}

fn resolution_from_max_fs(num: u32, denom: u32, max_fs: u32) -> (u32, u32) {
    fn greatest_common_divisor(mut a: u32, mut b: u32) -> u32 {
        while b != 0 {
            let tmp = b;
            b = a % b;
            a = tmp;
        }

        a
    }

    let max_pixels = max_fs.saturating_mul(256);
    let divisor = greatest_common_divisor(num, denom);
    let num = num / divisor;
    let denom = denom / divisor;

    // Search for the best resolution by testing them all
    for i in 1.. {
        let width = num * i;
        let height = denom * i;

        if width * height > max_pixels {
            let width = num * (i - 1);
            let height = denom * (i - 1);
            return (width, height);
        }
    }

    unreachable!()
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

        fn parse_u32(i: &str) -> Result<u32, ParseFmtpOptionsError> {
            Ok(i.parse::<u32>()?.clamp(1, 8_388_607))
        }

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
                "max-mbps" => options.max_mbps = Some(parse_u32(value)?),
                "max-fs" => options.max_fs = Some(parse_u32(value)?),
                "max-cbp" => options.max_cbp = Some(parse_u32(value)?),
                "max-dpb" => options.max_dpb = Some(parse_u32(value)?),
                "max-br" => options.max_br = Some(parse_u32(value)?),
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

    fn max_mbps(self) -> u32 {
        self.limits().0
    }

    fn max_fs(self) -> u32 {
        self.limits().1
    }

    fn max_br(self) -> u32 {
        self.limits().3
    }

    /// ITU-T H.264 Table A-1 Level Limits
    ///
    /// 0 - Max macroblock processing rate MaxMBPS (MB/s)
    /// 1 - Max frame size MaxFS (MBs)
    /// 2 - Max decoded picture buffer size MaxDpbMbs (MBs)
    /// 3 - Max video bit rate MaxBR (1000 bits/s, 1200 bits/s, cpbBrVclFactor bits/s, or cpbBrNalFactor bits/s)
    /// 4 - Max CPB size MaxCPB (1000 bits, 1200 bits, cpbBrVclFactor bits, or cpbBrNalFactor bits)
    /// 5 - Vertical MV component limit MaxVmvR (luma frame samples)
    /// 6 - Min compression ratio MinCR
    /// 7 - Max number of motion vectors per two consecutive MBs MaxMvsPer2Mb
    fn limits(self) -> (u32, u32, u32, u32, u32, u32, u32, Option<u32>) {
        match self {
            Level::Level_1_0 => (1485, 99, 396, 64, 175, 64, 2, None),
            Level::Level_1_B => (1485, 99, 396, 128, 350, 64, 2, None),
            Level::Level_1_1 => (3000, 396, 900, 192, 500, 128, 2, None),
            Level::Level_1_2 => (6000, 396, 2376, 384, 1000, 128, 2, None),
            Level::Level_1_3 => (11880, 396, 2376, 768, 2000, 128, 2, None),
            Level::Level_2_0 => (11880, 396, 2376, 2000, 2000, 128, 2, None),
            Level::Level_2_1 => (19800, 792, 4752, 4000, 4000, 256, 2, None),
            Level::Level_2_2 => (20250, 1620, 8100, 4000, 4000, 256, 2, None),
            Level::Level_3_0 => (40500, 1620, 8100, 10000, 10000, 256, 2, Some(32)),
            Level::Level_3_1 => (108000, 3600, 18000, 14000, 14000, 512, 4, Some(16)),
            Level::Level_3_2 => (216000, 5120, 20480, 20000, 20000, 512, 4, Some(16)),
            Level::Level_4_0 => (245760, 8192, 32768, 20000, 25000, 512, 4, Some(16)),
            Level::Level_4_1 => (245760, 8192, 32768, 50000, 62500, 512, 2, Some(16)),
            Level::Level_4_2 => (522240, 8704, 34816, 50000, 62500, 512, 2, Some(16)),
            Level::Level_5_0 => (589824, 22080, 110400, 135000, 135000, 512, 2, Some(16)),
            Level::Level_5_1 => (983040, 36864, 184320, 240000, 240000, 512, 2, Some(16)),
            Level::Level_5_2 => (2073600, 36864, 184320, 240000, 240000, 512, 2, Some(16)),
            Level::Level_6_0 => (4177920, 139264, 696320, 240000, 240000, 8192, 2, Some(16)),
            Level::Level_6_1 => (8355840, 139264, 696320, 480000, 480000, 8192, 2, Some(16)),
            Level::Level_6_2 => (16711680, 139264, 696320, 800000, 800000, 8192, 2, Some(16)),
        }
    }
}
