use crate::profile_level_id::{ParseProfileLevelIdError, ProfileLevelId};
use std::{fmt, num::ParseIntError, str::FromStr};

/// Specifies the RTP packetization mode
#[derive(Default, Debug, Clone, Copy, PartialEq, PartialOrd)]
pub enum H264PacketizationMode {
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
pub struct H264FmtpOptions {
    /// Indicates the profile and level used for encoding the video stream
    pub profile_level_id: ProfileLevelId,
    /// Whether level asymmetry, i.e., sending media encoded at a
    /// different level in the offerer-to-answerer direction than the
    /// level in the answerer-to-offerer direction, is allowed
    pub level_asymmetry_allowed: bool,
    /// RTP packetization mode
    pub packetization_mode: H264PacketizationMode,
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

impl H264FmtpOptions {
    /// Returns the maximum resolution for the given aspect ration
    pub fn max_resolution(&self, num: u32, denom: u32) -> (u32, u32) {
        let max_fs = self
            .max_fs
            .unwrap_or_else(|| self.profile_level_id.level.max_fs());

        resolution_from_max_fs(num, denom, max_fs)
    }

    /// Returns the maximum resolution with the given fps and aspect ratio num/denom
    pub fn max_resolution_for_fps(&self, num: u32, denom: u32, fps: u32) -> (u32, u32) {
        let max_mbps = self
            .max_mbps
            .unwrap_or_else(|| self.profile_level_id.level.max_mbps());

        let max_fs = max_mbps / fps.max(1);

        resolution_from_max_fs(num, denom, max_fs)
    }

    /// Returns the maximum supported FPS using the maximum supported resolution
    pub fn max_fps_for_max_resolution(&self) -> u32 {
        let max_fs = self
            .max_fs
            .unwrap_or_else(|| self.profile_level_id.level.max_fs());

        let max_mbps = self
            .max_mbps
            .unwrap_or_else(|| self.profile_level_id.level.max_mbps());

        max_mbps / max_fs.max(1)
    }

    /// Returns the maximum supported FPS for the given resolution
    pub fn max_fps_for_resolution(&self, width: u32, height: u32) -> u32 {
        let max_mbps = self
            .max_mbps
            .unwrap_or_else(|| self.profile_level_id.level.max_mbps());

        let frame_size = (width * height) / 256;

        max_mbps / frame_size.max(1)
    }

    /// Returns the maximum bitrate in bit/s
    pub fn max_bitrate(&self) -> u32 {
        self.max_br
            .unwrap_or_else(|| self.profile_level_id.level.max_br())
            .saturating_mul(1000)
    }
}

fn resolution_from_max_fs(num: u32, denom: u32, max_fs: u32) -> (u32, u32) {
    const MAX_FS_BOUND: u32 = 0x7FFFFF;

    fn greatest_common_divisor(mut a: u32, mut b: u32) -> u32 {
        while b != 0 {
            let tmp = b;
            b = a % b;
            a = tmp;
        }

        a
    }

    // Limit max FS to avoid integer overflows
    let max_fs = max_fs.min(MAX_FS_BOUND);
    let max_pixels = max_fs.saturating_mul(256);
    let divisor = greatest_common_divisor(num.max(1), denom.max(1));
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
pub enum ParseH264FmtpOptionsError {
    #[error(transparent)]
    InvalidProfileId(#[from] ParseProfileLevelIdError),
    #[error("encountered non integer value {0}")]
    InvalidValue(#[from] ParseIntError),
}

impl FromStr for H264FmtpOptions {
    type Err = ParseH264FmtpOptionsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut options = Self::default();

        fn parse_u32(i: &str) -> Result<u32, ParseH264FmtpOptionsError> {
            Ok(i.parse::<u32>()?.clamp(1, 8_388_607))
        }

        for (key, value) in s.split(';').filter_map(|e| e.split_once('=')) {
            let value = value.trim();
            match key {
                "profile-level-id" => options.profile_level_id = value.parse()?,
                "level-asymmetry-allowed" => options.level_asymmetry_allowed = value == "1",
                "packetization-mode" => {
                    options.packetization_mode = match value {
                        "0" => H264PacketizationMode::SingleNAL,
                        "1" => H264PacketizationMode::NonInterleavedMode,
                        "2" => H264PacketizationMode::InterleavedMode,
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

impl fmt::Display for H264FmtpOptions {
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

#[test]
fn no_panics() {
    let fmtp = H264FmtpOptions {
        profile_level_id: ProfileLevelId::default(),
        level_asymmetry_allowed: true,
        packetization_mode: H264PacketizationMode::SingleNAL,
        max_mbps: Some(u32::MAX),
        max_fs: Some(u32::MAX),
        max_cbp: Some(u32::MAX),
        max_dpb: Some(u32::MAX),
        max_br: Some(u32::MAX),
        redundant_pic_cap: false,
    };

    for i in 1..100 {
        for j in 1..100 {
            println!("{:?}", fmtp.max_resolution(i, j));
        }
    }
    println!("{:?}", fmtp.max_resolution_for_fps(16, 9, 30));
    println!("{:?}", fmtp.max_fps_for_max_resolution());
    println!("{:?}", fmtp.max_fps_for_resolution(1920, 1080));
    println!("{:?}", fmtp.max_bitrate());
}

#[test]
fn no_divide_by_zero() {
    let fmtp = H264FmtpOptions {
        profile_level_id: ProfileLevelId::default(),
        level_asymmetry_allowed: true,
        packetization_mode: H264PacketizationMode::SingleNAL,
        max_mbps: Some(0),
        max_fs: Some(0),
        max_cbp: Some(0),
        max_dpb: Some(0),
        max_br: Some(0),
        redundant_pic_cap: false,
    };

    for i in 1..100 {
        for j in 1..100 {
            println!("{:?}", fmtp.max_resolution(i, j));
        }
    }
    println!("{:?}", fmtp.max_resolution_for_fps(16, 9, 30));
    println!("{:?}", fmtp.max_fps_for_max_resolution());
    println!("{:?}", fmtp.max_fps_for_resolution(1920, 1080));
    println!("{:?}", fmtp.max_bitrate());
}
