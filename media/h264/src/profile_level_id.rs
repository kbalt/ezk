use crate::{Level, Profile};
use std::{fmt, num::ParseIntError, str::FromStr};

pub mod profile_iop_consts {
    pub const CONSTRAINT_SET0_FLAG: u8 = 1 << 7;
    pub const CONSTRAINT_SET1_FLAG: u8 = 1 << 6;
    pub const CONSTRAINT_SET2_FLAG: u8 = 1 << 5;
    pub const CONSTRAINT_SET3_FLAG: u8 = 1 << 4;
    pub const CONSTRAINT_SET4_FLAG: u8 = 1 << 3;
    pub const CONSTRAINT_SET5_FLAG: u8 = 1 << 2;
}

/// H.264 specific parameter which specifies the H.264 encoding profile and level
///
/// Represented in fmtp as 3 hex bytes e.g. (42E020)
#[derive(Debug, Clone, Copy)]
pub struct ProfileLevelId {
    pub profile: Profile,
    pub level: Level,
}

impl Default for ProfileLevelId {
    fn default() -> Self {
        Self {
            profile: Profile::Baseline,
            level: Level::Level_3_1,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProfileLevelIdFromBytesError {
    #[error("unknown profile-idc {0}")]
    UnknownProfileIdc(u8),
    #[error("unknown level-idc {0}")]
    UnknownLevelIdc(u8),
}

impl ProfileLevelId {
    pub fn from_bytes(
        profile_idc: u8,
        profile_iop: u8,
        level_idc: u8,
    ) -> Result<Self, ProfileLevelIdFromBytesError> {
        const fn bitpattern(ignore: u8, pattern: u8) -> impl Fn(u8) -> bool {
            move |input| {
                let input = input & !ignore;
                pattern == input
            }
        }

        #[rustfmt::skip]
        let table = [
            // Constrained baseline
            (0x42, bitpattern(0b1011_0000, 0b0100_0000), Profile::ConstrainedBaseline),
            (0x4D, bitpattern(0b0111_0000, 0b1000_0000), Profile::ConstrainedBaseline),
            (0x58, bitpattern(0b0011_0000, 0b1100_0000), Profile::ConstrainedBaseline),
            // Baseline
            (0x42, bitpattern(0b1011_0000, 0b0000_0000), Profile::Baseline),
            (0x58, bitpattern(0b0011_0000, 0b1000_0000), Profile::Baseline),
            // Main
            (0x4D, bitpattern(0b0101_0000, 0b0000_0000), Profile::Main),
            // Extended
            (0x58, bitpattern(0b0011_0000, 0b0000_0000), Profile::Extended),
            // High
            (0x64, bitpattern(0, 0), Profile::High),
            // High10
            (0x6E, bitpattern(0, 0), Profile::High10),
            // High422
            (0x7A, bitpattern(0, 0), Profile::High422),
            // High444Predictive
            (0xF4, bitpattern(0, 0), Profile::High444Predictive),
            // High10 Intra
            (0x6E, bitpattern(0, 0b001_0000), Profile::High10Intra),
            // High422 Intra
            (0x7A, bitpattern(0, 0b001_0000), Profile::High422Intra),
            // High444 Intra
            (0xF4, bitpattern(0, 0b001_0000), Profile::High444Intra),
            // CAVLC444 Intra
            (0x2C, bitpattern(0, 0b001_0000), Profile::CAVLC444Intra),
        ];

        let profile = table
            .iter()
            .find_map(|(p, pattern, profile)| {
                if profile_idc != *p && pattern(profile_iop) {
                    Some(*profile)
                } else {
                    None
                }
            })
            .ok_or(ProfileLevelIdFromBytesError::UnknownProfileIdc(profile_idc))?;

        let level = match level_idc {
            10 => Level::Level_1_0,
            11 => {
                if profile_iop & profile_iop_consts::CONSTRAINT_SET3_FLAG != 0 {
                    Level::Level_1_B
                } else {
                    Level::Level_1_1
                }
            }
            12 => Level::Level_1_2,
            13 => Level::Level_1_3,
            20 => Level::Level_2_0,
            21 => Level::Level_2_1,
            22 => Level::Level_2_2,
            30 => Level::Level_3_0,
            31 => Level::Level_3_1,
            32 => Level::Level_3_2,
            40 => Level::Level_4_0,
            41 => Level::Level_4_1,
            42 => Level::Level_4_2,
            50 => Level::Level_5_0,
            51 => Level::Level_5_1,
            52 => Level::Level_5_2,
            60 => Level::Level_6_0,
            61 => Level::Level_6_1,
            62 => Level::Level_6_2,
            _ => return Err(ProfileLevelIdFromBytesError::UnknownLevelIdc(level_idc)),
        };

        Ok(Self { profile, level })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ParseProfileLevelIdError {
    #[error("profile-level-id is not exactly 6 bytes")]
    InvalidLength,
    #[error("encountered invalid non-hex characters")]
    InvalidHexCharacter(#[from] ParseIntError),
    #[error(transparent)]
    InvalidValues(ProfileLevelIdFromBytesError),
}

impl FromStr for ProfileLevelId {
    type Err = ParseProfileLevelIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() != 6 {
            return Err(ParseProfileLevelIdError::InvalidLength);
        }

        let profile_idc = u8::from_str_radix(&s[..2], 16)?;
        let profile_iop = u8::from_str_radix(&s[2..4], 16)?;
        let level_idc = u8::from_str_radix(&s[4..], 16)?;

        Self::from_bytes(profile_idc, profile_iop, level_idc)
            .map_err(ParseProfileLevelIdError::InvalidValues)
    }
}

impl fmt::Display for ProfileLevelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut profile_iop = self.profile.profile_iop();

        if matches!(self.level, Level::Level_1_B) {
            profile_iop |= profile_iop_consts::CONSTRAINT_SET3_FLAG;
        }

        write!(
            f,
            "{:02X}{:02X}{:02X}",
            self.profile.profile_idc(),
            profile_iop,
            self.level.level_idc(),
        )
    }
}
