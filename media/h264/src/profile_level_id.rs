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
    pub profile_iop: u8,
    pub level: Level,
}

impl Default for ProfileLevelId {
    fn default() -> Self {
        Self {
            profile: Profile::Baseline,
            profile_iop: 0,
            level: Level::Level_1_0,
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
        let profile = match profile_idc {
            66 => Profile::Baseline,
            77 => Profile::Main,
            88 => Profile::Extended,
            100 => Profile::High,
            110 => Profile::High10,
            122 => Profile::High422,
            244 => Profile::High444Predictive,
            44 => Profile::CAVLC444,
            _ => return Err(ProfileLevelIdFromBytesError::UnknownProfileIdc(profile_iop)),
        };

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

        Ok(Self {
            profile,
            profile_iop,
            level,
        })
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
        let mut profile_iop = self.profile_iop;

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
