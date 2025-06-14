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
        #[rustfmt::skip]
        let table = const { [
            // Constrained baseline
            (0x42, const { bitpattern("?1??_0000") }, Profile::ConstrainedBaseline),
            (0x4D, const { bitpattern("1???_0000") }, Profile::ConstrainedBaseline),
            (0x58, const { bitpattern("11??_0000") }, Profile::ConstrainedBaseline),
            // Baseline
            (0x42, const { bitpattern("?0??_0000") }, Profile::Baseline),
            (0x58, const { bitpattern("10??_0000") }, Profile::Baseline),
            // Main
            (0x4D, const { bitpattern("0?0?_0000") }, Profile::Main),
            // Extended
            (0x58, const { bitpattern("00??_0000") }, Profile::Extended),
            // High
            (0x64, const { bitpattern("0000_0000") }, Profile::High),
            // High10
            (0x6E, const { bitpattern("0000_0000") }, Profile::High10),
            // High422
            (0x7A, const { bitpattern("0000_0000") }, Profile::High422),
            // High444Predictive
            (0xF4, const { bitpattern("0000_0000") }, Profile::High444Predictive),
            // High10 Intra
            (0x6E, const { bitpattern("0001_0000") }, Profile::High10Intra),
            // High422 Intra
            (0x7A, const { bitpattern("0001_0000") }, Profile::High422Intra),
            // High444 Intra
            (0xF4, const { bitpattern("0001_0000") }, Profile::High444Intra),
            // CAVLC444 Intra
            (0x2C, const { bitpattern("0001_0000") }, Profile::CAVLC444Intra),
        ] };

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

const fn bitpattern(pattern: &'static str) -> impl Fn(u8) -> bool {
    let pattern_bytes = pattern.as_bytes();

    let mut ignore = 0u8;
    let mut pattern = 0u8;

    let mut index = 0;
    let mut str_index = 0;
    while index < 8 {
        match pattern_bytes[str_index] {
            b'?' => {
                ignore |= 1 << (7 - index);
                str_index += 1;
                index += 1;
            }
            b'1' => {
                pattern |= 1 << (7 - index);
                str_index += 1;
                index += 1;
            }
            b'0' => {
                str_index += 1;
                index += 1;
            }
            b'_' => {
                str_index += 1;
            }
            _ => panic!("Invalid character in bitpattern"),
        }
    }

    let mask = !ignore;

    move |input: u8| {
        let masked_input = input & mask;
        pattern == masked_input
    }
}
#[test]
fn test() {
    let pattern = const { bitpattern("0000_0?01") };

    assert!(pattern(1));
    assert!(!pattern(2));
    assert!(!pattern(3));
    assert!(!pattern(4));
    assert!(pattern(5));
    assert!(!pattern(6));
}
