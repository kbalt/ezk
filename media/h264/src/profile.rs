
/// H.264 encoding profile
#[derive(Debug, Clone, Copy)]
pub enum Profile {
    Baseline,
    ConstrainedBaseline,
    Main,
    Extended,
    High,
    High10,
    High422,
    High444Predictive,
    High10Intra,
    High422Intra,
    High444Intra,
    CAVLC444Intra,
}

impl Profile {
    pub fn profile_idc(self) -> u8 {
        match self {
            Profile::Baseline | Profile::ConstrainedBaseline => 66,
            Profile::Main => 77,
            Profile::Extended => 88,
            Profile::High => 100,
            Profile::High10 | Profile::High10Intra => 110,
            Profile::High422 | Profile::High422Intra => 122,
            Profile::High444Predictive | Profile::High444Intra => 244,
            Profile::CAVLC444Intra => 44,
        }
    }

    pub fn profile_iop(self) -> u8 {
        use crate::profile_iop_consts::*;

        match self {
            Profile::Baseline => 0,
            Profile::ConstrainedBaseline => CONSTRAINT_SET1_FLAG,
            Profile::Main => 0,
            Profile::Extended => 0,
            Profile::High => 0,
            Profile::High10 => 0,
            Profile::High422 => 0,
            Profile::High444Predictive => 0,
            Profile::High10Intra => CONSTRAINT_SET3_FLAG,
            Profile::High422Intra => CONSTRAINT_SET3_FLAG,
            Profile::High444Intra => CONSTRAINT_SET3_FLAG,
            Profile::CAVLC444Intra => 0,
        }
    }
}

