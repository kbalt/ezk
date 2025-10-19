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
            Profile::Baseline => CONSTRAINT_SET0_FLAG,
            Profile::ConstrainedBaseline => CONSTRAINT_SET0_FLAG | CONSTRAINT_SET1_FLAG,
            Profile::Main => CONSTRAINT_SET1_FLAG,
            Profile::Extended => CONSTRAINT_SET2_FLAG,
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

    pub(crate) fn support_b_frames(&self) -> bool {
        match self {
            Profile::Baseline | Profile::ConstrainedBaseline => false,
            Profile::Main
            | Profile::Extended
            | Profile::High
            | Profile::High10
            | Profile::High422
            | Profile::High444Predictive
            | Profile::High10Intra
            | Profile::High422Intra
            | Profile::High444Intra
            | Profile::CAVLC444Intra => true,
        }
    }

    pub(crate) fn support_entropy_coding_mode(&self) -> bool {
        match self {
            Profile::Baseline
            | Profile::ConstrainedBaseline
            | Profile::Extended
            | Profile::CAVLC444Intra => false,
            Profile::Main
            | Profile::High
            | Profile::High10
            | Profile::High422
            | Profile::High444Predictive
            | Profile::High10Intra
            | Profile::High422Intra
            | Profile::High444Intra => true,
        }
    }

    pub(crate) fn support_transform_8x8_mode_flag(&self) -> bool {
        match self {
            Profile::Baseline
            | Profile::ConstrainedBaseline
            | Profile::Main
            | Profile::Extended => false,
            Profile::High
            | Profile::High10
            | Profile::High422
            | Profile::High444Predictive
            | Profile::High10Intra
            | Profile::High422Intra
            | Profile::High444Intra
            | Profile::CAVLC444Intra => true,
        }
    }
}
