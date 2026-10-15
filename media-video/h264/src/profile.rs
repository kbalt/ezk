/// H.264 encoding profile
#[derive(Debug, Clone, Copy)]
pub enum H264Profile {
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

impl H264Profile {
    pub fn profile_idc(self) -> u8 {
        match self {
            H264Profile::Baseline | H264Profile::ConstrainedBaseline => 66,
            H264Profile::Main => 77,
            H264Profile::Extended => 88,
            H264Profile::High => 100,
            H264Profile::High10 | H264Profile::High10Intra => 110,
            H264Profile::High422 | H264Profile::High422Intra => 122,
            H264Profile::High444Predictive | H264Profile::High444Intra => 244,
            H264Profile::CAVLC444Intra => 44,
        }
    }

    pub fn profile_iop(self) -> u8 {
        use crate::profile_iop_consts::*;

        match self {
            H264Profile::Baseline => CONSTRAINT_SET0_FLAG,
            H264Profile::ConstrainedBaseline => CONSTRAINT_SET0_FLAG | CONSTRAINT_SET1_FLAG,
            H264Profile::Main => CONSTRAINT_SET1_FLAG,
            H264Profile::Extended => CONSTRAINT_SET2_FLAG,
            H264Profile::High => 0,
            H264Profile::High10 => 0,
            H264Profile::High422 => 0,
            H264Profile::High444Predictive => 0,
            H264Profile::High10Intra => CONSTRAINT_SET3_FLAG,
            H264Profile::High422Intra => CONSTRAINT_SET3_FLAG,
            H264Profile::High444Intra => CONSTRAINT_SET3_FLAG,
            H264Profile::CAVLC444Intra => 0,
        }
    }

    pub(crate) fn support_b_frames(&self) -> bool {
        match self {
            H264Profile::Baseline | H264Profile::ConstrainedBaseline => false,
            H264Profile::Main
            | H264Profile::Extended
            | H264Profile::High
            | H264Profile::High10
            | H264Profile::High422
            | H264Profile::High444Predictive
            | H264Profile::High10Intra
            | H264Profile::High422Intra
            | H264Profile::High444Intra
            | H264Profile::CAVLC444Intra => true,
        }
    }

    pub(crate) fn support_entropy_coding_mode(&self) -> bool {
        match self {
            H264Profile::Baseline
            | H264Profile::ConstrainedBaseline
            | H264Profile::Extended
            | H264Profile::CAVLC444Intra => false,
            H264Profile::Main
            | H264Profile::High
            | H264Profile::High10
            | H264Profile::High422
            | H264Profile::High444Predictive
            | H264Profile::High10Intra
            | H264Profile::High422Intra
            | H264Profile::High444Intra => true,
        }
    }

    pub(crate) fn support_transform_8x8_mode_flag(&self) -> bool {
        match self {
            H264Profile::Baseline
            | H264Profile::ConstrainedBaseline
            | H264Profile::Main
            | H264Profile::Extended => false,
            H264Profile::High
            | H264Profile::High10
            | H264Profile::High422
            | H264Profile::High444Predictive
            | H264Profile::High10Intra
            | H264Profile::High422Intra
            | H264Profile::High444Intra
            | H264Profile::CAVLC444Intra => true,
        }
    }
}
