#![allow(unsafe_op_in_unsafe_fn)]

pub mod encoder;

mod rtp;

pub use rtp::{AV1DePayloader, AV1Payloader};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AV1Profile {
    Main,
    High,
    Professional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[allow(non_camel_case_types)]
pub enum AV1Level {
    Level_2_0,
    Level_2_1,
    Level_2_2,
    Level_2_3,
    Level_3_0,
    Level_3_1,
    Level_3_2,
    Level_3_3,
    Level_4_0,
    Level_4_1,
    Level_4_2,
    Level_4_3,
    Level_5_0,
    Level_5_1,
    Level_5_2,
    Level_5_3,
    Level_6_0,
    Level_6_1,
    Level_6_2,
    Level_6_3,
    Level_7_0,
    Level_7_1,
    Level_7_2,
    Level_7_3,
}

#[derive(Debug, Clone, Copy)]
pub struct AV1Framerate {
    pub num: u32,
    pub denom: u32,
}

impl AV1Framerate {
    pub const fn from_fps(fps: u32) -> Self {
        Self { num: fps, denom: 1 }
    }
}
