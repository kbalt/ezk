//! H.264 tools for use with SDP & RTP

#![allow(unsafe_op_in_unsafe_fn)]

mod fmtp;
mod level;
mod payload;
mod profile;
pub mod profile_level_id;

pub mod encoder;

pub use fmtp::{H264FmtpOptions, H264PacketizationMode, ParseH264FmtpOptionsError};
pub use level::H264Level;
pub use payload::{
    H264DePayloadError, H264DePayloader, H264DePayloaderOutputFormat, H264Payloader,
};
pub use profile::H264Profile;

mod profile_iop_consts {
    #![allow(unused)]

    pub(crate) const CONSTRAINT_SET0_FLAG: u8 = 1 << 7;
    pub(crate) const CONSTRAINT_SET1_FLAG: u8 = 1 << 6;
    pub(crate) const CONSTRAINT_SET2_FLAG: u8 = 1 << 5;
    pub(crate) const CONSTRAINT_SET3_FLAG: u8 = 1 << 4;
    pub(crate) const CONSTRAINT_SET4_FLAG: u8 = 1 << 3;
    pub(crate) const CONSTRAINT_SET5_FLAG: u8 = 1 << 2;
}
