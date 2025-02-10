//! Utility functions for openh264

use crate::{profile_level_id::ProfileLevelId, FmtpOptions, Level, PacketizationMode, Profile};
use openh264_sys2::API as _;
use std::mem::MaybeUninit;

fn map_profile(profile: Profile) -> openh264::encoder::Profile {
    match profile {
        Profile::Baseline => openh264::encoder::Profile::Baseline,
        Profile::Main => openh264::encoder::Profile::Main,
        Profile::Extended => openh264::encoder::Profile::Extended,
        Profile::High => openh264::encoder::Profile::High,
        Profile::High10 => openh264::encoder::Profile::High10,
        Profile::High422 => openh264::encoder::Profile::High422,
        Profile::High444Predictive => openh264::encoder::Profile::High444,
        Profile::CAVLC444 => openh264::encoder::Profile::CAVLC444,
    }
}

fn map_level(level: Level) -> openh264::encoder::Level {
    match level {
        Level::Level_1_0 => openh264::encoder::Level::Level_1_0,
        Level::Level_1_B => openh264::encoder::Level::Level_1_B,
        Level::Level_1_1 => openh264::encoder::Level::Level_1_1,
        Level::Level_1_2 => openh264::encoder::Level::Level_1_2,
        Level::Level_1_3 => openh264::encoder::Level::Level_1_3,
        Level::Level_2_0 => openh264::encoder::Level::Level_2_0,
        Level::Level_2_1 => openh264::encoder::Level::Level_2_1,
        Level::Level_2_2 => openh264::encoder::Level::Level_2_2,
        Level::Level_3_0 => openh264::encoder::Level::Level_3_0,
        Level::Level_3_1 => openh264::encoder::Level::Level_3_1,
        Level::Level_3_2 => openh264::encoder::Level::Level_3_2,
        Level::Level_4_0 => openh264::encoder::Level::Level_4_0,
        Level::Level_4_1 => openh264::encoder::Level::Level_4_1,
        Level::Level_4_2 => openh264::encoder::Level::Level_4_2,
        Level::Level_5_0 => openh264::encoder::Level::Level_5_0,
        Level::Level_5_1 => openh264::encoder::Level::Level_5_1,
        Level::Level_5_2 => openh264::encoder::Level::Level_5_2,
        // Level 6+ is not supported by openh264 - use 5.2
        Level::Level_6_0 => openh264::encoder::Level::Level_5_2,
        Level::Level_6_1 => openh264::encoder::Level::Level_5_2,
        Level::Level_6_2 => openh264::encoder::Level::Level_5_2,
    }
}

/// Create a openh264 encoder config from the parsed [`FmtpOptions`]
pub fn openh264_encoder_config(fmtp: &FmtpOptions, mtu: u32) -> openh264::encoder::EncoderConfig {
    let mut config = openh264::encoder::EncoderConfig::new()
        .bitrate(openh264::encoder::BitRate::from_bps(fmtp.max_bitrate()))
        .profile(map_profile(fmtp.profile_level_id.profile))
        .level(map_level(fmtp.profile_level_id.level));

    match fmtp.packetization_mode {
        PacketizationMode::SingleNAL => config = config.max_slice_len(mtu),
        PacketizationMode::NonInterleavedMode | PacketizationMode::InterleavedMode => {}
    }

    config
}

/// Create [`FmtpOptions`] from openh264's decoder capabilities.
///
/// Should be used when offering to receive H.264 in a SDP negotiation.
pub fn openh264_decoder_fmtp() -> FmtpOptions {
    let capability = unsafe {
        let mut capability = MaybeUninit::uninit();

        assert_eq!(
            openh264::OpenH264API::from_source().WelsGetDecoderCapability(capability.as_mut_ptr()),
            0,
            "openh264 WelsGetDecoderCapability failed"
        );

        capability.assume_init()
    };

    FmtpOptions {
        profile_level_id: ProfileLevelId::from_bytes(
            capability.iProfileIdc as u8,
            capability.iProfileIop as u8,
            capability.iLevelIdc as u8,
        )
        .expect("openh264 should not return unknown capabilities"),
        level_asymmetry_allowed: true,
        packetization_mode: PacketizationMode::NonInterleavedMode,
        max_mbps: Some(capability.iMaxMbps as u32),
        max_fs: Some(capability.iMaxFs as u32),
        max_cbp: Some(capability.iMaxCpb as u32),
        max_dpb: Some(capability.iMaxDpb as u32),
        max_br: Some(capability.iMaxBr as u32),
        redundant_pic_cap: capability.bRedPicCap,
    }
}
