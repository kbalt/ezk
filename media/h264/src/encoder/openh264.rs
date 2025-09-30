//! Utility functions for openh264

use super::H264EncoderConfig;
use crate::{
    FmtpOptions, Level, PacketizationMode, Profile,
    encoder::{H264FrameRate, H264RateControlConfig},
    profile_level_id::ProfileLevelId,
};
use openh264::encoder::{BitRate, FrameRate, IntraFramePeriod, QpRange, RateControlMode};
use openh264_sys2::API as _;
use std::mem::MaybeUninit;

fn map_profile(profile: Profile) -> openh264::encoder::Profile {
    use Profile::*;

    match profile {
        ConstrainedBaseline | Baseline => openh264::encoder::Profile::Baseline,
        Main => openh264::encoder::Profile::Main,
        Extended => openh264::encoder::Profile::Extended,
        High => openh264::encoder::Profile::High,
        High10 | High10Intra => openh264::encoder::Profile::High10,
        High422 | High422Intra => openh264::encoder::Profile::High422,
        High444Predictive | High444Intra => openh264::encoder::Profile::High444,
        CAVLC444Intra => openh264::encoder::Profile::CAVLC444,
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
pub fn openh264_encoder_config(c: H264EncoderConfig) -> openh264::encoder::EncoderConfig {
    let mut config = openh264::encoder::EncoderConfig::new()
        .profile(map_profile(c.profile))
        .level(map_level(c.level));

    if let Some(H264FrameRate {
        numerator,
        denominator,
    }) = c.framerate
    {
        config = config.max_frame_rate(FrameRate::from_hz(numerator as f32 / denominator as f32));
    }

    if let Some((qmin, qmax)) = c.qp {
        config = config.qp(QpRange::new(qmin, qmax));
    }

    config = config.intra_frame_period(IntraFramePeriod::from_num_frames(
        c.frame_pattern.intra_idr_period,
    ));

    match c.rate_control {
        H264RateControlConfig::ConstantBitRate { bitrate } => {
            config = config
                .rate_control_mode(RateControlMode::Bitrate)
                .bitrate(BitRate::from_bps(bitrate));
        }
        H264RateControlConfig::VariableBitRate {
            average_bitrate,
            max_bitrate,
        } => {
            // TODO: make the distinction between max & target bitrate in openh264
            let _ = average_bitrate;
            config = config
                .rate_control_mode(RateControlMode::Bitrate)
                .bitrate(BitRate::from_bps(max_bitrate));
        }
        H264RateControlConfig::ConstantQuality {
            const_qp,
            max_bitrate,
        } => {
            config = config
                .rate_control_mode(RateControlMode::Quality)
                .qp(QpRange::new(const_qp, const_qp));

            if let Some(max_bitrate) = max_bitrate {
                config = config.bitrate(BitRate::from_bps(max_bitrate));
            }
        }
    }

    if let Some(max_slice_len) = c.max_slice_len {
        config = config.max_slice_len(max_slice_len as u32);
    }

    config
}

/// Create [`FmtpOptions`] from openh264's decoder capabilities.
///
/// Should be used when offering to receive H.264 in a SDP negotiation.
pub fn openh264_decoder_fmtp(api: &openh264::OpenH264API) -> FmtpOptions {
    let capability = unsafe {
        let mut capability = MaybeUninit::uninit();

        assert_eq!(
            api.WelsGetDecoderCapability(capability.as_mut_ptr()),
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
