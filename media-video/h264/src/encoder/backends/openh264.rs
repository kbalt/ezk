//! Utility functions for openh264

use crate::{
    H264FmtpOptions, H264PacketizationMode, Level, Profile,
    encoder::config::{Framerate, H264EncoderConfig, H264RateControlConfig},
    profile_level_id::ProfileLevelId,
};
use ezk_image::{
    ColorInfo, ColorSpace, Image, ImageRef, ImageRefExt, PixelFormat, YuvColorInfo,
    convert_multi_thread,
};
use openh264::{
    encoder::{BitRate, Encoder, FrameRate, IntraFramePeriod, QpRange, RateControlMode},
    formats::YUVSlices,
};
use openh264_sys2::API as _;
use std::{collections::VecDeque, mem::MaybeUninit, time::Instant};

pub struct OpenH264Encoder {
    encoder: Encoder,
    scratch: Vec<u8>,
    output: VecDeque<Vec<u8>>,
    init: Option<Instant>,
}

impl OpenH264Encoder {
    pub fn new(config: H264EncoderConfig) -> Result<Self, openh264::Error> {
        let config = openh264_encoder_config(config);

        let encoder = Encoder::with_api_config(openh264::OpenH264API::from_source(), config)?;

        Ok(OpenH264Encoder {
            encoder,
            scratch: Vec::new(),
            output: VecDeque::new(),
            init: None,
        })
    }

    pub fn request_idr(&mut self) {
        self.encoder.force_intra_frame();
    }

    pub fn encode_frame(&mut self, image: &dyn ImageRef) -> Result<(), openh264::Error> {
        let init = self.init.get_or_insert_with(Instant::now);
        let timestamp = openh264::Timestamp::from_millis(init.elapsed().as_millis() as u64);

        let image = image.crop_even().map_err(|e| {
            openh264::Error::msg_string(format!(
                "Failed to crop input image to an even resolution: {e:?}"
            ))
        })?;

        let bitstream = if image.format() == PixelFormat::I420 {
            let mut planes = image.planes();

            let (y_plane, y_stride) = planes
                .next()
                .ok_or_else(|| openh264::Error::msg("Missing Y plane"))?;
            let (u_plane, u_stride) = planes
                .next()
                .ok_or_else(|| openh264::Error::msg("Missing U plane"))?;
            let (v_plane, v_stride) = planes
                .next()
                .ok_or_else(|| openh264::Error::msg("Missing V plane"))?;

            let input = YUVSlices::new(
                (y_plane, u_plane, v_plane),
                (image.width(), image.height()),
                (y_stride, u_stride, v_stride),
            );

            self.encoder.encode_at(&input, timestamp)?
        } else {
            self.scratch.resize(
                PixelFormat::I420.buffer_size(image.width(), image.height()),
                0,
            );

            let dst_color = match image.color() {
                ColorInfo::RGB(rgb_color_info) => YuvColorInfo {
                    transfer: rgb_color_info.transfer,
                    primaries: rgb_color_info.primaries,
                    space: ColorSpace::BT709,
                    full_range: true,
                },
                ColorInfo::YUV(yuv_color_info) => yuv_color_info,
            };

            let mut dst = Image::from_buffer(
                PixelFormat::I420,
                self.scratch.as_mut_slice(),
                None,
                image.width(),
                image.height(),
                dst_color.into(),
            )
            .map_err(|e| {
                openh264::Error::msg_string(format!(
                    "Failed to create convert destination image: {e:?}"
                ))
            })?;

            convert_multi_thread(&image, &mut dst).map_err(|e| {
                openh264::Error::msg_string(format!("Failed to convert input image to I420: {e:?}"))
            })?;

            let mut planes = dst.planes();

            let (y_plane, y_stride) = planes
                .next()
                .ok_or_else(|| openh264::Error::msg("Missing Y plane"))?;
            let (u_plane, u_stride) = planes
                .next()
                .ok_or_else(|| openh264::Error::msg("Missing U plane"))?;
            let (v_plane, v_stride) = planes
                .next()
                .ok_or_else(|| openh264::Error::msg("Missing V plane"))?;

            let input = YUVSlices::new(
                (y_plane, u_plane, v_plane),
                (image.width(), image.height()),
                (y_stride, u_stride, v_stride),
            );

            self.encoder.encode_at(&input, timestamp)?
        };

        match bitstream.frame_type() {
            openh264::encoder::FrameType::Invalid
            | openh264::encoder::FrameType::Skip
            | openh264::encoder::FrameType::IPMixed => {
                println!("Got invalid frame type: {:?}", bitstream.frame_type());
                return Ok(());
            }
            openh264::encoder::FrameType::IDR => {}
            openh264::encoder::FrameType::I => {}
            openh264::encoder::FrameType::P => {}
        }

        self.output.push_back(bitstream.to_vec());

        Ok(())
    }

    pub fn poll_result(&mut self) -> Option<Vec<u8>> {
        self.output.pop_front()
    }

    pub fn wait_result(&mut self) -> Option<Vec<u8>> {
        self.output.pop_front()
    }
}

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
fn openh264_encoder_config(c: H264EncoderConfig) -> openh264::encoder::EncoderConfig {
    let mut config = openh264::encoder::EncoderConfig::new()
        .profile(map_profile(c.profile))
        .level(map_level(c.level));

    if let Some(Framerate { num, denom }) = c.framerate {
        config = config.max_frame_rate(FrameRate::from_hz(num as f32 / denom as f32));
    }

    if let Some((qmin, qmax)) = c.qp {
        config = config.qp(QpRange::new(qmin, qmax));
    }

    config = config.intra_frame_period(IntraFramePeriod::from_num_frames(
        c.frame_pattern.intra_idr_period.into(),
    ));

    match c.rate_control {
        H264RateControlConfig::ConstantBitRate { bitrate } => {
            config = config
                .rate_control_mode(RateControlMode::Quality)
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

    if let Some(max_slice_len) = c.slice_max_len {
        config = config.max_slice_len(max_slice_len as u32);
    }

    config
}

/// Create [`FmtpOptions`] from openh264's decoder capabilities.
///
/// Should be used when offering to receive H.264 in a SDP negotiation.
pub fn openh264_decoder_fmtp(api: &openh264::OpenH264API) -> H264FmtpOptions {
    let capability = unsafe {
        let mut capability = MaybeUninit::uninit();

        assert_eq!(
            api.WelsGetDecoderCapability(capability.as_mut_ptr()),
            0,
            "openh264 WelsGetDecoderCapability failed"
        );

        capability.assume_init()
    };

    H264FmtpOptions {
        profile_level_id: ProfileLevelId::from_bytes(
            capability.iProfileIdc as u8,
            capability.iProfileIop as u8,
            capability.iLevelIdc as u8,
        )
        .expect("openh264 should not return unknown capabilities"),
        level_asymmetry_allowed: true,
        packetization_mode: H264PacketizationMode::NonInterleavedMode,
        max_mbps: Some(capability.iMaxMbps as u32),
        max_fs: Some(capability.iMaxFs as u32),
        max_cbp: Some(capability.iMaxCpb as u32),
        max_dpb: Some(capability.iMaxDpb as u32),
        max_br: Some(capability.iMaxBr as u32),
        redundant_pic_cap: capability.bRedPicCap,
    }
}
