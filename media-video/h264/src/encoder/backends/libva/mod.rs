use super::stateless::{H264EncoderBackend, H264EncoderBackendResources};
use crate::{
    Profile,
    encoder::{
        H264Encoder, H264EncoderCapabilities, H264EncoderConfig, H264EncoderDevice, H264FrameType,
        H264RateControlConfig,
        backends::stateless::H264StatelessEncoder,
        util::{FrameEncodeInfo, macro_block_align},
    },
};
use ezk_image::{
    ColorInfo, ColorSpace, Image, ImageRef, PixelFormat, YuvColorInfo, convert_multi_thread,
};
use libva::{Buffer, Context, Display, Surface, VaError, ffi};
use std::{
    collections::VecDeque,
    mem::zeroed,
    slice::{self, from_raw_parts},
};

mod bitstream;

#[derive(Debug, thiserror::Error)]
pub enum VaCapabilitiesError {
    #[error("Profile {0:?} is not supported")]
    UnsupportedProfile(Profile),
    #[error("Failed to get entrypoints for profile {0:?}")]
    FailedToGetEntrypoints(VaError),
    #[error("No encode entrypoint for profile {0:?}")]
    UnsupportedEncodeProfile(Profile),
    #[error("Failed to get config attributes {0}")]
    FailedToGetConfigAttributes(#[source] VaError),
    #[error("Failed to get image formats {0}")]
    FailedToGetImageFormats(#[source] VaError),
    #[error("Image format derived from profile is not supported")]
    UnsupportedImageFormat,
}

#[derive(Debug, thiserror::Error)]
pub enum VaCreateEncoderError {
    #[error("Profile {0:?} is not supported")]
    UnsupportedProfile(Profile),
    #[error("Failed to get entrypoints for profile {0:?}")]
    FailedToGetEntrypoints(VaError),
    #[error("No encode entrypoint for profile {0:?}")]
    UnsupportedEncodeProfile(Profile),
    #[error("Failed to get config attributed {0}")]
    FailedToGetConfigAttributes(#[source] VaError),
    #[error("Failed to get image formats {0}")]
    FailedToGetImageFormats(#[source] VaError),
    #[error("Image format derived from profile is not support")]
    UnsupportedImageFormat,
    #[error("Failed to create va config")]
    FailedToCreateConfig(#[source] VaError),
    #[error("Failed to create va surfaces")]
    FailedToCreateSurfaces(#[source] VaError),
    #[error("Failed to create va context")]
    FailedToCreateContext(#[source] VaError),
    #[error("Failed to create coded buffer")]
    FailedToCreateCodedBuffer(#[source] VaError),
}

impl From<VaCapabilitiesError> for VaCreateEncoderError {
    fn from(value: VaCapabilitiesError) -> Self {
        use VaCapabilitiesError as E;

        match value {
            E::UnsupportedProfile(profile) => Self::UnsupportedProfile(profile),
            E::FailedToGetEntrypoints(va_error) => Self::FailedToGetEntrypoints(va_error),
            E::UnsupportedEncodeProfile(profile) => Self::UnsupportedEncodeProfile(profile),
            E::FailedToGetConfigAttributes(va_error) => Self::FailedToGetConfigAttributes(va_error),
            E::FailedToGetImageFormats(va_error) => Self::FailedToGetImageFormats(va_error),
            E::UnsupportedImageFormat => Self::UnsupportedImageFormat,
        }
    }
}

// 16 is the maximum number of reference frames allowed by H.264
const MAX_SURFACES: usize = 16;

// TODO: resolution changes

impl H264EncoderDevice for Display {
    type Encoder = VaH264Encoder;

    type CapabilitiesError = VaCapabilitiesError;
    type CreateEncoderError = VaCreateEncoderError;

    fn profiles(&mut self) -> Vec<Profile> {
        let mut profiles = Vec::new();

        let va_profiles: Vec<ffi::VAProfile> = (*self).profiles().unwrap();

        for va_profile in va_profiles {
            let profile = match va_profile {
                ffi::VAProfile_VAProfileH264Baseline => Profile::Baseline,
                ffi::VAProfile_VAProfileH264ConstrainedBaseline => Profile::ConstrainedBaseline,
                ffi::VAProfile_VAProfileH264High => Profile::High,
                ffi::VAProfile_VAProfileH264High10 => Profile::High10,
                ffi::VAProfile_VAProfileH264Main => Profile::Main,
                _ => continue,
            };

            let entrypoints = self.entrypoints(va_profile).unwrap();

            let supports_encode = entrypoints.contains(&ffi::VAEntrypoint_VAEntrypointEncSlice)
                || entrypoints.contains(&ffi::VAEntrypoint_VAEntrypointEncSliceLP);

            if supports_encode {
                profiles.push(profile);
            }
        }

        profiles
    }

    fn capabilities(
        &mut self,
        profile: Profile,
    ) -> Result<H264EncoderCapabilities, Self::CapabilitiesError> {
        let (va_profile, va_format) = profile_to_profile_and_format(profile)
            .ok_or(VaCapabilitiesError::UnsupportedProfile(profile))?;

        let va_entrypoint = self
            .entrypoints(va_profile)
            .map_err(VaCapabilitiesError::FailedToGetEntrypoints)?
            .into_iter()
            .find(|&e| {
                e == ffi::VAEntrypoint_VAEntrypointEncSlice
                    || e == ffi::VAEntrypoint_VAEntrypointEncSliceLP
            })
            .ok_or(VaCapabilitiesError::UnsupportedEncodeProfile(profile))?;

        let attrs = self
            .get_config_attributes(va_profile, va_entrypoint)
            .map_err(VaCapabilitiesError::FailedToGetConfigAttributes)?;

        // Test the requested format is available
        {
            let formats = attrs[ffi::VAConfigAttribType_VAConfigAttribRTFormat as usize].value;
            if formats & va_format == 0 {
                return Err(VaCapabilitiesError::UnsupportedImageFormat);
            }
        }

        let (max_l0, max_l1) = {
            let attr = attrs[ffi::VAConfigAttribType_VAConfigAttribEncMaxRefFrames as usize];
            if attr.value != ffi::VA_ATTRIB_NOT_SUPPORTED {
                let [b0, b1, b2, b3] = attr.value.to_ne_bytes();

                (u16::from_ne_bytes([b0, b1]), u16::from_ne_bytes([b2, b3]))
            } else {
                // Limit the maximum number of reference frames to 1 for both future and past
                (1, 1)
            }
        };

        let min_width = 16;
        let min_height = 16;
        let max_width = attrs[ffi::VAConfigAttribType_VAConfigAttribMaxPictureWidth as usize].value;
        let max_height =
            attrs[ffi::VAConfigAttribType_VAConfigAttribMaxPictureHeight as usize].value;

        let max_quality_level = {
            let value = attrs[ffi::VAConfigAttribType_VAConfigAttribEncQualityRange as usize].value;

            if value == ffi::VA_ATTRIB_NOT_SUPPORTED {
                1
            } else {
                value
            }
        };

        let formats = self
            .image_formats()
            .map_err(VaCapabilitiesError::FailedToGetConfigAttributes)?
            .into_iter()
            .filter_map(|format| map_pixel_format(format.fourcc))
            .collect();

        Ok(H264EncoderCapabilities {
            min_qp: 0,
            max_qp: 51,
            min_resolution: (min_width, min_height),
            max_resolution: (max_width, max_height),
            max_l0_p_references: max_l0.into(),
            max_l0_b_references: max_l0.into(),
            max_l1_b_references: max_l1.into(),
            max_quality_level,
            formats,
        })
    }

    fn create_encoder(
        &mut self,
        mut config: H264EncoderConfig,
    ) -> Result<Self::Encoder, Self::CreateEncoderError> {
        let capabilites = self.capabilities(config.profile)?;

        config.quality_level = capabilites.max_quality_level - config.quality_level;

        let width_mbaligned = macro_block_align(config.resolution.0);
        let height_mbaligned = macro_block_align(config.resolution.1);

        let (va_profile, va_format) = profile_to_profile_and_format(config.profile)
            .ok_or(VaCreateEncoderError::UnsupportedProfile(config.profile))?;

        let va_entrypoint = self
            .entrypoints(va_profile)
            .map_err(VaCreateEncoderError::FailedToGetEntrypoints)?
            .into_iter()
            .find(|&e| {
                e == ffi::VAEntrypoint_VAEntrypointEncSlice
                    || e == ffi::VAEntrypoint_VAEntrypointEncSliceLP
            })
            .ok_or(VaCreateEncoderError::UnsupportedEncodeProfile(
                config.profile,
            ))?;

        let attributes = self
            .get_config_attributes(va_profile, va_entrypoint)
            .map_err(VaCreateEncoderError::FailedToGetConfigAttributes)?;

        let mut config_attributes = Vec::new();
        config_attributes.push(ffi::VAConfigAttrib {
            type_: ffi::VAConfigAttribType_VAConfigAttribRTFormat,
            value: va_format,
        });

        {
            let rc_mode = match config.rate_control {
                H264RateControlConfig::ConstantBitRate { .. } => ffi::VA_RC_CBR,
                H264RateControlConfig::VariableBitRate { .. } => ffi::VA_RC_VBR,
                H264RateControlConfig::ConstantQuality { .. } => ffi::VA_RC_CQP,
            };

            config_attributes.push(ffi::VAConfigAttrib {
                type_: ffi::VAConfigAttribType_VAConfigAttribRateControl,
                value: rc_mode,
            });
        }

        let mut support_packed_header_sequence = false;
        let mut support_packed_header_picture = false;
        let mut support_packed_header_slice = false;

        {
            let value =
                attributes[ffi::VAConfigAttribType_VAConfigAttribEncPackedHeaders as usize].value;

            if value != ffi::VA_ATTRIB_NOT_SUPPORTED {
                support_packed_header_sequence = (value & ffi::VA_ENC_PACKED_HEADER_SEQUENCE) != 0;
                support_packed_header_picture = (value & ffi::VA_ENC_PACKED_HEADER_PICTURE) != 0;
                support_packed_header_slice = (value & ffi::VA_ENC_PACKED_HEADER_SLICE) != 0;

                config_attributes.push(ffi::VAConfigAttrib {
                    type_: ffi::VAConfigAttribType_VAConfigAttribEncPackedHeaders,
                    value: value
                        & (ffi::VA_ENC_PACKED_HEADER_SEQUENCE
                            | ffi::VA_ENC_PACKED_HEADER_PICTURE
                            | ffi::VA_ENC_PACKED_HEADER_SLICE),
                });
            }
        }

        let va_config = self
            .create_config(va_profile, va_entrypoint, &config_attributes)
            .map_err(VaCreateEncoderError::FailedToCreateConfig)?;

        let input_surfaces = self
            .create_surfaces(
                va_format,
                width_mbaligned,
                height_mbaligned,
                MAX_SURFACES,
                &[],
            )
            .map_err(VaCreateEncoderError::FailedToCreateSurfaces)?;

        let reference_surfaces = self
            .create_surfaces(
                va_format,
                width_mbaligned,
                height_mbaligned,
                MAX_SURFACES,
                &[],
            )
            .map_err(VaCreateEncoderError::FailedToCreateSurfaces)?;

        let context = self
            .create_context(
                &va_config,
                width_mbaligned as _,
                height_mbaligned as _,
                ffi::VA_PROGRESSIVE as _,
                input_surfaces.iter().chain(reference_surfaces.iter()),
            )
            .map_err(VaCreateEncoderError::FailedToCreateContext)?;

        let dpb_slots: Vec<_> = reference_surfaces
            .into_iter()
            .map(|surface| DpbSlot {
                surface,
                picture: ffi::_VAPictureH264 {
                    picture_id: ffi::VA_INVALID_SURFACE,
                    flags: ffi::VA_PICTURE_H264_INVALID,
                    ..unsafe { zeroed() }
                },
            })
            .collect();

        // EncCodec buffer size is estimated from the input image resolution. Currently using a higher value to ensure
        // proper output even with worst case input
        let output_buffer_size = (width_mbaligned as f64 * height_mbaligned as f64 * 1.5) as usize;

        let encode_slots = input_surfaces
            .into_iter()
            .map(|surface| -> Result<EncodeSlot, VaError> {
                let output = context.create_buffer_empty(
                    ffi::VABufferType_VAEncCodedBufferType,
                    output_buffer_size,
                )?;

                Ok(EncodeSlot { surface, output })
            })
            .collect::<Result<Vec<_>, VaError>>()
            .map_err(VaCreateEncoderError::FailedToCreateCodedBuffer)?;

        let backend = VaBackend {
            config,
            context,
            support_packed_header_sequence,
            support_packed_header_picture,
            support_packed_header_slice,
            width_mbaligned,
            height_mbaligned,
            max_l0: config.max_l0_b_references,
            max_l1: config.max_l1_b_references,
        };

        let resources = H264EncoderBackendResources {
            backend,
            encode_slots,
            dpb_slots,
        };

        Ok(VaH264Encoder {
            driver: H264StatelessEncoder::new(config, resources),
        })
    }
}

fn map_pixel_format(fourcc: u32) -> Option<PixelFormat> {
    match fourcc {
        ffi::VA_FOURCC_NV12 => Some(PixelFormat::NV12),
        ffi::VA_FOURCC_RGBA => Some(PixelFormat::RGBA),
        ffi::VA_FOURCC_RGBX => Some(PixelFormat::RGBA),
        ffi::VA_FOURCC_BGRA => Some(PixelFormat::BGRA),
        ffi::VA_FOURCC_BGRX => Some(PixelFormat::BGRA),
        ffi::VA_FOURCC_I420 => Some(PixelFormat::I420),
        ffi::VA_FOURCC_422H => Some(PixelFormat::I422),
        ffi::VA_FOURCC_444P => Some(PixelFormat::I444),
        ffi::VA_FOURCC_RGBP => Some(PixelFormat::RGB),
        ffi::VA_FOURCC_BGRP => Some(PixelFormat::BGR),
        ffi::VA_FOURCC_I010 => Some(PixelFormat::I010),
        _ => None,
    }
}

pub struct VaH264Encoder {
    driver: H264StatelessEncoder<VaBackend>,
}

impl H264Encoder for VaH264Encoder {
    type Error = VaError;

    fn encode_frame(&mut self, image: &dyn ImageRef) -> Result<(), Self::Error> {
        self.driver.encode_frame(image)
    }

    fn poll_result(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        self.driver.poll_result()
    }

    fn wait_result(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        self.driver.wait_result()
    }
}

struct VaBackend {
    config: H264EncoderConfig,

    context: Context,

    /// Indicates if packed headers are supported
    support_packed_header_sequence: bool,
    support_packed_header_picture: bool,
    support_packed_header_slice: bool,

    /// Resolution macro block aligned (next 16x16 block boundary)
    width_mbaligned: u32,
    height_mbaligned: u32,

    /// Maximum number of reference frames that should be used when encoding a P or B-Frame
    max_l0: u32,
    max_l1: u32,
}

struct EncodeSlot {
    surface: Surface,
    output: Buffer,
}

struct DpbSlot {
    surface: Surface,
    picture: ffi::VAPictureH264,
}

impl H264EncoderBackend for VaBackend {
    type EncodeSlot = EncodeSlot;
    type DpbSlot = DpbSlot;
    type Error = VaError;

    fn wait_encode_slot(&mut self, encode_slot: &mut Self::EncodeSlot) -> Result<(), VaError> {
        encode_slot.surface.sync()
    }

    fn poll_encode_slot(&mut self, encode_slot: &mut Self::EncodeSlot) -> Result<bool, VaError> {
        encode_slot.surface.try_sync()
    }

    fn read_out_encode_slot(
        &mut self,
        encode_slot: &mut Self::EncodeSlot,
        output: &mut VecDeque<Vec<u8>>,
    ) -> Result<(), VaError> {
        let mut codec_buffer_mapped = encode_slot.output.map()?;
        let mut ptr = codec_buffer_mapped.data();

        while !ptr.is_null() {
            let segment = unsafe { ptr.cast::<ffi::VACodedBufferSegment>().read() };
            ptr = segment.next;

            let buf = segment.buf.cast::<u8>().cast_const();
            let buf = unsafe { from_raw_parts(buf, segment.size as usize) };

            output.push_back(buf.to_vec());
        }

        Ok(())
    }

    fn upload_image_to_slot(
        &mut self,
        encode_slot: &mut Self::EncodeSlot,
        image: &dyn ImageRef,
    ) -> Result<(), VaError> {
        let mut dst = encode_slot.surface.derive_image()?;
        let dst_img = *dst.ffi();
        let dst_pixel_format = map_pixel_format(dst_img.format.fourcc).unwrap();

        // Safety: the mapped image must live for this entire scope
        unsafe {
            let mut mapped = dst.map()?;

            let mut planes = vec![];
            let mut strides = vec![];

            strides.push(dst_img.pitches[0] as usize);
            planes.push(slice::from_raw_parts_mut(
                mapped.data().add(dst_img.offsets[0] as usize),
                (dst_img.offsets[1] - dst_img.offsets[0]) as usize,
            ));

            if dst_img.num_planes >= 2 {
                strides.push(dst_img.pitches[1] as usize);
                planes.push(slice::from_raw_parts_mut(
                    mapped.data().add(dst_img.offsets[1] as usize),
                    (dst_img.offsets[2] - dst_img.offsets[1]) as usize,
                ));
            }

            if dst_img.num_planes == 3 {
                strides.push(dst_img.pitches[2] as usize);
                planes.push(slice::from_raw_parts_mut(
                    mapped.data().add(dst_img.offsets[2] as usize),
                    (dst_img.data_size - dst_img.offsets[2]) as usize,
                ));
            }

            let dst_color = match image.color() {
                ColorInfo::RGB(rgb_color_info) => YuvColorInfo {
                    transfer: rgb_color_info.transfer,
                    primaries: rgb_color_info.primaries,
                    space: ColorSpace::BT709,
                    full_range: true,
                },
                ColorInfo::YUV(yuv_color_info) => yuv_color_info,
            };

            let mut dst_image = Image::from_planes(
                dst_pixel_format,
                planes,
                Some(strides),
                image.width(),
                image.height(),
                dst_color.into(),
            )
            .unwrap();

            convert_multi_thread(image, &mut dst_image).unwrap();
        }

        Ok(())
    }

    fn encode_slot(
        &mut self,
        frame_info: FrameEncodeInfo,
        encode_slot: &mut Self::EncodeSlot,
        setup_reference: &mut Self::DpbSlot,
        l0_references: &[&Self::DpbSlot],
        l1_references: &[&Self::DpbSlot],
    ) -> Result<(), VaError> {
        setup_reference.picture.picture_id = setup_reference.surface.id();
        setup_reference.picture.frame_idx = frame_info.frame_num.into();
        setup_reference.picture.TopFieldOrderCnt = frame_info.picture_order_count.into();
        setup_reference.picture.BottomFieldOrderCnt = frame_info.picture_order_count.into();
        setup_reference.picture.flags = if matches!(
            frame_info.frame_type,
            H264FrameType::Idr | H264FrameType::I | H264FrameType::P
        ) {
            ffi::VA_PICTURE_H264_SHORT_TERM_REFERENCE
        } else {
            0
        };

        let mut bufs = Vec::new();

        let seq_param = self.create_seq_params();
        let pic_param = self.create_picture_params(
            &frame_info,
            setup_reference,
            l0_references,
            l1_references,
            &encode_slot.output,
        );
        let slice_param = self.create_slice_params(&frame_info, l0_references, l1_references);

        if frame_info.frame_type == H264FrameType::Idr {
            // Render sequence params
            bufs.push(self.context.create_buffer_with_data(
                ffi::VABufferType_VAEncSequenceParameterBufferType,
                &seq_param,
            )?);
            bufs.push(self.create_rate_control_params()?);
            bufs.push(self.create_quality_params()?);

            // Render packed sequence
            if self.support_packed_header_sequence {
                let packed_sequence_param = bitstream::write_sps_rbsp(&self.config, &seq_param);

                self.create_packed_param(
                    ffi::VAEncPackedHeaderTypeH264_VAEncPackedHeaderH264_SPS,
                    &packed_sequence_param,
                    &mut bufs,
                )?;
            }

            // Render packed picture
            if self.support_packed_header_picture {
                let packed_picture_param = bitstream::write_pps_rbsp(&pic_param);
                self.create_packed_param(
                    ffi::VAEncPackedHeaderTypeH264_VAEncPackedHeaderH264_PPS,
                    &packed_picture_param,
                    &mut bufs,
                )?;
            }
        }

        // Render picture
        bufs.push(self.context.create_buffer_with_data(
            ffi::VABufferType_VAEncPictureParameterBufferType,
            &pic_param,
        )?);

        // Render packed slice
        if self.support_packed_header_slice {
            let packed_slice_params =
                bitstream::write_slice_header(&seq_param, &pic_param, &slice_param);

            self.create_packed_param(
                ffi::VAEncPackedHeaderTypeH264_VAEncPackedHeaderH264_Slice,
                &packed_slice_params,
                &mut bufs,
            )?;
        }

        // Render slice
        bufs.push(self.context.create_buffer_with_data(
            ffi::VABufferType_VAEncSliceParameterBufferType,
            &slice_param,
        )?);

        let pipeline = self.context.begin_picture(&encode_slot.surface)?;
        pipeline.render_picture(&bufs)?;
        pipeline.end_picture()?;

        // explicitly drop bufs after `end_picture` to ensure them not being dropped before
        drop(bufs);

        Ok(())
    }
}

impl VaBackend {
    fn create_seq_params(&self) -> ffi::VAEncSequenceParameterBufferH264 {
        unsafe {
            let mut seq_param = zeroed::<ffi::VAEncSequenceParameterBufferH264>();

            seq_param.level_idc = self.config.level.level_idc();
            seq_param.picture_width_in_mbs = (self.width_mbaligned / 16) as u16;
            seq_param.picture_height_in_mbs = (self.height_mbaligned / 16) as u16;

            seq_param.intra_idr_period = self.config.frame_pattern.intra_idr_period.into();
            seq_param.intra_period = self.config.frame_pattern.intra_period.into();
            seq_param.ip_period = self.config.frame_pattern.ip_period.into();

            seq_param.max_num_ref_frames = self.max_l0 + self.max_l1;
            seq_param.time_scale = 900; // TODO: configurable
            seq_param.num_units_in_tick = 15; // TODO: configurable

            let seq_fields = &mut seq_param.seq_fields.bits;

            seq_fields.set_log2_max_pic_order_cnt_lsb_minus4(
                //(self.state.log2_max_pic_order_cnt_lsb - 4) as u32,
                16 - 4,
            );

            seq_fields.set_log2_max_frame_num_minus4(16 - 4);
            seq_fields.set_frame_mbs_only_flag(1);
            seq_fields.set_chroma_format_idc(1); // TODO: configurable this is currently hardcoded to yuv420
            seq_fields.set_direct_8x8_inference_flag(1);

            let (width, height) = self.config.resolution;

            if width != self.width_mbaligned || height != self.height_mbaligned {
                seq_param.frame_cropping_flag = 1;
                seq_param.frame_crop_right_offset = (self.width_mbaligned - width) / 2;
                seq_param.frame_crop_bottom_offset = (self.height_mbaligned - height) / 2;
            }

            seq_param
        }
    }

    fn create_quality_params(&self) -> Result<Buffer, VaError> {
        unsafe {
            let mut quality_params_buffer = self.context.create_buffer_empty(
                ffi::VABufferType_VAEncMiscParameterBufferType,
                size_of::<ffi::VAEncMiscParameterBuffer>()
                    + size_of::<ffi::VAEncMiscParameterRateControl>(),
            )?;
            let mut mapped = quality_params_buffer.map()?;
            let misc_param = &mut *mapped.data().cast::<ffi::VAEncMiscParameterBuffer>();
            misc_param.type_ = ffi::VAEncMiscParameterType_VAEncMiscParameterTypeEncQuality;

            let enc_quality_params = &mut *misc_param
                .data
                .as_mut_ptr()
                .cast::<ffi::VAEncMiscParameterBufferQualityLevel>();

            *enc_quality_params = zeroed();

            enc_quality_params.quality_level = self.config.quality_level;

            drop(mapped);

            Ok(quality_params_buffer)
        }
    }

    fn create_rate_control_params(&self) -> Result<Buffer, VaError> {
        unsafe {
            // Build rate control parameter buffer
            //
            // Modifying the data in the buffer instead of on the stack since the
            // VAEncMiscParameterBuffer and VAEncMiscParameterRateControl must be packed after another
            let mut rate_control_params_buffer = self.context.create_buffer_empty(
                ffi::VABufferType_VAEncMiscParameterBufferType,
                size_of::<ffi::VAEncMiscParameterBuffer>()
                    + size_of::<ffi::VAEncMiscParameterRateControl>(),
            )?;
            let mut mapped = rate_control_params_buffer.map()?;
            let misc_param = &mut *mapped.data().cast::<ffi::VAEncMiscParameterBuffer>();
            misc_param.type_ = ffi::VAEncMiscParameterType_VAEncMiscParameterTypeRateControl;

            let rate_control_params = &mut *misc_param
                .data
                .as_mut_ptr()
                .cast::<ffi::VAEncMiscParameterRateControl>();

            *rate_control_params = zeroed();

            rate_control_params.window_size = 100;

            if let Some((min_qp, max_qp)) = self.config.qp {
                rate_control_params.min_qp = min_qp.into();
                rate_control_params.max_qp = max_qp.into();
            }

            match self.config.rate_control {
                H264RateControlConfig::ConstantBitRate { bitrate } => {
                    rate_control_params.rc_flags.value = ffi::VA_RC_CBR;
                    rate_control_params.bits_per_second = bitrate;
                    rate_control_params.target_percentage = 100;
                }
                H264RateControlConfig::VariableBitRate {
                    average_bitrate,
                    max_bitrate,
                } => {
                    rate_control_params.rc_flags.value = ffi::VA_RC_VBR;
                    rate_control_params.bits_per_second = max_bitrate;
                    rate_control_params.target_percentage = (average_bitrate * 10) / max_bitrate;
                }
                H264RateControlConfig::ConstantQuality {
                    const_qp,
                    max_bitrate,
                } => {
                    rate_control_params.rc_flags.value = ffi::VA_RC_CQP;
                    rate_control_params.initial_qp = const_qp.into();
                    rate_control_params.min_qp = const_qp.into();
                    rate_control_params.max_qp = const_qp.into();

                    if let Some(max_bitrate) = max_bitrate {
                        rate_control_params.bits_per_second = max_bitrate;
                    }
                }
            }

            drop(mapped);

            Ok(rate_control_params_buffer)
        }
    }

    fn create_picture_params(
        &self,
        frame_info: &FrameEncodeInfo,
        setup_reference: &DpbSlot,
        l0_references: &[&DpbSlot],
        l1_references: &[&DpbSlot],
        output: &Buffer,
    ) -> ffi::VAEncPictureParameterBufferH264 {
        unsafe {
            let mut pic_param = zeroed::<ffi::VAEncPictureParameterBufferH264>();

            pic_param.frame_num = frame_info.frame_num;
            pic_param.CurrPic = setup_reference.picture;

            match frame_info.frame_type {
                H264FrameType::P | H264FrameType::B => {
                    let iter = l0_references.iter().chain(l1_references).copied();

                    fill_pic_list(&mut pic_param.ReferenceFrames, iter);
                }
                H264FrameType::I | H264FrameType::Idr => {
                    // No references to add
                }
            }

            log::trace!(
                "\tpic_params.ReferenceFrames = {:?}",
                debug_pic_list(&pic_param.ReferenceFrames)
            );

            pic_param
                .pic_fields
                .bits
                .set_idr_pic_flag((frame_info.frame_type == H264FrameType::Idr) as u32);
            pic_param
                .pic_fields
                .bits
                .set_reference_pic_flag((frame_info.frame_type != H264FrameType::B) as u32);
            pic_param.pic_fields.bits.set_entropy_coding_mode_flag(1);
            pic_param
                .pic_fields
                .bits
                .set_deblocking_filter_control_present_flag(1);

            pic_param.coded_buf = output.id();
            pic_param.last_picture = 0; // TODO: set on flush
            pic_param.pic_init_qp = 24; // TODO: configurable

            pic_param
        }
    }

    fn create_slice_params(
        &self,
        frame_info: &FrameEncodeInfo,
        l0_references: &[&DpbSlot],
        l1_references: &[&DpbSlot],
    ) -> ffi::VAEncSliceParameterBufferH264 {
        unsafe {
            let mut slice_params = zeroed::<ffi::VAEncSliceParameterBufferH264>();

            slice_params.num_macroblocks = self.width_mbaligned * self.height_mbaligned / (16 * 16);
            slice_params.slice_type = match frame_info.frame_type {
                H264FrameType::P => 0,
                H264FrameType::B => 1,
                H264FrameType::Idr | H264FrameType::I => 2,
            };

            match frame_info.frame_type {
                H264FrameType::P => {
                    fill_pic_list(&mut slice_params.RefPicList0, l0_references.iter().copied());
                    fill_pic_list(&mut slice_params.RefPicList1, None);
                }
                H264FrameType::B => {
                    fill_pic_list(&mut slice_params.RefPicList0, l0_references.iter().copied());
                    fill_pic_list(&mut slice_params.RefPicList1, l1_references.iter().copied());
                }
                H264FrameType::I => {
                    fill_pic_list(&mut slice_params.RefPicList0, None);
                    fill_pic_list(&mut slice_params.RefPicList1, None);
                }
                H264FrameType::Idr => {
                    fill_pic_list(&mut slice_params.RefPicList0, None);
                    fill_pic_list(&mut slice_params.RefPicList1, None);

                    slice_params.idr_pic_id = frame_info.idr_pic_id;
                }
            }

            log::trace!(
                "\tslice_params.RefPicList0 = {:?}",
                debug_pic_list(&slice_params.RefPicList0)
            );

            log::trace!(
                "\tslice_params.RefPicList1 = {:?}",
                debug_pic_list(&slice_params.RefPicList1)
            );

            slice_params.slice_alpha_c0_offset_div2 = 0;
            slice_params.slice_beta_offset_div2 = 0;

            slice_params.direct_spatial_mv_pred_flag = 1;
            slice_params.pic_order_cnt_lsb = frame_info.picture_order_count;

            slice_params
        }
    }

    fn create_packed_param(
        &self,
        type_: u32,
        buf: &[u8],
        bufs: &mut Vec<Buffer>,
    ) -> Result<(), VaError> {
        let params = ffi::VAEncPackedHeaderParameterBuffer {
            type_,
            bit_length: (buf.len() * 8) as _,
            has_emulation_bytes: 0,
            va_reserved: Default::default(),
        };

        let packed_header_params = self.context.create_buffer_with_data(
            ffi::VABufferType_VAEncPackedHeaderParameterBufferType,
            &params,
        )?;

        let b = self
            .context
            .create_buffer_from_bytes(ffi::VABufferType_VAEncPackedHeaderDataBufferType, buf)?;

        bufs.push(packed_header_params);
        bufs.push(b);

        Ok(())
    }
}

fn debug_pic_list(list: &[ffi::VAPictureH264]) -> Vec<u32> {
    list.iter()
        .take_while(|p| p.flags != ffi::VA_PICTURE_H264_INVALID)
        .map(|p| p.frame_idx)
        .collect::<Vec<_>>()
}

fn fill_pic_list<'a>(list: &mut [ffi::VAPictureH264], iter: impl IntoIterator<Item = &'a DpbSlot>) {
    let mut iter = iter.into_iter();
    for dst_picture in list {
        if let Some(DpbSlot {
            surface: _,
            picture,
        }) = iter.next()
        {
            *dst_picture = *picture;
        } else {
            dst_picture.picture_id = ffi::VA_INVALID_SURFACE;
            dst_picture.flags = ffi::VA_PICTURE_H264_INVALID;
        }
    }
}

fn profile_to_profile_and_format(profile: crate::Profile) -> Option<(i32, u32)> {
    let (profile, format) = match profile {
        crate::Profile::Baseline => (
            ffi::VAProfile_VAProfileH264Baseline,
            ffi::VA_RT_FORMAT_YUV420,
        ),
        crate::Profile::ConstrainedBaseline => (
            ffi::VAProfile_VAProfileH264ConstrainedBaseline,
            ffi::VA_RT_FORMAT_YUV420,
        ),
        crate::Profile::Main => (ffi::VAProfile_VAProfileH264Main, ffi::VA_RT_FORMAT_YUV420),
        crate::Profile::Extended => return None,
        crate::Profile::High => (ffi::VAProfile_VAProfileH264High, ffi::VA_RT_FORMAT_YUV420),
        crate::Profile::High10 => (
            ffi::VAProfile_VAProfileH264High10,
            ffi::VA_RT_FORMAT_YUV420_10,
        ),
        crate::Profile::High422 => (ffi::VAProfile_VAProfileH264High, ffi::VA_RT_FORMAT_YUV422),
        crate::Profile::High444Predictive => {
            (ffi::VAProfile_VAProfileH264High, ffi::VA_RT_FORMAT_YUV444)
        }
        crate::Profile::High10Intra => (
            ffi::VAProfile_VAProfileH264High10,
            ffi::VA_RT_FORMAT_YUV420_10,
        ),
        crate::Profile::High422Intra => {
            (ffi::VAProfile_VAProfileH264High, ffi::VA_RT_FORMAT_YUV422)
        }
        crate::Profile::High444Intra => {
            (ffi::VAProfile_VAProfileH264High, ffi::VA_RT_FORMAT_YUV444)
        }
        crate::Profile::CAVLC444Intra => return None,
    };

    Some((profile, format))
}
