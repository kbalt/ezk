use crate::{
    Level, Profile,
    encoder::{
        H264Encoder, H264EncoderCapabilities, H264EncoderConfig, H264EncoderDevice, H264FrameRate,
        H264FrameType, H264RateControlConfig,
        util::{FrameEncodeInfo, H264EncoderState, macro_block_align},
    },
};
use ezk_image::{ImageRef, PixelFormat};
use std::{
    cmp,
    collections::VecDeque,
    mem::{take, zeroed},
    ptr::null_mut,
};
use vulkan::{
    PhysicalDevice, VulkanError,
    ash::vk::{self},
    encoder::{H264, VulkanEncodeSlot, VulkanEncoder, VulkanEncoderCapabilities},
};

impl H264EncoderDevice for PhysicalDevice {
    type Encoder = VkH264Encoder;
    type CapabilitiesError = vk::Result;
    type CreateEncoderError = VulkanError;

    fn profiles(&mut self) -> Vec<Profile> {
        vec![Profile::Baseline, Profile::Main, Profile::High]
    }

    fn capabilities(
        &mut self,
        profile: Profile,
    ) -> Result<H264EncoderCapabilities, Self::CapabilitiesError> {
        let profile_idc = map_profile(profile).unwrap();

        let mut h264_profile_info =
            vk::VideoEncodeH264ProfileInfoKHR::default().std_profile_idc(profile_idc);

        let capabilities = VulkanEncoderCapabilities::<H264>::new(self, &mut h264_profile_info);

        let video_formats = self.video_format_properties(&[capabilities.video_profile_info])?;

        let formats = video_formats
            .iter()
            .filter_map(|format| match format.format {
                vk::Format::R8G8B8A8_UNORM => Some(PixelFormat::RGBA),
                vk::Format::B8G8R8A8_UNORM => Some(PixelFormat::BGRA),
                vk::Format::R8G8B8_UNORM => Some(PixelFormat::RGB),
                vk::Format::B8G8R8_UNORM => Some(PixelFormat::BGR),
                vk::Format::G8_B8R8_2PLANE_420_UNORM => Some(PixelFormat::NV12),
                vk::Format::G8_B8_R8_3PLANE_420_UNORM => Some(PixelFormat::I420),
                vk::Format::G8_B8_R8_3PLANE_422_UNORM => Some(PixelFormat::I422),
                vk::Format::G8_B8_R8_3PLANE_444_UNORM => Some(PixelFormat::I444),
                _ => None,
            })
            .collect();

        Ok(H264EncoderCapabilities {
            min_qp: capabilities.video_encode_codec_capabilities.min_qp as u8,
            max_qp: capabilities.video_encode_codec_capabilities.max_qp as u8,
            min_resolution: (
                capabilities.video_capabilities.min_coded_extent.width,
                capabilities.video_capabilities.min_coded_extent.height,
            ),
            max_resolution: (
                capabilities.video_capabilities.max_coded_extent.width,
                capabilities.video_capabilities.max_coded_extent.height,
            ),
            max_l0_p_references: capabilities
                .video_encode_codec_capabilities
                .max_p_picture_l0_reference_count,
            max_l0_b_references: capabilities
                .video_encode_codec_capabilities
                .max_b_picture_l0_reference_count,
            max_l1_b_references: capabilities
                .video_encode_codec_capabilities
                .max_l1_reference_count,
            max_quality_level: capabilities.video_encode_capabilities.max_quality_levels,
            formats,
        })
    }

    fn create_encoder(
        &mut self,
        config: H264EncoderConfig,
    ) -> Result<Self::Encoder, Self::CreateEncoderError> {
        let profile_idc = map_profile(config.profile).unwrap();

        let mut h264_profile_info =
            vk::VideoEncodeH264ProfileInfoKHR::default().std_profile_idc(profile_idc);

        let capabilities = VulkanEncoderCapabilities::<H264>::new(self, &mut h264_profile_info);

        let caps = capabilities.video_capabilities;
        let h264_caps = capabilities.video_encode_codec_capabilities;

        let max_references = cmp::max(
            h264_caps.max_p_picture_l0_reference_count,
            h264_caps.max_b_picture_l0_reference_count + h264_caps.max_l1_reference_count,
        );
        let max_active_ref_images = cmp::min(max_references, caps.max_active_reference_pictures);

        // Make only as many dpb slots as can be actively references, + 1 for the setup reference
        let max_dpb_slots = cmp::min(caps.max_dpb_slots, max_active_ref_images + 1);

        let (width, height) = config.resolution;
        let (width_mbaligned, height_mbaligned) =
            (macro_block_align(width), macro_block_align(height));

        let mut seq_params: vk::native::StdVideoH264SequenceParameterSet = unsafe { zeroed() };
        seq_params.profile_idc = profile_idc;
        seq_params.level_idc = map_level(config.level).unwrap();
        seq_params.chroma_format_idc =
            vk::native::StdVideoH264ChromaFormatIdc_STD_VIDEO_H264_CHROMA_FORMAT_IDC_420;

        seq_params.log2_max_frame_num_minus4 = 16 - 4;
        seq_params.log2_max_pic_order_cnt_lsb_minus4 = 16 - 4;
        seq_params.max_num_ref_frames = max_active_ref_images as u8;
        seq_params.pic_width_in_mbs_minus1 = (width_mbaligned / 16) - 1;
        seq_params.pic_height_in_map_units_minus1 = (height_mbaligned / 16) - 1;

        seq_params.flags.set_frame_mbs_only_flag(1);
        seq_params.flags.set_direct_8x8_inference_flag(1);

        if width != width_mbaligned || height != height_mbaligned {
            seq_params.flags.set_frame_cropping_flag(1);

            seq_params.frame_crop_right_offset = (width_mbaligned - width) / 2;
            seq_params.frame_crop_bottom_offset = (height_mbaligned - height) / 2;
        }

        let mut pic_params: vk::native::StdVideoH264PictureParameterSet = unsafe { zeroed() };
        pic_params
            .flags
            .set_deblocking_filter_control_present_flag(1);
        pic_params.flags.set_entropy_coding_mode_flag(1);

        let std_sp_ss = [seq_params];
        let std_pp_ss = [pic_params];
        let video_encode_h264_session_parameters_add_info =
            vk::VideoEncodeH264SessionParametersAddInfoKHR::default()
                .std_sp_ss(&std_sp_ss)
                .std_pp_ss(&std_pp_ss);

        let mut video_encode_h264_session_parameters_create_info =
            vk::VideoEncodeH264SessionParametersCreateInfoKHR::default()
                .max_std_sps_count(1)
                .max_std_pps_count(1)
                .parameters_add_info(&video_encode_h264_session_parameters_add_info);

        let encoder = capabilities.create_encoder(
            &mut video_encode_h264_session_parameters_create_info,
            vk::Extent2D { width, height },
            max_active_ref_images,
            max_dpb_slots,
        );

        Ok(VkH264Encoder {
            config,
            state: H264EncoderState::new(config.frame_pattern),
            encoder,
            max_l0_p_ref_images: h264_caps.max_p_picture_l0_reference_count as usize,
            max_l0_b_ref_images: h264_caps.max_b_picture_l0_reference_count as usize,
            max_l1_b_ref_images: h264_caps.max_l1_reference_count as usize,
            backlogged_b_frames: Vec::new(),
            free_dpb_slots: (0..max_dpb_slots as usize)
                .map(|index| DpbSlot {
                    index,
                    display_index: 0,
                })
                .rev()
                .collect(),
            active_dpb_slots: VecDeque::new(),
        })
    }
}

pub struct VkH264Encoder {
    config: H264EncoderConfig,
    state: H264EncoderState,
    encoder: VulkanEncoder<H264>,

    max_l0_p_ref_images: usize,
    max_l0_b_ref_images: usize,
    max_l1_b_ref_images: usize,

    backlogged_b_frames: Vec<(FrameEncodeInfo, VulkanEncodeSlot)>,
    free_dpb_slots: Vec<DpbSlot>,
    active_dpb_slots: VecDeque<DpbSlot>,
}

#[derive(Clone, Copy)]
struct DpbSlot {
    index: usize,
    display_index: u16,
}

impl H264Encoder for VkH264Encoder {
    type Error = VulkanError;

    fn encode_frame(&mut self, image: &dyn ImageRef) -> Result<(), Self::Error> {
        let frame_info = self.state.next();

        log::debug!("Encode {frame_info:?}");

        let mut encode_slot = self.encoder.pop_encode_slot().unwrap();

        self.encoder
            .upload_image_to_encode_slot(&mut encode_slot, image);

        // B-Frames are not encoded immediately, they are queued until after an I or P-frame is encoded
        if frame_info.frame_type == H264FrameType::B {
            self.backlogged_b_frames.push((frame_info, encode_slot));
            return Ok(());
        }

        self.encode_slot(frame_info, encode_slot);

        if matches!(
            frame_info.frame_type,
            H264FrameType::Idr | H264FrameType::I | H264FrameType::P
        ) {
            let backlogged_b_frames = take(&mut self.backlogged_b_frames);

            // Process backlogged B-Frames
            for (frame_info, encode_slot) in backlogged_b_frames {
                self.encode_slot(frame_info, encode_slot);
            }
        }

        Ok(())
    }

    fn poll_result(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.encoder.poll_result())
    }

    fn wait_result(&mut self) -> Result<Option<Vec<u8>>, Self::Error> {
        Ok(self.encoder.wait_result())
    }
}

impl VkH264Encoder {
    fn encode_slot(&mut self, frame_info: FrameEncodeInfo, encode_slot: VulkanEncodeSlot) {
        let mut setup_dpb_slot = if let Some(dpb_slot) = self.free_dpb_slots.pop() {
            dpb_slot
        } else if let Some(dpb_slot) = self.active_dpb_slots.pop_back() {
            dpb_slot
        } else {
            unreachable!()
        };

        log::trace!("\tUsing setup slot {}", setup_dpb_slot.index);

        setup_dpb_slot.display_index = frame_info.picture_order_count;

        let l0_references = self
            .active_dpb_slots
            .iter()
            .filter(|dpb_slot| dpb_slot.display_index < frame_info.picture_order_count)
            .map(|dpb_slot| dpb_slot.index);

        let l1_references = self
            .active_dpb_slots
            .iter()
            .rev()
            .filter(|dpb_slot| dpb_slot.display_index > frame_info.picture_order_count)
            .map(|dpb_slot| dpb_slot.index);

        let (l0_references, l1_references) = match frame_info.frame_type {
            H264FrameType::P => (
                l0_references.take(self.max_l0_p_ref_images).collect(),
                vec![],
            ),
            H264FrameType::B => (
                l0_references.take(self.max_l0_b_ref_images).collect(),
                l1_references.take(self.max_l1_b_ref_images).collect(),
            ),
            H264FrameType::I | H264FrameType::Idr => (vec![], vec![]),
        };

        let primary_pic_type = match frame_info.frame_type {
            H264FrameType::P => vk::native::StdVideoH264PictureType_STD_VIDEO_H264_PICTURE_TYPE_P,
            H264FrameType::B => vk::native::StdVideoH264PictureType_STD_VIDEO_H264_PICTURE_TYPE_B,
            H264FrameType::I => vk::native::StdVideoH264PictureType_STD_VIDEO_H264_PICTURE_TYPE_I,
            H264FrameType::Idr => {
                vk::native::StdVideoH264PictureType_STD_VIDEO_H264_PICTURE_TYPE_IDR
            }
        };

        let setup_std_reference_info = vk::native::StdVideoEncodeH264ReferenceInfo {
            flags: vk::native::StdVideoEncodeH264ReferenceInfoFlags {
                _bitfield_align_1: [0; 0],
                _bitfield_1: vk::native::StdVideoEncodeH264ReferenceInfoFlags::new_bitfield_1(
                    0, // used_for_long_term_reference
                    0, // reserved
                ),
            },
            primary_pic_type,
            FrameNum: frame_info.frame_num.into(),
            PicOrderCnt: frame_info.picture_order_count.into(),
            long_term_pic_num: 0,
            long_term_frame_idx: 0,
            temporal_id: 0,
        };

        let std_slice_header = vk::native::StdVideoEncodeH264SliceHeader {
            flags: vk::native::StdVideoEncodeH264SliceHeaderFlags {
                _bitfield_align_1: [0; 0],
                _bitfield_1: vk::native::StdVideoEncodeH264SliceHeaderFlags::new_bitfield_1(
                    1, // direct_spatial_mv_pred_flag
                    // TODO: add condition if this must be set
                    1, // num_ref_idx_active_override_flag
                    0, // reserved
                ),
            },
            first_mb_in_slice: 0,
            slice_type: match frame_info.frame_type {
                H264FrameType::P => vk::native::StdVideoH264SliceType_STD_VIDEO_H264_SLICE_TYPE_P,
                H264FrameType::B => vk::native::StdVideoH264SliceType_STD_VIDEO_H264_SLICE_TYPE_B,
                H264FrameType::I => vk::native::StdVideoH264SliceType_STD_VIDEO_H264_SLICE_TYPE_I,
                H264FrameType::Idr => vk::native::StdVideoH264SliceType_STD_VIDEO_H264_SLICE_TYPE_I,
            },
            slice_alpha_c0_offset_div2: 0,
            slice_beta_offset_div2: 0,
            slice_qp_delta: 0,
            reserved1: 0,
            cabac_init_idc: vk::native::StdVideoH264CabacInitIdc_STD_VIDEO_H264_CABAC_INIT_IDC_0,
            disable_deblocking_filter_idc: vk::native::StdVideoH264DisableDeblockingFilterIdc_STD_VIDEO_H264_DISABLE_DEBLOCKING_FILTER_IDC_DISABLED,
            pWeightTable: null_mut(),
        };

        let mut nalu_slices =
            [vk::VideoEncodeH264NaluSliceInfoKHR::default().std_slice_header(&std_slice_header)];

        if let H264RateControlConfig::ConstantQuality {
            const_qp,
            max_bitrate: _,
        } = &self.config.rate_control
        {
            for nalu_slice in &mut nalu_slices {
                nalu_slice.constant_qp = (*const_qp).into();
            }
        }

        let mut ref_lists = unsafe { zeroed::<vk::native::StdVideoEncodeH264ReferenceListsInfo>() };

        let mut l0_iter = l0_references.iter().map(|index| *index as u8);
        ref_lists
            .RefPicList0
            .fill_with(|| l0_iter.next().unwrap_or(0xFF));

        let mut l1_iter = l1_references.iter().map(|index| *index as u8);
        ref_lists
            .RefPicList1
            .fill_with(|| l1_iter.next().unwrap_or(0xFF));

        ref_lists.num_ref_idx_l0_active_minus1 = l0_references.len().saturating_sub(1) as u8;
        ref_lists.num_ref_idx_l1_active_minus1 = l1_references.len().saturating_sub(1) as u8;

        log::trace!("\tRefPicList0: {}", debug_list(&ref_lists.RefPicList0));
        log::trace!("\tRefPicList1: {}", debug_list(&ref_lists.RefPicList1));

        let std_picture_info = vk::native::StdVideoEncodeH264PictureInfo {
            flags: vk::native::StdVideoEncodeH264PictureInfoFlags {
                _bitfield_align_1: [0; 0],
                _bitfield_1: vk::native::StdVideoEncodeH264PictureInfoFlags::new_bitfield_1(
                    (frame_info.frame_type == H264FrameType::Idr) as u32, // IdrPicFlag
                    (frame_info.frame_type != H264FrameType::B) as u32,   // is_reference
                    0, // no_output_of_prior_pics_flag
                    0, // long_term_reference_flag
                    0, // adaptive_ref_pic_marking_mode_flag
                    0, // reserved
                ),
            },
            seq_parameter_set_id: 0,
            pic_parameter_set_id: 0,
            idr_pic_id: frame_info.idr_pic_id,
            primary_pic_type,
            frame_num: frame_info.frame_num.into(),
            PicOrderCnt: frame_info.picture_order_count.into(),
            temporal_id: 0,
            reserved1: [0; 3],
            pRefLists: &raw const ref_lists,
        };

        let picture_info = vk::VideoEncodeH264PictureInfoKHR::default()
            .generate_prefix_nalu(false)
            .nalu_slice_entries(&nalu_slices)
            .std_picture_info(&std_picture_info);

        self.encoder.submit_encode_slot(
            encode_slot,
            l0_references
                .iter()
                .chain(l1_references.iter())
                .copied()
                .collect(),
            setup_dpb_slot.index,
            setup_std_reference_info,
            picture_info,
            frame_info.frame_type == H264FrameType::Idr,
        );

        if frame_info.frame_type == H264FrameType::B {
            self.free_dpb_slots.push(setup_dpb_slot);
        } else {
            self.active_dpb_slots.push_front(setup_dpb_slot);
        }
    }
}

fn debug_list(list: &[u8]) -> String {
    format!(
        "{:?}",
        list.iter().take_while(|x| **x != 0xFF).collect::<Vec<_>>()
    )
}

fn map_profile(profile: Profile) -> Option<vk::native::StdVideoH264ProfileIdc> {
    match profile {
        Profile::Baseline => {
            Some(vk::native::StdVideoH264ProfileIdc_STD_VIDEO_H264_PROFILE_IDC_BASELINE)
        }
        Profile::ConstrainedBaseline => None,
        Profile::Main => Some(vk::native::StdVideoH264ProfileIdc_STD_VIDEO_H264_PROFILE_IDC_MAIN),
        Profile::Extended => None,
        Profile::High => Some(vk::native::StdVideoH264ProfileIdc_STD_VIDEO_H264_PROFILE_IDC_HIGH),
        Profile::High10 => None,
        Profile::High422 => None,
        Profile::High444Predictive => {
            Some(vk::native::StdVideoH264ProfileIdc_STD_VIDEO_H264_PROFILE_IDC_HIGH_444_PREDICTIVE)
        }
        Profile::High10Intra => None,
        Profile::High422Intra => None,
        Profile::High444Intra => None,
        Profile::CAVLC444Intra => None,
    }
}

fn map_level(profile: Level) -> Option<vk::native::StdVideoH264LevelIdc> {
    match profile {
        Level::Level_1_0 => Some(vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_1_0),
        Level::Level_1_B => None,
        Level::Level_1_1 => Some(vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_1_1),
        Level::Level_1_2 => Some(vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_1_2),
        Level::Level_1_3 => Some(vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_1_3),
        Level::Level_2_0 => Some(vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_2_0),
        Level::Level_2_1 => Some(vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_2_1),
        Level::Level_2_2 => Some(vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_2_2),
        Level::Level_3_0 => Some(vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_3_0),
        Level::Level_3_1 => Some(vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_3_1),
        Level::Level_3_2 => Some(vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_3_2),
        Level::Level_4_0 => Some(vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_4_0),
        Level::Level_4_1 => Some(vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_4_1),
        Level::Level_4_2 => Some(vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_4_2),
        Level::Level_5_0 => Some(vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_5_0),
        Level::Level_5_1 => Some(vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_5_1),
        Level::Level_5_2 => Some(vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_5_2),
        Level::Level_6_0 => Some(vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_6_0),
        Level::Level_6_1 => Some(vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_6_1),
        Level::Level_6_2 => Some(vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_6_2),
    }
}

struct RateControl {
    h264_layer: vk::VideoEncodeH264RateControlLayerInfoKHR<'static>,
    layer: vk::VideoEncodeRateControlLayerInfoKHR<'static>,

    h264_info: vk::VideoEncodeH264RateControlInfoKHR<'static>,
    info: vk::VideoEncodeRateControlInfoKHR<'static>,
}

impl RateControl {
    fn default() -> Box<Self> {
        let mut this = Box::new(RateControl {
            h264_layer: vk::VideoEncodeH264RateControlLayerInfoKHR::default(),
            layer: vk::VideoEncodeRateControlLayerInfoKHR::default(),
            h264_info: vk::VideoEncodeH264RateControlInfoKHR::default(),
            info: vk::VideoEncodeRateControlInfoKHR::default(),
        });

        this.layer.p_next = (&raw mut this.h264_layer).cast();
        this.info.p_next = (&raw mut this.h264_info).cast();

        this.info.p_layers = &raw const this.layer;

        this
    }

    fn update_from_config(&mut self, config: &H264EncoderConfig) {
        // TODO: magic value
        self.info.virtual_buffer_size_in_ms = 100;
        self.h264_info.idr_period = config.frame_pattern.intra_idr_period.into();
        self.h264_info.gop_frame_count = config.frame_pattern.intra_period.into();
        self.info.layer_count = 1;

        if let Some(H264FrameRate {
            numerator,
            denominator,
        }) = config.framerate
        {
            self.layer.frame_rate_numerator = numerator;
            self.layer.frame_rate_denominator = denominator;
        } else {
            self.layer.frame_rate_numerator = 1;
            self.layer.frame_rate_denominator = 1;
        }

        if let Some((min_qp, max_qp)) = config.qp {
            set_qp(&mut self.h264_layer, min_qp, max_qp);
        }

        match config.rate_control {
            H264RateControlConfig::ConstantBitRate { bitrate } => {
                self.info.rate_control_mode = vk::VideoEncodeRateControlModeFlagsKHR::CBR;
                self.layer.average_bitrate = bitrate.into();
                self.layer.max_bitrate = bitrate.into();
            }
            H264RateControlConfig::VariableBitRate {
                average_bitrate,
                max_bitrate,
            } => {
                self.info.rate_control_mode = vk::VideoEncodeRateControlModeFlagsKHR::VBR;
                self.layer.average_bitrate = average_bitrate.into();
                self.layer.max_bitrate = max_bitrate.into();
            }
            H264RateControlConfig::ConstantQuality {
                const_qp,
                max_bitrate,
            } => {
                if let Some(max_bitrate) = max_bitrate {
                    // TODO: Trying to limit the bitrate using VBR, vulkan doesn't do CQP currently
                    self.info.rate_control_mode = vk::VideoEncodeRateControlModeFlagsKHR::VBR;
                    self.layer.max_bitrate = max_bitrate.into();
                } else {
                    self.info.rate_control_mode = vk::VideoEncodeRateControlModeFlagsKHR::DISABLED;
                }

                set_qp(&mut self.h264_layer, const_qp, const_qp);
            }
        }
    }
}

fn set_qp(
    h264_layer_rate_control_info: &mut vk::VideoEncodeH264RateControlLayerInfoKHR<'_>,
    min_qp: u8,
    max_qp: u8,
) {
    h264_layer_rate_control_info.min_qp = vk::VideoEncodeH264QpKHR {
        qp_i: min_qp.into(),
        qp_p: min_qp.into(),
        qp_b: min_qp.into(),
    };
    h264_layer_rate_control_info.max_qp = vk::VideoEncodeH264QpKHR {
        qp_i: max_qp.into(),
        qp_p: max_qp.into(),
        qp_b: max_qp.into(),
    };

    h264_layer_rate_control_info.use_min_qp = 1;
    h264_layer_rate_control_info.use_max_qp = 1;
}
