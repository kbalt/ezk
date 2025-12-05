use crate::{
    Level, Profile,
    encoder::{
        config::{FramePattern, Framerate, H264FrameType, SliceMode},
        util::{FrameEncodeInfo, H264EncoderState},
    },
    profile_iop_consts::{
        CONSTRAINT_SET0_FLAG, CONSTRAINT_SET1_FLAG, CONSTRAINT_SET2_FLAG, CONSTRAINT_SET3_FLAG,
        CONSTRAINT_SET4_FLAG, CONSTRAINT_SET5_FLAG,
    },
};
use smallvec::SmallVec;
use std::{
    cmp,
    collections::VecDeque,
    ffi::c_void,
    mem::{take, zeroed},
    pin::Pin,
    ptr::null,
    time::Instant,
};
use vulkan::{
    Device, PhysicalDevice, VulkanError,
    ash::vk,
    encoder::{
        RateControlInfos, VulkanEncodeFrameError, VulkanEncodeSlot, VulkanEncoder,
        VulkanEncoderConfig, VulkanEncoderImplConfig,
        capabilities::{VulkanEncoderCapabilities, VulkanEncoderCapabilitiesError},
        codec::H264,
        input::InputData,
    },
};

#[derive(Debug, Clone, Copy)]
pub struct VulkanH264EncoderConfig {
    pub encoder: VulkanEncoderConfig,
    pub profile: Profile,
    pub level: Level,
    pub frame_pattern: FramePattern,
    pub rate_control: VulkanH264RateControlConfig,
    pub slice_mode: SliceMode,
}

#[derive(Debug, Clone, Copy)]
pub struct VulkanH264RateControlConfig {
    pub mode: VulkanH264RateControlMode,
    pub framerate: Option<Framerate>,
    pub min_qp: Option<u8>,
    pub max_qp: Option<u8>,
}

#[derive(Debug, Clone, Copy)]
pub enum VulkanH264RateControlMode {
    Default,
    ConstantBitrate {
        bitrate: u32,
    },
    VariableBitrate {
        average_bitrate: u32,
        max_bitrate: u32,
    },
    ConstantQuality {
        qp: u8,
    },
}

#[derive(Debug)]
pub struct VkH264Encoder {
    config: VulkanH264EncoderConfig,
    state: H264EncoderState,
    encoder: VulkanEncoder<H264>,

    seq_params: vk::native::StdVideoH264SequenceParameterSet,
    pic_params: vk::native::StdVideoH264PictureParameterSet,

    max_l0_p_ref_images: usize,
    max_l0_b_ref_images: usize,
    max_l1_b_ref_images: usize,

    backlogged_b_frames: Vec<(FrameEncodeInfo, VulkanEncodeSlot)>,
    free_dpb_slots: Vec<DpbSlot>,
    active_dpb_slots: VecDeque<DpbSlot>,
}

unsafe impl Send for VkH264Encoder {}

#[derive(Debug, Clone, Copy)]
struct DpbSlot {
    index: usize,
    display_index: u16,
}

impl VkH264Encoder {
    pub fn capabilities(
        physical_device: &PhysicalDevice,
        profile: Profile,
    ) -> Result<VulkanEncoderCapabilities<H264>, VulkanEncoderCapabilitiesError> {
        let h264_profile_info = vk::VideoEncodeH264ProfileInfoKHR::default()
            .std_profile_idc(profile.profile_idc().into());

        let capabilities =
            VulkanEncoderCapabilities::<H264>::new(physical_device, h264_profile_info)?;

        Ok(capabilities)
    }

    pub fn new(
        device: &Device,
        capabilities: &VulkanEncoderCapabilities<H264>,
        config: VulkanH264EncoderConfig,
    ) -> Result<VkH264Encoder, VulkanError> {
        assert_eq!(
            capabilities.video_codec_profile_info.std_profile_idc,
            config.profile.profile_idc().into(),
            "Passed capabilities created from a different profile than the one in the encoder config"
        );

        let state = H264EncoderState::new(config.frame_pattern);

        let caps = capabilities.video_capabilities;
        let h264_caps = capabilities.video_encode_codec_capabilities;
        let max_references = cmp::max(
            h264_caps.max_p_picture_l0_reference_count,
            h264_caps.max_b_picture_l0_reference_count + h264_caps.max_l1_reference_count,
        );
        let max_active_references = cmp::min(max_references, caps.max_active_reference_pictures);

        // Make only as many dpb slots as can be actively references, + 1 for the setup reference
        let max_dpb_slots = cmp::min(caps.max_dpb_slots, max_active_references + 1);

        let vk::Extent2D { width, height } = config.encoder.initial_encode_resolution;

        let width_mbaligned = width.next_multiple_of(16);
        let height_mbaligned = height.next_multiple_of(16);

        let profile_idc = config.profile.profile_idc();
        let profile_iop = config.profile.profile_iop();

        let seq_params = vk::native::StdVideoH264SequenceParameterSet {
            flags: vk::native::StdVideoH264SpsFlags {
                _bitfield_align_1: [],
                _bitfield_1: vk::native::StdVideoH264SpsFlags::new_bitfield_1(
                    (profile_iop | CONSTRAINT_SET0_FLAG) as u32,
                    (profile_iop | CONSTRAINT_SET1_FLAG) as u32,
                    (profile_iop | CONSTRAINT_SET2_FLAG) as u32,
                    (profile_iop | CONSTRAINT_SET3_FLAG) as u32,
                    (profile_iop | CONSTRAINT_SET4_FLAG) as u32,
                    (profile_iop | CONSTRAINT_SET5_FLAG) as u32,
                    1, // direct_0x0_inference_flag
                    0, // mb_adaptive_frame_field_flag,
                    1, // frame_mbs_only_flag,
                    0, // delta_pic_order_always_zero_flag,
                    0, // separate_colour_plane_flag,
                    0, // gaps_in_frame_num_value_allowed_flag,
                    0, // qpprime_y_zero_transform_bypass_flag,
                    (width != width_mbaligned || height != height_mbaligned).into(), // frame_cropping_flag,
                    0, // seq_scaling_matrix_present_flag,
                    0, // vui_parameters_present_flag,
                ),
                __bindgen_padding_0: 0,
            },
            profile_idc: profile_idc.into(),
            level_idc: map_level(config.level),
            chroma_format_idc:
                vk::native::StdVideoH264ChromaFormatIdc_STD_VIDEO_H264_CHROMA_FORMAT_IDC_420,
            seq_parameter_set_id: 0,
            bit_depth_luma_minus8: 0,
            bit_depth_chroma_minus8: 0,
            log2_max_frame_num_minus4: state.log2_max_frame_num - 4,
            pic_order_cnt_type: 0,
            offset_for_non_ref_pic: 0,
            offset_for_top_to_bottom_field: 0,
            log2_max_pic_order_cnt_lsb_minus4: state.log2_max_pic_order_cnt_lsb - 4,
            num_ref_frames_in_pic_order_cnt_cycle: 0,
            max_num_ref_frames: max_active_references as u8,
            reserved1: 0,
            pic_width_in_mbs_minus1: (width_mbaligned / 16) - 1,
            pic_height_in_map_units_minus1: (height_mbaligned / 16) - 1,
            frame_crop_left_offset: 0,
            frame_crop_right_offset: 0,
            frame_crop_top_offset: (width_mbaligned - width) / 2,
            frame_crop_bottom_offset: (height_mbaligned - height) / 2,
            reserved2: 0,
            pOffsetForRefFrame: null(),
            pScalingLists: null(),
            pSequenceParameterSetVui: null(),
        };

        let pic_params = vk::native::StdVideoH264PictureParameterSet {
            flags: vk::native::StdVideoH264PpsFlags {
                _bitfield_align_1: [],
                _bitfield_1: vk::native::StdVideoH264PpsFlags::new_bitfield_1(
                    config.profile.support_transform_8x8_mode_flag().into(), // transform_8x8_mode_flag,
                    0, // redundant_pic_cnt_present_flag,
                    0, // constrained_intra_pred_flag,
                    0, // deblocking_filter_control_present_flag,
                    0, // weighted_pred_flag,
                    0, // bottom_field_pic_order_in_frame_present_flag,
                    config.profile.support_entropy_coding_mode().into(), // entropy_coding_mode_flag,
                    0, // pic_scaling_matrix_present_flag,
                ),
                __bindgen_padding_0: [0; _],
            },
            seq_parameter_set_id: 0,
            pic_parameter_set_id: 0,
            num_ref_idx_l0_default_active_minus1: 0,
            num_ref_idx_l1_default_active_minus1: 0,
            weighted_bipred_idc: 0,
            pic_init_qp_minus26: 0,
            pic_init_qs_minus26: 0,
            chroma_qp_index_offset: 0,
            second_chroma_qp_index_offset: 0,
            pScalingLists: null(),
        };

        let std_sp_ss = [seq_params];
        let std_pp_ss = [pic_params];
        let video_encode_h264_session_parameters_add_info =
            vk::VideoEncodeH264SessionParametersAddInfoKHR::default()
                .std_sp_ss(&std_sp_ss)
                .std_pp_ss(&std_pp_ss);

        let mut video_encode_h264_session_parameters_create_info =
            vk::VideoEncodeH264SessionParametersCreateInfoKHR::default()
                .max_std_sps_count(u32::MAX)
                .max_std_pps_count(u32::MAX)
                .parameters_add_info(&video_encode_h264_session_parameters_add_info);

        let encoder_config = VulkanEncoderImplConfig {
            user: config.encoder,
            // Set number of encode slots to (num_b_frames + 1) and at least 16
            num_encode_slots: cmp::max(16, u32::from(config.frame_pattern.ip_period) + 1),
            max_active_references,
            num_dpb_slots: max_dpb_slots,
        };

        let encoder = capabilities.create_encoder(
            device,
            encoder_config,
            &mut video_encode_h264_session_parameters_create_info,
            Some(rate_control_from_config(&config)),
        )?;

        let free_dpb_slots = (0..max_dpb_slots as usize)
            .map(|index| DpbSlot {
                index,
                display_index: 0,
            })
            .rev()
            .collect();

        Ok(VkH264Encoder {
            config,
            state,
            encoder,
            seq_params,
            pic_params,
            max_l0_p_ref_images: h264_caps.max_p_picture_l0_reference_count as usize,
            max_l0_b_ref_images: h264_caps.max_b_picture_l0_reference_count as usize,
            max_l1_b_ref_images: h264_caps.max_l1_reference_count as usize,
            backlogged_b_frames: Vec::new(),
            free_dpb_slots,
            active_dpb_slots: VecDeque::new(),
        })
    }

    /// Request the next frame to be an IDR frame
    pub fn request_idr(&mut self) {
        // TODO: this totally blows up b-frames are currently queued
        self.state.begin_new_gop();
    }

    /// Change the output resolution of the encoder
    pub fn update_output_extent(
        &mut self,
        new_extent: vk::Extent2D,
    ) -> Result<(), VulkanEncodeFrameError> {
        if new_extent == self.encoder.current_extent() {
            return Ok(());
        }

        // First drain all backlogged B-Frames since we're going to emit an IDR frame next
        let mut backlogged_b_frames = take(&mut self.backlogged_b_frames);

        // Encode the last frame a P frame
        if let Some((mut frame_info, encode_slot)) = backlogged_b_frames.pop() {
            frame_info.frame_type = H264FrameType::P;
            self.encode_slot(frame_info, encode_slot)?;
        }

        // Then encode all other frames as B-Frames
        for (frame_info, encode_slot) in backlogged_b_frames {
            self.encode_slot(frame_info, encode_slot)?;
        }

        self.state.begin_new_gop();

        // Update the encoder
        let vk::Extent2D { width, height } = new_extent;

        let width_mbaligned = width.next_multiple_of(16);
        let height_mbaligned = height.next_multiple_of(16);

        self.seq_params.flags.set_frame_cropping_flag(
            (width != width_mbaligned || height != height_mbaligned).into(),
        );

        self.seq_params.seq_parameter_set_id += 1;
        self.pic_params.seq_parameter_set_id = self.seq_params.seq_parameter_set_id;
        self.pic_params.pic_parameter_set_id += 1;

        self.seq_params.pic_width_in_mbs_minus1 = (width_mbaligned / 16) - 1;
        self.seq_params.pic_height_in_map_units_minus1 = (height_mbaligned / 16) - 1;

        self.seq_params.frame_crop_top_offset = (width_mbaligned - width) / 2;
        self.seq_params.frame_crop_bottom_offset = (height_mbaligned - height) / 2;

        let parameters = vk::VideoEncodeH264SessionParametersAddInfoKHR::default()
            .std_sp_ss(std::slice::from_ref(&self.seq_params))
            .std_pp_ss(std::slice::from_ref(&self.pic_params));

        self.encoder.update_current_extent(new_extent, parameters)?;

        Ok(())
    }

    pub fn poll_result(&mut self) -> Result<Option<(Instant, Vec<u8>)>, VulkanError> {
        self.encoder.poll_result()
    }

    pub fn wait_result(&mut self) -> Result<Option<(Instant, Vec<u8>)>, VulkanError> {
        self.encoder.wait_result()
    }

    pub fn encode_frame(&mut self, input: InputData<'_>) -> Result<(), VulkanEncodeFrameError> {
        let frame_info = self.state.next();

        log::debug!("Encode {frame_info:?}");

        let mut encode_slot = self
            .encoder
            .pop_encode_slot()?
            .expect("encoder must have enough encode_slots for the given ip_period configuration");

        self.encoder
            .set_input_of_encode_slot(&mut encode_slot, input)?;

        // B-Frames are not encoded immediately, they are queued until after an I or P-frame is encoded
        if frame_info.frame_type == H264FrameType::B {
            self.backlogged_b_frames.push((frame_info, encode_slot));
            return Ok(());
        }

        if frame_info.frame_type == H264FrameType::Idr {
            assert!(self.backlogged_b_frames.is_empty());
            // Just encoded an IDR frame, put all reference surfaces back into the surface pool,
            self.free_dpb_slots.extend(self.active_dpb_slots.drain(..));
        }

        self.encode_slot(frame_info, encode_slot)?;

        if matches!(
            frame_info.frame_type,
            H264FrameType::Idr | H264FrameType::I | H264FrameType::P
        ) {
            let backlogged_b_frames = take(&mut self.backlogged_b_frames);

            // Process backlogged B-Frames
            for (frame_info, encode_slot) in backlogged_b_frames {
                self.encode_slot(frame_info, encode_slot)?;
            }
        }

        Ok(())
    }

    fn encode_slot(
        &mut self,
        frame_info: FrameEncodeInfo,
        encode_slot: VulkanEncodeSlot,
    ) -> Result<(), VulkanEncodeFrameError> {
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

        let (l0_references, l1_references): (SmallVec<[_; 8]>, SmallVec<[_; 1]>) = match frame_info
            .frame_type
        {
            H264FrameType::P => (
                l0_references.take(self.max_l0_p_ref_images).collect(),
                smallvec::smallvec![],
            ),
            H264FrameType::B => (
                l0_references.take(self.max_l0_b_ref_images).collect(),
                l1_references.take(self.max_l1_b_ref_images).collect(),
            ),
            H264FrameType::I | H264FrameType::Idr => (smallvec::smallvec![], smallvec::smallvec![]),
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

        let mut std_slice_headers = vec![];

        let vk::Extent2D { width, height } = self.encoder.current_extent();

        let total_macroblocks = (width / 16) * (height / 16);

        match self.config.slice_mode {
            SliceMode::Picture => {
                std_slice_headers.push(slice_header(&frame_info, 0));
            }
            SliceMode::Rows(num_rows) => {
                for row in (0..height / 16).step_by(num_rows.get() as usize) {
                    let first_macroblock = (width / 16) * row;

                    std_slice_headers.push(slice_header(&frame_info, first_macroblock));
                }
            }
            SliceMode::MacroBlocks(config_num_mbs) => {
                for first_macroblock in
                    (0..total_macroblocks).step_by(config_num_mbs.get() as usize)
                {
                    std_slice_headers.push(slice_header(&frame_info, first_macroblock));
                }
            }
        }

        let mut nalu_slices: SmallVec<[_; 1]> = std_slice_headers
            .iter()
            .map(|std_slice_header| {
                vk::VideoEncodeH264NaluSliceInfoKHR::default().std_slice_header(std_slice_header)
            })
            .collect();

        if let VulkanH264RateControlMode::ConstantQuality { qp } = &self.config.rate_control.mode {
            for nalu_slice in &mut nalu_slices {
                nalu_slice.constant_qp = (*qp).into();
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
            seq_parameter_set_id: self.seq_params.seq_parameter_set_id,
            pic_parameter_set_id: self.pic_params.pic_parameter_set_id,
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
        )?;

        if frame_info.frame_type == H264FrameType::B {
            self.free_dpb_slots.push(setup_dpb_slot);
        } else {
            self.active_dpb_slots.push_front(setup_dpb_slot);
        }

        Ok(())
    }
}

fn slice_header(
    frame_info: &FrameEncodeInfo,
    first_mb_in_slice: u32,
) -> vk::native::StdVideoEncodeH264SliceHeader {
    vk::native::StdVideoEncodeH264SliceHeader {
        flags: vk::native::StdVideoEncodeH264SliceHeaderFlags {
            _bitfield_align_1: [0; 0],
            _bitfield_1: vk::native::StdVideoEncodeH264SliceHeaderFlags::new_bitfield_1(
                1, // direct_spatial_mv_pred_flag
                1, // num_ref_idx_active_override_flag
                0, // reserved
            ),
        },
        first_mb_in_slice,
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
        pWeightTable: null(),
    }
}

fn debug_list(list: &[u8]) -> String {
    format!(
        "{:?}",
        list.iter().take_while(|x| **x != 0xFF).collect::<Vec<_>>()
    )
}

fn map_level(profile: Level) -> vk::native::StdVideoH264LevelIdc {
    match profile {
        Level::Level_1_0 => vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_1_0,
        // TODO: not super excited about silently discarding the B here, just hoping noone is actually using this
        Level::Level_1_B => vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_1_0,
        Level::Level_1_1 => vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_1_1,
        Level::Level_1_2 => vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_1_2,
        Level::Level_1_3 => vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_1_3,
        Level::Level_2_0 => vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_2_0,
        Level::Level_2_1 => vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_2_1,
        Level::Level_2_2 => vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_2_2,
        Level::Level_3_0 => vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_3_0,
        Level::Level_3_1 => vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_3_1,
        Level::Level_3_2 => vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_3_2,
        Level::Level_4_0 => vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_4_0,
        Level::Level_4_1 => vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_4_1,
        Level::Level_4_2 => vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_4_2,
        Level::Level_5_0 => vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_5_0,
        Level::Level_5_1 => vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_5_1,
        Level::Level_5_2 => vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_5_2,
        Level::Level_6_0 => vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_6_0,
        Level::Level_6_1 => vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_6_1,
        Level::Level_6_2 => vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_6_2,
    }
}

fn rate_control_from_config(config: &VulkanH264EncoderConfig) -> Pin<Box<RateControlInfos<H264>>> {
    let mut this = Box::pin(RateControlInfos::<H264> {
        codec_layer: vk::VideoEncodeH264RateControlLayerInfoKHR::default(),
        layer: vk::VideoEncodeRateControlLayerInfoKHR::default(),
        codec_info: vk::VideoEncodeH264RateControlInfoKHR::default(),
        info: vk::VideoEncodeRateControlInfoKHR::default(),
    });

    this.layer.p_next = (&raw const this.codec_layer) as *const c_void;
    this.info.p_next = (&raw const this.codec_info) as *const c_void;
    this.info.p_layers = &raw const this.layer;

    // TODO: magic value
    this.codec_info.idr_period = config.frame_pattern.intra_idr_period.into();
    this.codec_info.gop_frame_count = config.frame_pattern.intra_period.into();
    this.info.virtual_buffer_size_in_ms = 100;
    this.info.layer_count = 1;

    if let Some(Framerate { num, denom }) = config.rate_control.framerate {
        this.layer.frame_rate_numerator = num;
        this.layer.frame_rate_denominator = denom;
    } else {
        this.layer.frame_rate_numerator = 1;
        this.layer.frame_rate_denominator = 1;
    }

    if let Some(min_qp) = config.rate_control.min_qp {
        this.codec_layer.min_qp = vk::VideoEncodeH264QpKHR {
            qp_i: min_qp.into(),
            qp_p: min_qp.into(),
            qp_b: min_qp.into(),
        };

        this.codec_layer.use_min_qp = vk::TRUE;
    } else {
        this.codec_layer.use_min_qp = vk::FALSE;
    }

    if let Some(max_qp) = config.rate_control.max_qp {
        this.codec_layer.max_qp = vk::VideoEncodeH264QpKHR {
            qp_i: max_qp.into(),
            qp_p: max_qp.into(),
            qp_b: max_qp.into(),
        };

        this.codec_layer.use_max_qp = vk::TRUE;
    } else {
        this.codec_layer.use_max_qp = vk::FALSE;
    }

    match config.rate_control.mode {
        VulkanH264RateControlMode::Default => {
            this.info.rate_control_mode = vk::VideoEncodeRateControlModeFlagsKHR::DEFAULT;
        }
        VulkanH264RateControlMode::ConstantBitrate { bitrate } => {
            this.info.rate_control_mode = vk::VideoEncodeRateControlModeFlagsKHR::CBR;
            this.layer.average_bitrate = bitrate.into();
            this.layer.max_bitrate = bitrate.into();
        }
        VulkanH264RateControlMode::VariableBitrate {
            average_bitrate,
            max_bitrate,
        } => {
            this.info.rate_control_mode = vk::VideoEncodeRateControlModeFlagsKHR::VBR;
            this.layer.average_bitrate = average_bitrate.into();
            this.layer.max_bitrate = max_bitrate.into();
        }
        VulkanH264RateControlMode::ConstantQuality { .. } => {
            this.info.rate_control_mode = vk::VideoEncodeRateControlModeFlagsKHR::DISABLED;
        }
    }

    this
}
