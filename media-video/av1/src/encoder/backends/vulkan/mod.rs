use smallvec::SmallVec;
use std::{collections::VecDeque, ffi::c_void, pin::Pin, ptr::null, time::Instant};
use vulkan::{
    Device, PhysicalDevice, VulkanError,
    ash::vk,
    encoder::{
        RateControlInfos, VulkanEncodeFrameError, VulkanEncodeSlot, VulkanEncoder,
        VulkanEncoderConfig, VulkanEncoderImplConfig,
        capabilities::{VulkanEncoderCapabilities, VulkanEncoderCapabilitiesError},
        codec::AV1,
        input::InputData,
    },
};

use crate::{
    AV1Framerate, AV1Level, AV1Profile,
    encoder::util::{AV1EncoderState, AV1FramePattern, FrameEncodeInfo},
};

#[derive(Debug, Clone, Copy)]
pub struct VulkanAV1EncoderConfig {
    pub encoder: VulkanEncoderConfig,
    pub profile: AV1Profile,
    pub level: AV1Level,
    pub frame_pattern: AV1FramePattern,
    pub rate_control: VulkanAV1RateControlConfig,
}

#[derive(Debug, Clone, Copy)]
pub struct VulkanAV1RateControlConfig {
    /// Rate control mode for the AV1 encoder
    pub mode: VulkanAV1RateControlMode,

    /// Expected framerate of the video stream. Default to 60 frames per second
    pub framerate: Option<AV1Framerate>,

    /// Maximum Quality index. 0 is highest quality & 255 is the lowest quality
    ///
    /// Must be equal or smaller than max_q_index
    pub min_q_index: Option<u32>,

    /// Minimum Quality index. 0 is highest quality & 255 is the lowest quality
    ///
    /// Must be equal or greater than min_q_index
    pub max_q_index: Option<u32>,
}

#[derive(Debug, Clone, Copy)]
pub enum VulkanAV1RateControlMode {
    Default,
    ConstantBitrate {
        bitrate: u32,
    },
    VariableBitrate {
        average_bitrate: u32,
        max_bitrate: u32,
    },
    ConstantQuality {
        q_index: u32,
    },
}

#[derive(Debug)]
pub struct VkAV1Encoder {
    config: VulkanAV1EncoderConfig,
    state: AV1EncoderState,
    encoder: VulkanEncoder<AV1>,

    caps: VulkanEncoderCapabilities<AV1>,

    free_dpb_slots: Vec<DpbSlot>,
    active_dpb_slots: VecDeque<DpbSlot>,
}

#[derive(Debug, Clone, Copy)]
struct DpbSlot {
    index: usize,
    order_hint: u8,
}

impl VkAV1Encoder {
    pub fn capabilities(
        physical_device: &PhysicalDevice,
        profile: AV1Profile,
    ) -> Result<VulkanEncoderCapabilities<AV1>, VulkanEncoderCapabilitiesError> {
        let av1_profile_info =
            vk::VideoEncodeAV1ProfileInfoKHR::default().std_profile(match profile {
                AV1Profile::Main => vk::native::StdVideoAV1Profile_STD_VIDEO_AV1_PROFILE_MAIN,
                AV1Profile::High => vk::native::StdVideoAV1Profile_STD_VIDEO_AV1_PROFILE_HIGH,
                AV1Profile::Professional => {
                    vk::native::StdVideoAV1Profile_STD_VIDEO_AV1_PROFILE_PROFESSIONAL
                }
            });

        let capabilities =
            VulkanEncoderCapabilities::<AV1>::new(physical_device, av1_profile_info)?;

        Ok(capabilities)
    }

    pub fn new(
        device: &Device,
        caps: &VulkanEncoderCapabilities<AV1>,
        config: VulkanAV1EncoderConfig,
    ) -> Result<VkAV1Encoder, VulkanError> {
        let profile = match config.profile {
            AV1Profile::Main => vk::native::StdVideoAV1Profile_STD_VIDEO_AV1_PROFILE_MAIN,
            AV1Profile::High => vk::native::StdVideoAV1Profile_STD_VIDEO_AV1_PROFILE_HIGH,
            AV1Profile::Professional => {
                vk::native::StdVideoAV1Profile_STD_VIDEO_AV1_PROFILE_PROFESSIONAL
            }
        };

        let std_sequence_header = vk::native::StdVideoAV1SequenceHeader {
            flags: vk::native::StdVideoAV1SequenceHeaderFlags {
                _bitfield_align_1: [],
                _bitfield_1: {
                    vk::native::StdVideoAV1SequenceHeaderFlags::new_bitfield_1(
                        0, // still_picture
                        0, // reduced_still_picture_header
                        0, // use_128x128_superblock
                        0, // enable_filter_intra
                        0, // enable_intra_edge_filter
                        0, // enable_interintra_compound
                        0, // enable_masked_compound
                        0, // enable_warped_motion
                        0, // enable_dual_filter
                        1, // enable_order_hint
                        0, // enable_jnt_comp
                        0, // enable_ref_frame_mvs
                        0, // frame_id_numbers_present_flag
                        0, // enable_superres,
                        0, // enable_cdef,
                        1, // enable_restoration,
                        0, // film_grain_params_present,
                        0, // timing_info_present_flag,
                        0, // initial_display_delay_present_flag,
                        0, // reserved
                    )
                },
            },
            seq_profile: profile,
            frame_width_bits_minus_1: 11, // 4096x4096 is maximum for now
            frame_height_bits_minus_1: 11,
            max_frame_width_minus_1: (config.encoder.max_encode_resolution.width - 1) as u16,
            max_frame_height_minus_1: (config.encoder.max_encode_resolution.height - 1) as u16,
            delta_frame_id_length_minus_2: 0,
            additional_frame_id_length_minus_1: 0,
            order_hint_bits_minus_1: 7, // 8 bits for order hint
            seq_force_integer_mv: 0,
            seq_force_screen_content_tools: 0,
            reserved1: [0u8; 5],
            pColorConfig: null(),
            pTimingInfo: null(),
        };

        let video_encode_av1_session_parameters_create_info =
            vk::VideoEncodeAV1SessionParametersCreateInfoKHR::default()
                .std_sequence_header(&std_sequence_header);

        let encoder_config = VulkanEncoderImplConfig {
            user: config.encoder,
            num_encode_slots: 4,
            max_active_references: 7,
            num_dpb_slots: 8,
        };

        let av1_profile_info = vk::VideoEncodeAV1ProfileInfoKHR::default().std_profile(profile);

        let encoder = caps.create_encoder(
            device,
            encoder_config,
            av1_profile_info,
            vk::VideoEncodeAV1SessionCreateInfoKHR::default()
                .max_level(map_level(config.level))
                .use_max_level(true),
            video_encode_av1_session_parameters_create_info,
            Some(rate_control_from_config(&config, caps)),
        )?;

        let free_dpb_slots = (0..8)
            .map(|index| DpbSlot {
                index,
                order_hint: 0,
            })
            .rev()
            .collect();

        Ok(VkAV1Encoder {
            config,
            state: AV1EncoderState::new(config.frame_pattern),
            encoder,
            caps: caps.clone(),
            free_dpb_slots,
            active_dpb_slots: VecDeque::new(),
        })
    }

    /// Request the next frame to be an IDR frame
    pub fn request_idr(&mut self) {
        // TODO: this totally blows up b-frames are currently queued
        self.state.request_keyframe();
    }

    /// Update the encoders rate control config
    pub fn update_rate_control(&mut self, rate_control: VulkanAV1RateControlConfig) {
        unsafe {
            self.config.rate_control = rate_control;

            self.encoder
                .update_rc(rate_control_from_config(&self.config, &self.caps));
        }
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

        if frame_info.is_key {
            self.free_dpb_slots.extend(self.active_dpb_slots.drain(..));
        }

        self.encode_slot(frame_info, encode_slot)?;

        Ok(())
    }

    fn encode_slot(
        &mut self,
        frame_info: FrameEncodeInfo,
        encode_slot: VulkanEncodeSlot,
    ) -> Result<(), VulkanEncodeFrameError> {
        // Reference Frame Name indices

        const LAST_FRAME: u8 = 0;
        const LAST2_FRAME: u8 = 1;
        const LAST3_FRAME: u8 = 2;
        const GOLDEN_FRAME: u8 = 3;
        // const BWDREF_FRAME: u8 = 4;
        // const ALTREF2_FRAME: u8 = 5;
        // const ALTREF_FRAME: u8 = 6;

        let mut setup_dpb_slot = if let Some(dpb_slot) = self.free_dpb_slots.pop() {
            dpb_slot
        } else if let Some(dpb_slot) = self.active_dpb_slots.pop_back() {
            dpb_slot
        } else {
            unreachable!()
        };

        setup_dpb_slot.order_hint = frame_info.order_hint;

        let frame_type = if frame_info.is_key {
            vk::native::StdVideoAV1FrameType_STD_VIDEO_AV1_FRAME_TYPE_KEY
        } else {
            vk::native::StdVideoAV1FrameType_STD_VIDEO_AV1_FRAME_TYPE_INTER
        };

        let caps = &self.caps.codec;

        let (prediction_mode, max_reference_frames, name_mask) = if frame_info.is_key {
            // INTRA Frame for Keyframes
            (vk::VideoEncodeAV1PredictionModeKHR::INTRA_ONLY, 0, 0)
        } else if self.active_dpb_slots.len() >= 2
            && caps.max_unidirectional_compound_group1_reference_count >= 2
        {
            // When 2 or more references are active & UNIDIRECTIONAL_COMPOUND allows for 2 or more
            (
                vk::VideoEncodeAV1PredictionModeKHR::UNIDIRECTIONAL_COMPOUND,
                caps.max_unidirectional_compound_group1_reference_count,
                caps.unidirectional_compound_reference_name_mask,
            )
        } else if self.active_dpb_slots.len() == 1 && caps.single_reference_name_mask == 1 {
            (
                vk::VideoEncodeAV1PredictionModeKHR::SINGLE_REFERENCE,
                1,
                caps.single_reference_name_mask,
            )
        } else {
            panic!("Failed to identify prediction mode");
        };

        let reference_slots: SmallVec<[_; 8]> = self
            .active_dpb_slots
            .iter()
            .take(max_reference_frames as usize)
            .take(name_mask.count_ones() as usize)
            .collect();

        log::trace!("\tUsing setup slot {}", setup_dpb_slot.index);

        let ref_frame_idx = {
            let mut iter = reference_slots.iter().map(|x| x.index as i8);

            let mut ref_frame_idx = [-1; 7];

            if name_mask & (1 << LAST_FRAME) != 0 {
                ref_frame_idx[LAST_FRAME as usize] = iter.next().unwrap_or(-1);
            }
            if name_mask & (1 << LAST2_FRAME) != 0 {
                ref_frame_idx[LAST2_FRAME as usize] = iter.next().unwrap_or(-1);
            }
            if name_mask & (1 << LAST3_FRAME) != 0 {
                ref_frame_idx[LAST3_FRAME as usize] = iter.next().unwrap_or(-1);
            }
            if name_mask & (1 << GOLDEN_FRAME) != 0 {
                ref_frame_idx[GOLDEN_FRAME as usize] = iter.next().unwrap_or(-1);
            }

            assert!(iter.next().is_none());

            ref_frame_idx
        };

        let reference_name_slot_indices = ref_frame_idx.map(i32::from);

        let ref_order_hint = {
            let mut ref_order_hint = [0; 8];

            for dpb_slot in &self.active_dpb_slots {
                ref_order_hint[dpb_slot.index] = dpb_slot.order_hint;
            }

            ref_order_hint
        };

        log::trace!("\treference_name_slot_indices {reference_name_slot_indices:?}");
        log::trace!("\tref_frame_idx {ref_frame_idx:?}");
        log::trace!("\tref_order_hint {ref_order_hint:?}");

        let loop_restoration = vk::native::StdVideoAV1LoopRestoration {
            FrameRestorationType: [vk::native::StdVideoAV1FrameRestorationType_STD_VIDEO_AV1_FRAME_RESTORATION_TYPE_SGRPROJ; 3],
            LoopRestorationSize: [64; 3],
        };

        let setup_std_reference_info = vk::native::StdVideoEncodeAV1ReferenceInfo {
            flags: vk::native::StdVideoEncodeAV1ReferenceInfoFlags {
                _bitfield_align_1: [0; 0],
                _bitfield_1: vk::native::StdVideoEncodeAV1ReferenceInfoFlags::new_bitfield_1(
                    0, // disable_frame_end_update_cdf,
                    0, // segmentation_enabled,
                    0, // reserved,
                ),
            },
            RefFrameId: frame_info.current_frame_id,
            frame_type,
            OrderHint: frame_info.order_hint,
            reserved1: [0; 3],
            pExtensionHeader: null(),
        };

        let std_picture_info = vk::native::StdVideoEncodeAV1PictureInfo {
            flags: vk::native::StdVideoEncodeAV1PictureInfoFlags {
                _bitfield_align_1: [],
                _bitfield_1: vk::native::StdVideoEncodeAV1PictureInfoFlags::new_bitfield_1(
                    0, // error_resilient_mode,
                    0, // disable_cdf_update,
                    0, // use_superres,
                    0, // render_and_frame_size_different,
                    0, // allow_screen_content_tools,
                    0, // is_filter_switchable,
                    0, // force_integer_mv,
                    0, // frame_size_override_flag,TODO
                    0, // buffer_removal_time_present_flag,
                    1, // allow_intrabc,
                    0, // frame_refs_short_signaling, TODO??
                    0, // allow_high_precision_mv,
                    1, // is_motion_mode_switchable,
                    1, // use_ref_frame_mvs,
                    0, // disable_frame_end_update_cdf,
                    0, // allow_warped_motion,
                    0, // reduced_tx_set, TODO?
                    0, // skip_mode_present,
                    0, // delta_q_present,
                    0, // delta_lf_present,
                    0, // delta_lf_multi,
                    0, // segmentation_enabled,
                    0, // segmentation_update_map,
                    0, // segmentation_temporal_update,
                    0, // segmentation_update_data,
                    1, // UsesLr,
                    1, // usesChromaLr,
                    1, // show_frame
                    0, // showable_frame,
                    0, // reserved,
                ),
            },
            frame_type,
            frame_presentation_time: 0,
            current_frame_id: frame_info.current_frame_id,
            order_hint: frame_info.order_hint,
            primary_ref_frame: 7,
            refresh_frame_flags: if frame_info.is_key { 0xFF } else { 1 << setup_dpb_slot.index },
            coded_denom: 0,
            render_width_minus_1: (self.encoder.current_extent().width - 1) as u16,
            render_height_minus_1: (self.encoder.current_extent().height - 1) as u16,
            interpolation_filter:  vk::native::StdVideoAV1InterpolationFilter_STD_VIDEO_AV1_INTERPOLATION_FILTER_EIGHTTAP,
            TxMode: vk::native::StdVideoAV1TxMode_STD_VIDEO_AV1_TX_MODE_LARGEST,
            delta_q_res: 0,
            delta_lf_res: 0,
            ref_order_hint,
            ref_frame_idx,
            reserved1: [0u8; 3],
            delta_frame_id_minus_1: [0; 7],
            pTileInfo: null(),
            pQuantization: null(),
            pSegmentation: null(),
            pLoopFilter: null(),
            pCDEF: null(),
            pLoopRestoration:  &raw const loop_restoration,
            pGlobalMotion: null(),
            pExtensionHeader: null(),
            pBufferRemovalTimes: null(),
        };

        let rate_control_group = if frame_info.is_key {
            vk::VideoEncodeAV1RateControlGroupKHR::INTRA
        } else {
            vk::VideoEncodeAV1RateControlGroupKHR::PREDICTIVE
        };

        let mut picture_info = vk::VideoEncodeAV1PictureInfoKHR::default()
            .std_picture_info(&std_picture_info)
            .prediction_mode(prediction_mode)
            .reference_name_slot_indices(reference_name_slot_indices)
            .rate_control_group(rate_control_group)
            .primary_reference_cdf_only(false)
            .generate_obu_extension_header(false);

        if let VulkanAV1RateControlMode::ConstantQuality { q_index } = self.config.rate_control.mode
        {
            picture_info = picture_info.constant_q_index(q_index);
        }

        self.encoder.submit_encode_slot(
            encode_slot,
            reference_slots.into_iter().map(|slot| slot.index).collect(),
            setup_dpb_slot.index,
            setup_std_reference_info,
            picture_info,
            frame_info.is_key,
        )?;

        self.active_dpb_slots.push_front(setup_dpb_slot);

        Ok(())
    }
}

fn map_level(profile: AV1Level) -> vk::native::StdVideoAV1Level {
    match profile {
        AV1Level::Level_2_0 => vk::native::StdVideoAV1Level_STD_VIDEO_AV1_LEVEL_2_0,
        AV1Level::Level_2_1 => vk::native::StdVideoAV1Level_STD_VIDEO_AV1_LEVEL_2_1,
        AV1Level::Level_2_2 => vk::native::StdVideoAV1Level_STD_VIDEO_AV1_LEVEL_2_2,
        AV1Level::Level_2_3 => vk::native::StdVideoAV1Level_STD_VIDEO_AV1_LEVEL_2_3,
        AV1Level::Level_3_0 => vk::native::StdVideoAV1Level_STD_VIDEO_AV1_LEVEL_3_0,
        AV1Level::Level_3_1 => vk::native::StdVideoAV1Level_STD_VIDEO_AV1_LEVEL_3_1,
        AV1Level::Level_3_2 => vk::native::StdVideoAV1Level_STD_VIDEO_AV1_LEVEL_3_2,
        AV1Level::Level_3_3 => vk::native::StdVideoAV1Level_STD_VIDEO_AV1_LEVEL_3_3,
        AV1Level::Level_4_0 => vk::native::StdVideoAV1Level_STD_VIDEO_AV1_LEVEL_4_0,
        AV1Level::Level_4_1 => vk::native::StdVideoAV1Level_STD_VIDEO_AV1_LEVEL_4_1,
        AV1Level::Level_4_2 => vk::native::StdVideoAV1Level_STD_VIDEO_AV1_LEVEL_4_2,
        AV1Level::Level_4_3 => vk::native::StdVideoAV1Level_STD_VIDEO_AV1_LEVEL_4_3,
        AV1Level::Level_5_0 => vk::native::StdVideoAV1Level_STD_VIDEO_AV1_LEVEL_5_0,
        AV1Level::Level_5_1 => vk::native::StdVideoAV1Level_STD_VIDEO_AV1_LEVEL_5_1,
        AV1Level::Level_5_2 => vk::native::StdVideoAV1Level_STD_VIDEO_AV1_LEVEL_5_2,
        AV1Level::Level_5_3 => vk::native::StdVideoAV1Level_STD_VIDEO_AV1_LEVEL_5_3,
        AV1Level::Level_6_0 => vk::native::StdVideoAV1Level_STD_VIDEO_AV1_LEVEL_6_0,
        AV1Level::Level_6_1 => vk::native::StdVideoAV1Level_STD_VIDEO_AV1_LEVEL_6_1,
        AV1Level::Level_6_2 => vk::native::StdVideoAV1Level_STD_VIDEO_AV1_LEVEL_6_2,
        AV1Level::Level_6_3 => vk::native::StdVideoAV1Level_STD_VIDEO_AV1_LEVEL_6_3,
        AV1Level::Level_7_0 => vk::native::StdVideoAV1Level_STD_VIDEO_AV1_LEVEL_7_0,
        AV1Level::Level_7_1 => vk::native::StdVideoAV1Level_STD_VIDEO_AV1_LEVEL_7_1,
        AV1Level::Level_7_2 => vk::native::StdVideoAV1Level_STD_VIDEO_AV1_LEVEL_7_2,
        AV1Level::Level_7_3 => vk::native::StdVideoAV1Level_STD_VIDEO_AV1_LEVEL_7_3,
    }
}

fn rate_control_from_config(
    config: &VulkanAV1EncoderConfig,
    caps: &VulkanEncoderCapabilities<AV1>,
) -> Pin<Box<RateControlInfos<AV1>>> {
    let mut this = Box::pin(RateControlInfos::<AV1> {
        codec_layer: vk::VideoEncodeAV1RateControlLayerInfoKHR::default(),
        layer: vk::VideoEncodeRateControlLayerInfoKHR::default(),
        codec_info: vk::VideoEncodeAV1RateControlInfoKHR::default(),
        info: vk::VideoEncodeRateControlInfoKHR::default(),
    });

    this.layer.p_next = (&raw const this.codec_layer) as *const c_void;
    this.info.p_next = (&raw const this.codec_info) as *const c_void;
    this.info.p_layers = &raw const this.layer;
    this.info.layer_count = 1;

    this.codec_info.key_frame_period = config.frame_pattern.keyframe_interval.into();
    this.codec_info.gop_frame_count = config.frame_pattern.keyframe_interval.into();
    this.codec_info.consecutive_bipredictive_frame_count = 0; // TODO BIPRED not supported atm
    this.codec_info.temporal_layer_count = 1;
    this.codec_info.flags |= vk::VideoEncodeAV1RateControlFlagsKHR::REGULAR_GOP; // TODO BIPRED not supported atm

    // TODO: magic value
    this.info.virtual_buffer_size_in_ms = 1000;
    this.info.initial_virtual_buffer_size_in_ms = 1000;

    if let Some(AV1Framerate { num, denom }) = config.rate_control.framerate {
        this.layer.frame_rate_numerator = num;
        this.layer.frame_rate_denominator = denom;
    } else {
        this.layer.frame_rate_numerator = 60;
        this.layer.frame_rate_denominator = 1;
    }

    let cap_min_q_index = caps.codec.min_q_index;
    let cap_max_q_index = caps.codec.max_q_index;

    // TODO: RADV doesn't seem to care about rate control unless min & max qp are enabled?
    let min_q_index = Some(
        config
            .rate_control
            .min_q_index
            .map_or(cap_min_q_index, |i| {
                i.clamp(cap_min_q_index, cap_max_q_index)
            }),
    );
    let max_q_index = Some(
        config
            .rate_control
            .max_q_index
            .map_or(cap_max_q_index, |i| {
                i.clamp(cap_min_q_index, cap_max_q_index)
            }),
    );

    if let Some(min_q_index) = min_q_index {
        this.codec_layer.min_q_index = vk::VideoEncodeAV1QIndexKHR {
            intra_q_index: min_q_index,
            predictive_q_index: min_q_index,
            bipredictive_q_index: min_q_index,
        };

        this.codec_layer.use_min_q_index = vk::TRUE;
    } else {
        this.codec_layer.use_min_q_index = vk::FALSE;
    }

    if let Some(max_q_index) = max_q_index {
        this.codec_layer.max_q_index = vk::VideoEncodeAV1QIndexKHR {
            intra_q_index: max_q_index,
            predictive_q_index: max_q_index,
            bipredictive_q_index: max_q_index,
        };

        this.codec_layer.use_max_q_index = vk::TRUE;
    } else {
        this.codec_layer.use_max_q_index = vk::FALSE;
    }

    match config.rate_control.mode {
        VulkanAV1RateControlMode::Default => {
            this.info.rate_control_mode = vk::VideoEncodeRateControlModeFlagsKHR::DEFAULT;
        }
        VulkanAV1RateControlMode::ConstantBitrate { bitrate } => {
            this.info.rate_control_mode = vk::VideoEncodeRateControlModeFlagsKHR::CBR;
            this.layer.average_bitrate = bitrate.into();
            this.layer.max_bitrate = bitrate.into();
        }
        VulkanAV1RateControlMode::VariableBitrate {
            average_bitrate,
            max_bitrate,
        } => {
            this.info.rate_control_mode = vk::VideoEncodeRateControlModeFlagsKHR::VBR;
            this.layer.average_bitrate = average_bitrate.into();
            this.layer.max_bitrate = max_bitrate.into();
        }
        VulkanAV1RateControlMode::ConstantQuality { .. } => {
            this.info.rate_control_mode = vk::VideoEncodeRateControlModeFlagsKHR::DISABLED;
        }
    }

    this
}
