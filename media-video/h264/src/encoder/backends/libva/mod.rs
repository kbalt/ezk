use crate::{
    H264Level, H264Profile,
    encoder::{
        config::{FramePattern, H264FrameType, SliceMode},
        util::{FrameEncodeInfo, H264EncoderState},
    },
};
use ezk_image::ImageRef;
use libva::{
    Buffer, Display, RtFormat, VaError,
    encoder::{
        VaEncodeFrameError, VaEncodeSlot, VaEncoder, VaEncoderCapabilities,
        VaEncoderCapabilitiesError, VaEncoderConfig, VaEncoderCreateError, VaEncoderImplConfig,
        VaEncoderRateControlMode,
    },
    ffi,
};
use std::{
    cmp,
    collections::VecDeque,
    mem::{take, zeroed},
};

mod bitstream;

#[derive(Debug, Clone, Copy)]
pub struct VaH264EncoderConfig {
    pub encoder: VaEncoderConfig,
    pub profile: H264Profile,
    pub level: H264Level,
    pub frame_pattern: FramePattern,
    pub slice_mode: SliceMode,
}

pub struct VaH264Encoder {
    config: VaH264EncoderConfig,
    state: H264EncoderState,
    encoder: VaEncoder,

    max_l0_references: usize,
    max_l1_references: usize,

    backlogged_b_frames: Vec<(FrameEncodeInfo, VaEncodeSlot)>,
    free_dpb_slots: Vec<DpbSlot>,
    active_dpb_slots: VecDeque<DpbSlot>,
}

struct DpbSlot {
    index: usize,
    picture: ffi::VAPictureH264,
}

impl VaH264Encoder {
    pub fn profiles(display: &Display) -> Result<Vec<H264Profile>, VaError> {
        let mut profiles = Vec::new();

        for va_profile in display.profiles()? {
            let profile = match va_profile {
                ffi::VAProfile_VAProfileH264Baseline => H264Profile::Baseline,
                ffi::VAProfile_VAProfileH264ConstrainedBaseline => H264Profile::ConstrainedBaseline,
                ffi::VAProfile_VAProfileH264High => H264Profile::High,
                ffi::VAProfile_VAProfileH264High10 => H264Profile::High10,
                ffi::VAProfile_VAProfileH264Main => H264Profile::Main,
                _ => continue,
            };

            let entrypoints = display.entrypoints(va_profile)?;

            let supports_encode = entrypoints.contains(&ffi::VAEntrypoint_VAEntrypointEncSlice)
                || entrypoints.contains(&ffi::VAEntrypoint_VAEntrypointEncSliceLP);

            if supports_encode {
                profiles.push(profile);
            }
        }

        Ok(profiles)
    }

    pub fn capabilities(
        display: &Display,
        profile: H264Profile,
    ) -> Result<VaEncoderCapabilities, VaEncoderCapabilitiesError> {
        let va_profile = profile_to_va_profile(profile)
            .expect("Passed profile which was not returned by VaH264Encoder::profiles");

        VaEncoderCapabilities::new(display, va_profile)
    }

    pub fn new(
        capabilities: &VaEncoderCapabilities,
        mut config: VaH264EncoderConfig,
    ) -> Result<VaH264Encoder, VaEncoderCreateError> {
        if !config.profile.support_b_frames() {
            config.frame_pattern.ip_period = 1;
        }

        let va_profile = profile_to_va_profile(config.profile)
            .expect("Profile in config must be returned by VaH264Encoder::profiles");

        assert_eq!(
            va_profile,
            capabilities.profile(),
            "Profile must be the same the capabilites were queried for"
        );

        config.encoder.max_encode_resolution[0] =
            config.encoder.max_encode_resolution[0].next_multiple_of(16);
        config.encoder.max_encode_resolution[1] =
            config.encoder.max_encode_resolution[1].next_multiple_of(16);

        let contains = |rt_format| {
            capabilities
                .rt_formats
                .contains(rt_format)
                .then_some(rt_format)
        };

        // compile_error!("Investigate input image formats for 10/12 bit RT FORMATS");

        let va_rt_format = contains(RtFormat::YUV420)
            .or(contains(RtFormat::YUV422))
            .or(contains(RtFormat::YUV444))
            .or(contains(RtFormat::YUV420_10))
            .or(contains(RtFormat::YUV422_10))
            .or(contains(RtFormat::YUV444_10))
            .or(contains(RtFormat::YUV420_12))
            .or(contains(RtFormat::YUV422_12))
            .or(contains(RtFormat::YUV444_12))
            .unwrap();

        let num_dpb_slots = 16;

        let encoder = capabilities.create_encoder(VaEncoderImplConfig {
            user: config.encoder,
            va_rt_format,
            num_dpb_slots: 16,
            num_encode_slots: cmp::max(16, u32::from(config.frame_pattern.ip_period) + 1),
        })?;

        let (max_l0_references, max_l1_references) = {
            let [b0, b1, b2, b3] = capabilities.max_reference_frames.to_ne_bytes();

            (u16::from_ne_bytes([b0, b1]), u16::from_ne_bytes([b2, b3]))
        };

        let free_dpb_slots = (0..num_dpb_slots)
            .map(|index| DpbSlot {
                index,
                picture: ffi::VAPictureH264 {
                    picture_id: ffi::VA_INVALID_SURFACE,
                    flags: ffi::VA_PICTURE_H264_INVALID,
                    ..unsafe { zeroed() }
                },
            })
            .collect();

        Ok(VaH264Encoder {
            config,
            state: H264EncoderState::new(config.frame_pattern),
            encoder,
            max_l0_references: max_l0_references as usize,
            max_l1_references: max_l1_references as usize,
            backlogged_b_frames: Vec::new(),
            free_dpb_slots,
            active_dpb_slots: VecDeque::new(),
        })
    }

    pub fn request_idr(&mut self) {
        // TODO: this blows up when B-Frames are queued
        self.state.begin_new_gop();
    }

    pub fn poll_result(&mut self) -> Result<Option<Vec<u8>>, VaError> {
        self.encoder.poll_result()
    }

    pub fn wait_result(&mut self) -> Result<Option<Vec<u8>>, VaError> {
        self.encoder.wait_result()
    }

    pub fn encode_frame(&mut self, image: &dyn ImageRef) -> Result<(), VaEncodeFrameError> {
        let frame_info = self.state.next();

        log::debug!("Encode {frame_info:?}");

        let mut encode_slot = self
            .encoder
            .pop_encode_slot()?
            .expect("Invalid VaEncoder configuration, not enough encode slots");

        self.encoder
            .copy_image_to_encode_slot(&mut encode_slot, image)?;

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
        encode_slot: VaEncodeSlot,
    ) -> Result<(), VaError> {
        let mut setup_dpb_slot = if let Some(dpb_slot) = self.free_dpb_slots.pop() {
            dpb_slot
        } else if let Some(dpb_slot) = self.active_dpb_slots.pop_back() {
            dpb_slot
        } else {
            unreachable!()
        };

        log::trace!("\tUsing setup slot {}", setup_dpb_slot.index);

        setup_dpb_slot.picture.picture_id =
            self.encoder.dpb_slot_surface(setup_dpb_slot.index).id();
        setup_dpb_slot.picture.frame_idx = frame_info.picture_order_count.into();
        setup_dpb_slot.picture.TopFieldOrderCnt = frame_info.picture_order_count.into();
        setup_dpb_slot.picture.BottomFieldOrderCnt = frame_info.picture_order_count.into();
        setup_dpb_slot.picture.flags = if matches!(
            frame_info.frame_type,
            H264FrameType::Idr | H264FrameType::I | H264FrameType::P
        ) {
            ffi::VA_PICTURE_H264_SHORT_TERM_REFERENCE
        } else {
            0
        };

        let l0_references = self
            .active_dpb_slots
            .iter()
            .filter(|dpb_slot| dpb_slot.picture.frame_idx < setup_dpb_slot.picture.frame_idx);

        let l1_references = self
            .active_dpb_slots
            .iter()
            .rev()
            .filter(|dpb_slot| dpb_slot.picture.frame_idx > setup_dpb_slot.picture.frame_idx);

        let (l0_references, l1_references) = match frame_info.frame_type {
            H264FrameType::P => (l0_references.take(self.max_l0_references).collect(), vec![]),
            H264FrameType::B => (
                l0_references.take(self.max_l0_references).collect(),
                l1_references.take(self.max_l1_references).collect(),
            ),
            H264FrameType::I | H264FrameType::Idr => (vec![], vec![]),
        };

        let encode_params = self.build_encode_params(
            frame_info,
            &encode_slot,
            &setup_dpb_slot,
            l0_references,
            l1_references,
        )?;

        if frame_info.frame_type == H264FrameType::B {
            self.free_dpb_slots.insert(0, setup_dpb_slot);
        } else {
            self.active_dpb_slots.push_front(setup_dpb_slot);
        }
        self.encoder
            .submit_encode_slot(encode_slot, encode_params)?;

        Ok(())
    }

    fn build_encode_params(
        &self,
        frame_info: FrameEncodeInfo,
        encode_slot: &VaEncodeSlot,
        setup_dpb_slot: &DpbSlot,
        l0_references: Vec<&DpbSlot>,
        l1_references: Vec<&DpbSlot>,
    ) -> Result<Vec<Buffer>, VaError> {
        let mut encode_params = Vec::new();

        let seq_param = self.create_seq_params();
        let pic_param = self.create_picture_params(
            &frame_info,
            setup_dpb_slot,
            &l0_references,
            &l1_references,
            encode_slot.output_buffer(),
        );

        if frame_info.frame_type == H264FrameType::Idr {
            // Render sequence params
            encode_params.push(self.encoder.context().create_buffer_with_data(
                ffi::VABufferType_VAEncSequenceParameterBufferType,
                &seq_param,
            )?);
            encode_params.push(self.encoder.create_rate_control_params()?);
            encode_params.push(self.encoder.create_quality_params()?);

            // Render packed sequence
            if self.encoder.support_packed_header_sequence {
                let packed_sequence_param = bitstream::write_sps_rbsp(&self.config, &seq_param);

                self.encoder.create_packed_param(
                    ffi::VAEncPackedHeaderTypeH264_VAEncPackedHeaderH264_SPS,
                    &packed_sequence_param,
                    &mut encode_params,
                )?;
            }

            // Render packed picture
            if self.encoder.support_packed_header_picture {
                let packed_picture_param = bitstream::write_pps_rbsp(&pic_param);
                self.encoder.create_packed_param(
                    ffi::VAEncPackedHeaderTypeH264_VAEncPackedHeaderH264_PPS,
                    &packed_picture_param,
                    &mut encode_params,
                )?;
            }
        }

        encode_params.push(self.encoder.context().create_buffer_with_data(
            ffi::VABufferType_VAEncPictureParameterBufferType,
            &pic_param,
        )?);

        let current_resolution = self.encoder.current_encode_resolution();
        let total_macroblocks = (current_resolution[0] / 16) * (current_resolution[1] / 16);

        match self.config.slice_mode {
            SliceMode::Picture => {
                self.build_encode_slice_params(
                    frame_info,
                    &l0_references,
                    &l1_references,
                    &mut encode_params,
                    &seq_param,
                    &pic_param,
                    0,
                    total_macroblocks,
                )?;
            }
            SliceMode::Rows(num_rows) => {
                let num_macroblocks = (current_resolution[0] / 16) * num_rows.get();

                for row in (0..current_resolution[1] / 16).step_by(num_rows.get() as usize) {
                    let first_macroblock = (current_resolution[1] / 16) * row;
                    let num_macroblocks =
                        (num_macroblocks).min(total_macroblocks - first_macroblock);

                    self.build_encode_slice_params(
                        frame_info,
                        &l0_references,
                        &l1_references,
                        &mut encode_params,
                        &seq_param,
                        &pic_param,
                        first_macroblock,
                        num_macroblocks,
                    )?;
                }
            }
            SliceMode::MacroBlocks(config_num_mbs) => {
                for first_macroblock in
                    (0..total_macroblocks).step_by(config_num_mbs.get() as usize)
                {
                    let num_macroblocks =
                        (config_num_mbs.get()).min(total_macroblocks - first_macroblock);

                    self.build_encode_slice_params(
                        frame_info,
                        &l0_references,
                        &l1_references,
                        &mut encode_params,
                        &seq_param,
                        &pic_param,
                        first_macroblock,
                        num_macroblocks,
                    )?;
                }
            }
        }

        Ok(encode_params)
    }

    #[allow(clippy::too_many_arguments)]
    fn build_encode_slice_params(
        &self,
        frame_info: FrameEncodeInfo,
        l0_references: &Vec<&DpbSlot>,
        l1_references: &Vec<&DpbSlot>,
        encode_params: &mut Vec<Buffer>,
        seq_param: &ffi::_VAEncSequenceParameterBufferH264,
        pic_param: &ffi::_VAEncPictureParameterBufferH264,
        first_macroblock: u32,
        num_macroblocks: u32,
    ) -> Result<(), VaError> {
        let slice_param = self.create_slice_params(
            &frame_info,
            l0_references,
            l1_references,
            first_macroblock,
            num_macroblocks,
        );

        if self.encoder.support_packed_header_slice {
            let packed_slice_params =
                bitstream::write_slice_header(seq_param, pic_param, &slice_param);

            self.encoder.create_packed_param(
                ffi::VAEncPackedHeaderTypeH264_VAEncPackedHeaderH264_Slice,
                &packed_slice_params,
                encode_params,
            )?;
        }

        encode_params.push(self.encoder.context().create_buffer_with_data(
            ffi::VABufferType_VAEncSliceParameterBufferType,
            &slice_param,
        )?);

        Ok(())
    }
}

impl VaH264Encoder {
    fn create_seq_params(&self) -> ffi::VAEncSequenceParameterBufferH264 {
        let [width, height] = self.encoder.current_encode_resolution();
        let [width_mbaligned, height_mbaligned] = self
            .encoder
            .current_encode_resolution()
            .map(|v| v.next_multiple_of(16));

        unsafe {
            let mut seq_param = zeroed::<ffi::VAEncSequenceParameterBufferH264>();

            seq_param.level_idc = self.config.level.level_idc();
            seq_param.picture_width_in_mbs = (width_mbaligned / 16) as u16;
            seq_param.picture_height_in_mbs = (height_mbaligned / 16) as u16;

            seq_param.intra_idr_period = self.config.frame_pattern.intra_idr_period.into();
            seq_param.intra_period = self.config.frame_pattern.intra_period.into();
            seq_param.ip_period = self.config.frame_pattern.ip_period.into();

            seq_param.max_num_ref_frames = self.max_l0_references as u32
                + if self.config.frame_pattern.ip_period > 1 {
                    self.max_l1_references as u32
                } else {
                    0
                };

            seq_param.time_scale = 900; // TODO: configurable
            seq_param.num_units_in_tick = 15; // TODO: configurable

            let seq_fields = &mut seq_param.seq_fields.bits;

            seq_fields.set_log2_max_pic_order_cnt_lsb_minus4(
                (self.state.log2_max_pic_order_cnt_lsb - 4).into(),
            );
            seq_fields.set_log2_max_frame_num_minus4((self.state.log2_max_frame_num - 4).into());

            seq_fields.set_frame_mbs_only_flag(1);
            seq_fields.set_chroma_format_idc(1); // TODO: configurable this is currently hardcoded to yuv420
            seq_fields.set_direct_8x8_inference_flag(1);

            if width != width_mbaligned || height != height_mbaligned {
                seq_param.frame_cropping_flag = 1;
                seq_param.frame_crop_right_offset = (width_mbaligned - width) / 2;
                seq_param.frame_crop_bottom_offset = (height_mbaligned - height) / 2;
            }

            seq_param
        }
    }

    fn create_picture_params(
        &self,
        frame_info: &FrameEncodeInfo,
        setup_dpb_slot: &DpbSlot,
        l0_references: &[&DpbSlot],
        l1_references: &[&DpbSlot],
        output: &Buffer,
    ) -> ffi::VAEncPictureParameterBufferH264 {
        unsafe {
            let mut pic_param = zeroed::<ffi::VAEncPictureParameterBufferH264>();

            pic_param.frame_num = frame_info.frame_num;
            pic_param.CurrPic = setup_dpb_slot.picture;

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
            pic_param.pic_fields.bits.set_entropy_coding_mode_flag(
                self.config.profile.support_entropy_coding_mode().into(),
            );
            pic_param.pic_fields.bits.set_transform_8x8_mode_flag(
                self.config.profile.support_transform_8x8_mode_flag().into(),
            );
            pic_param
                .pic_fields
                .bits
                .set_deblocking_filter_control_present_flag(1);

            pic_param.coded_buf = output.id();
            pic_param.last_picture = 0; // TODO: set on flush

            if self
                .config
                .encoder
                .rate_control
                .mode
                .contains(VaEncoderRateControlMode::CQP)
            {
                pic_param.pic_init_qp = self.config.encoder.rate_control.initial_qp;
            }

            pic_param
        }
    }

    fn create_slice_params(
        &self,
        frame_info: &FrameEncodeInfo,
        l0_references: &[&DpbSlot],
        l1_references: &[&DpbSlot],
        first_macroblock: u32,
        num_macroblocks: u32,
    ) -> ffi::VAEncSliceParameterBufferH264 {
        unsafe {
            let mut slice_params = zeroed::<ffi::VAEncSliceParameterBufferH264>();

            slice_params.macroblock_address = first_macroblock;
            slice_params.num_macroblocks = num_macroblocks;
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
        if let Some(DpbSlot { picture, index: _ }) = iter.next() {
            *dst_picture = *picture;
        } else {
            dst_picture.picture_id = ffi::VA_INVALID_SURFACE;
            dst_picture.flags = ffi::VA_PICTURE_H264_INVALID;
        }
    }
}

fn profile_to_va_profile(profile: crate::H264Profile) -> Option<i32> {
    let profile = match profile {
        crate::H264Profile::Baseline => ffi::VAProfile_VAProfileH264Baseline,
        crate::H264Profile::ConstrainedBaseline => ffi::VAProfile_VAProfileH264ConstrainedBaseline,
        crate::H264Profile::Main => ffi::VAProfile_VAProfileH264Main,
        crate::H264Profile::Extended => return None,
        crate::H264Profile::High => ffi::VAProfile_VAProfileH264High,
        crate::H264Profile::High10 => ffi::VAProfile_VAProfileH264High10,
        crate::H264Profile::High422 => ffi::VAProfile_VAProfileH264High,
        crate::H264Profile::High444Predictive => ffi::VAProfile_VAProfileH264High,
        crate::H264Profile::High10Intra => ffi::VAProfile_VAProfileH264High10,
        crate::H264Profile::High422Intra => ffi::VAProfile_VAProfileH264High,
        crate::H264Profile::High444Intra => ffi::VAProfile_VAProfileH264High,
        crate::H264Profile::CAVLC444Intra => return None,
    };

    Some(profile)
}
