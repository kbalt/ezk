use libva::{Buffer, Context, Display, Surface, ffi};
use std::{
    collections::VecDeque,
    mem::{take, zeroed},
    ptr::copy_nonoverlapping,
    slice::from_raw_parts,
};

use crate::encoder::{FrameEncodeInfo, FrameType, H264EncoderConfig, H264EncoderState};

mod bitstream;

// 16 is the maximum number of reference frames allowed by H.264
const MAX_SURFACES: usize = 16;

// TODO: resolution changes
// TODO: rate control
// TODO: fix B-Frames
pub struct VaH264Encoder {
    h264_config: H264EncoderConfig,

    context: Context,

    /// Indicates if packed headers are supported
    support_packed_header_sequence: bool,
    support_packed_header_picture: bool,
    support_packed_header_slice: bool,

    /// Resolution macro block aligned (next 16x16 block boundary)
    width_mbaligned: u32,
    height_mbaligned: u32,

    /// Maximum bitrate for rate control
    target_bitrate: u32,

    state: H264EncoderState,

    /// Pool of pre-allocated source surfaces and coded buffers
    available_src_surfaces: Vec<(Surface, Buffer)>,
    in_flight: VecDeque<(Surface, Buffer)>,

    /// Pool of pre-allocated surfaces for reference frames
    available_ref_surfaces: Vec<Surface>,

    /// Active reference pictures
    reference_frames: Vec<(Surface, ffi::VAPictureH264)>,

    /// Maximum number of reference frames that should be used when encoding a P or B-Frame
    max_ref_frames: usize,

    /// Source pictures with their display index that should be rendered into B-Frames
    /// once a P or I Frame has been rendered and can be used as reference
    backlogged_b_frames: Vec<(Surface, Buffer, FrameEncodeInfo)>,

    output: VecDeque<Vec<u8>>,
}

impl VaH264Encoder {
    pub fn new(display: &Display, h264_config: H264EncoderConfig) -> Self {
        let width_mbaligned = macro_block_align(h264_config.resolution.0);
        let height_mbaligned = macro_block_align(h264_config.resolution.1);

        let (profile, format) = profile_to_profile_and_format(h264_config.profile).unwrap();

        let entrypoint = display
            .entrypoints(profile)
            .into_iter()
            .find(|&e| {
                e == ffi::VAEntrypoint_VAEntrypointEncSlice
                    || e == ffi::VAEntrypoint_VAEntrypointEncSliceLP
            })
            .unwrap();

        let mut config_attributes = Vec::new();

        let attributes = display.get_config_attributes(profile, entrypoint);

        // Test the requested format is available
        if attributes[ffi::VAConfigAttribType_VAConfigAttribRTFormat as usize].value & format == 0 {
            todo!("Format not available");
        }

        config_attributes.push(ffi::VAConfigAttrib {
            type_: ffi::VAConfigAttribType_VAConfigAttribRTFormat,
            value: format,
        });

        // Test if rate control is available
        let rc_attr = attributes[ffi::VAConfigAttribType_VAConfigAttribRateControl as usize];
        if rc_attr.value != ffi::VA_ATTRIB_NOT_SUPPORTED {
            // TODO: rate control
            println!("Rate control available");

            println!("\tNONE: {}", rc_attr.value & ffi::VA_RC_NONE != 0);
            println!("\tCBR: {}", rc_attr.value & ffi::VA_RC_CBR != 0);
            println!("\tVBR: {}", rc_attr.value & ffi::VA_RC_VBR != 0);
            println!("\tVCM: {}", rc_attr.value & ffi::VA_RC_VCM != 0);
            println!("\tCQP: {}", rc_attr.value & ffi::VA_RC_CQP != 0);
            println!(
                "\tVBR_CONSTRAINED: {}",
                rc_attr.value & ffi::VA_RC_VBR_CONSTRAINED != 0
            );
            println!("\tICQ: {}", rc_attr.value & ffi::VA_RC_ICQ != 0);
            println!("\tMB: {}", rc_attr.value & ffi::VA_RC_MB != 0);
            println!("\tCFS: {}", rc_attr.value & ffi::VA_RC_CFS != 0);
            println!("\tPARALLEL: {}", rc_attr.value & ffi::VA_RC_PARALLEL != 0);
            println!("\tQVBR: {}", rc_attr.value & ffi::VA_RC_QVBR != 0);
            println!("\tAVBR: {}", rc_attr.value & ffi::VA_RC_AVBR != 0);
            println!("\tTCBRC: {}", rc_attr.value & ffi::VA_RC_TCBRC != 0);

            config_attributes.push(ffi::VAConfigAttrib {
                type_: ffi::VAConfigAttribType_VAConfigAttribRateControl,
                value: ffi::VA_RC_CBR,
            });
        }

        // Test if packed headers are available, and enable some if they are
        let packed_headers_attr =
            attributes[ffi::VAConfigAttribType_VAConfigAttribEncPackedHeaders as usize];

        let mut support_packed_header_sequence = false;
        let mut support_packed_header_picture = false;
        let mut support_packed_header_slice = false;

        if packed_headers_attr.value != ffi::VA_ATTRIB_NOT_SUPPORTED {
            let v = packed_headers_attr.value;

            support_packed_header_sequence = (v & ffi::VA_ENC_PACKED_HEADER_SEQUENCE) != 0;
            support_packed_header_picture = (v & ffi::VA_ENC_PACKED_HEADER_PICTURE) != 0;
            support_packed_header_slice = (v & ffi::VA_ENC_PACKED_HEADER_SLICE) != 0;

            config_attributes.push(ffi::VAConfigAttrib {
                type_: ffi::VAConfigAttribType_VAConfigAttribEncPackedHeaders,
                value: v
                    & (ffi::VA_ENC_PACKED_HEADER_SEQUENCE
                        | ffi::VA_ENC_PACKED_HEADER_PICTURE
                        | ffi::VA_ENC_PACKED_HEADER_SLICE),
            });
        }

        let max_ref_frames =
            attributes[ffi::VAConfigAttribType_VAConfigAttribEncMaxRefFrames as usize];
        if max_ref_frames.value != ffi::VA_ATTRIB_NOT_SUPPORTED {
            println!("max ref frames: {}", max_ref_frames.value);
        }

        let max_slices = attributes[ffi::VAConfigAttribType_VAConfigAttribEncMaxSlices as usize];
        if max_slices.value != ffi::VA_ATTRIB_NOT_SUPPORTED {
            println!("max slices: {}", max_slices.value);
        }

        let config = display
            .create_config(profile, entrypoint, &config_attributes)
            .unwrap();

        let src_surfaces =
            display.create_surfaces(format, width_mbaligned, height_mbaligned, MAX_SURFACES, &[]);
        let ref_surfaces =
            display.create_surfaces(format, width_mbaligned, height_mbaligned, MAX_SURFACES, &[]);

        let context = display.create_context(
            &config,
            width_mbaligned as _,
            height_mbaligned as _,
            ffi::VA_PROGRESSIVE as _,
            src_surfaces.iter().chain(ref_surfaces.iter()),
        );

        // EncCodec buffer size is estimated from the input image resolution. Currently using a higher value to ensure
        // proper output even with worst case input
        let coded_buffer_size = (width_mbaligned as f64 * height_mbaligned as f64 * 2.5) as usize;

        let src_surfaces = src_surfaces
            .into_iter()
            .map(|src_surface| {
                let coded_buffer = context
                    .create_buffer_empty(ffi::VABufferType_VAEncCodedBufferType, coded_buffer_size);

                (src_surface, coded_buffer)
            })
            .collect();

        VaH264Encoder {
            h264_config,
            context,
            support_packed_header_sequence,
            support_packed_header_picture,
            support_packed_header_slice,
            width_mbaligned,
            height_mbaligned,
            target_bitrate: h264_config.bitrate.unwrap_or(6_000_000),
            state: H264EncoderState::new(h264_config.frame_pattern),
            available_src_surfaces: src_surfaces,
            in_flight: VecDeque::new(),
            available_ref_surfaces: ref_surfaces,
            reference_frames: Vec::new(),
            max_ref_frames: 2,
            backlogged_b_frames: Vec::new(),
            output: VecDeque::new(),
        }
    }

    fn read_out_coded_buffer(&mut self, coded_buffer: &mut Buffer) {
        let mut codec_buffer_mapped = coded_buffer.map();
        let mut ptr = codec_buffer_mapped.data();

        while !ptr.is_null() {
            let segment = unsafe { ptr.cast::<ffi::VACodedBufferSegment>().read() };
            ptr = segment.next;

            let buf = segment.buf.cast::<u8>().cast_const();
            let buf = unsafe { from_raw_parts(buf, segment.size as usize) };

            self.output.push_back(buf.to_vec());
        }
    }

    /// Poll for encoded frame to be completed
    ///
    /// Returns `None` if nothing is ready yet, or no work has been submitted
    pub fn poll_result(&mut self) -> Option<Vec<u8>> {
        if let Some(buf) = self.output.pop_front() {
            return Some(buf);
        }

        if let Some((src_surface, _)) = self.in_flight.front_mut()
            && src_surface.try_sync()
        {
            let (src_surface, mut coded_buffer) = self.in_flight.pop_front().unwrap();
            self.read_out_coded_buffer(&mut coded_buffer);
            self.available_src_surfaces
                .push((src_surface, coded_buffer));

            self.output.pop_front()
        } else {
            None
        }
    }

    /// Wait for encoded frame to be completed
    ///
    /// Returns `None` if work has been submitted
    pub fn wait_result(&mut self) -> Option<Vec<u8>> {
        if let Some(buf) = self.output.pop_front() {
            return Some(buf);
        }

        if let Some((mut src_surface, mut coded_buffer)) = self.in_flight.pop_front() {
            src_surface.sync();
            self.read_out_coded_buffer(&mut coded_buffer);
            self.available_src_surfaces
                .push((src_surface, coded_buffer));
        }

        self.output.pop_front()
    }

    /// Submit a frame to be encoded
    pub fn encode_frame(
        &mut self,
        src_data: [&[u8]; 3],
        src_strides: [usize; 3],
        src_width: u32,
        src_height: u32,
    ) {
        let (mut src_surface, coded_buffer) =
            if let Some(src_surface) = self.available_src_surfaces.pop() {
                src_surface
            } else if let Some((mut src_surface, mut coded_buffer)) = self.in_flight.pop_front() {
                // Wait for the src_surface to be ready
                src_surface.sync();
                self.read_out_coded_buffer(&mut coded_buffer);
                (src_surface, coded_buffer)
            } else {
                panic!("ran out of source surfaces to use");
            };

        upload_yuv_to_surface(
            src_data,
            src_strides,
            src_width,
            src_height,
            &mut src_surface,
        );

        let frame_info = self.state.next();

        log::trace!("Encode frame {frame_info:?}");

        // B-Frames are not encoded immediately, they are queued until after an I or P-frame is encoded
        if frame_info.frame_type == FrameType::B {
            self.backlogged_b_frames
                .push((src_surface, coded_buffer, frame_info));
            return;
        }

        if frame_info.frame_type == FrameType::Idr {
            assert!(self.backlogged_b_frames.is_empty());

            // Just encoded an IDR frame, put all reference surfaces back into the surface pool,
            for (ref_surface, _) in self.reference_frames.drain(..) {
                self.available_ref_surfaces.push(ref_surface);
            }
        }

        self.encode_surface(&frame_info, src_surface, coded_buffer);

        if matches!(
            frame_info.frame_type,
            FrameType::Idr | FrameType::I | FrameType::P
        ) {
            let backlogged_b_frames = take(&mut self.backlogged_b_frames);

            // Process backlogged B-Frames
            for (src_surface, coded_buffer, frame_info) in backlogged_b_frames {
                self.encode_surface(&frame_info, src_surface, coded_buffer);
            }
        }
    }

    fn encode_surface(
        &mut self,
        frame_info: &FrameEncodeInfo,
        src_surface: Surface,
        coded_buffer: Buffer,
    ) {
        log::trace!("Encode surface {frame_info:?}");

        let ref_surface = if let Some(ref_surface) = self.available_ref_surfaces.pop() {
            ref_surface
        } else {
            self.reference_frames.remove(0).0
        };

        self.context.begin_picture(&src_surface);

        let mut bufs = Vec::new();

        let seq_param = self.create_seq_params();
        let pic_param = self.create_picture_params(frame_info, &ref_surface, &coded_buffer);
        let slice_param = self.create_slice_params(frame_info);

        if frame_info.frame_type == FrameType::Idr {
            // Render sequence params
            let rc_params_buf = self.create_rate_control_params();
            bufs.push(self.context.create_buffer_with_data(
                ffi::VABufferType_VAEncSequenceParameterBufferType,
                &seq_param,
            ));
            bufs.push(rc_params_buf);

            // Render packed sequence
            if self.support_packed_header_sequence {
                let packed_sequence_param =
                    bitstream::write_sps_rbsp(&self.h264_config, &seq_param);

                self.create_packed_param(
                    ffi::VAEncPackedHeaderTypeH264_VAEncPackedHeaderH264_SPS,
                    &packed_sequence_param,
                    &mut bufs,
                );
            }

            // Render packed picture
            if self.support_packed_header_picture {
                let packed_picture_param = bitstream::write_pps_rbsp(&pic_param);
                self.create_packed_param(
                    ffi::VAEncPackedHeaderTypeH264_VAEncPackedHeaderH264_PPS,
                    &packed_picture_param,
                    &mut bufs,
                );
            }
        }

        // Render picture
        bufs.push(self.context.create_buffer_with_data(
            ffi::VABufferType_VAEncPictureParameterBufferType,
            &pic_param,
        ));

        // Render packed slice
        if self.support_packed_header_slice {
            let packed_slice_params =
                bitstream::write_slice_header(&seq_param, &pic_param, &slice_param);

            self.create_packed_param(
                ffi::VAEncPackedHeaderTypeH264_VAEncPackedHeaderH264_Slice,
                &packed_slice_params,
                &mut bufs,
            );
        }

        // Render slice
        bufs.push(self.context.create_buffer_with_data(
            ffi::VABufferType_VAEncSliceParameterBufferType,
            &slice_param,
        ));

        self.context.render_picture(&bufs);

        self.context.end_picture();

        // explicitly drop bufs after `render_picture` to ensure them not being dropped before
        drop(bufs);

        self.in_flight.push_back((src_surface, coded_buffer));

        if matches!(
            frame_info.frame_type,
            FrameType::Idr | FrameType::I | FrameType::P
        ) {
            self.reference_frames.push((ref_surface, pic_param.CurrPic));
        } else {
            self.available_ref_surfaces.insert(0, ref_surface);
        }
    }

    fn create_seq_params(&mut self) -> ffi::VAEncSequenceParameterBufferH264 {
        unsafe {
            let mut seq_param = zeroed::<ffi::VAEncSequenceParameterBufferH264>();

            seq_param.level_idc = self.h264_config.level.level_idc();
            seq_param.picture_width_in_mbs = (self.width_mbaligned / 16) as u16;
            seq_param.picture_height_in_mbs = (self.height_mbaligned / 16) as u16;

            seq_param.intra_idr_period = self.h264_config.frame_pattern.intra_idr_period;
            seq_param.intra_period = self.h264_config.frame_pattern.intra_period;
            seq_param.ip_period = self.h264_config.frame_pattern.ip_period;

            seq_param.max_num_ref_frames = self.max_ref_frames as u32;
            seq_param.time_scale = 900; // TODO: configurable
            seq_param.num_units_in_tick = 15; // TODO: configurable

            let seq_fields = &mut seq_param.seq_fields.bits;

            seq_fields.set_log2_max_pic_order_cnt_lsb_minus4(
                (self.state.log2_max_pic_order_cnt_lsb - 4) as u32,
            );

            seq_fields.set_log2_max_frame_num_minus4(16 - 4);
            seq_fields.set_frame_mbs_only_flag(1);
            seq_fields.set_chroma_format_idc(1); // TODO: configurable this is currently harcoded to yuv420
            seq_fields.set_direct_8x8_inference_flag(1);

            let (width, height) = self.h264_config.resolution;

            if width != self.width_mbaligned || height != self.height_mbaligned {
                seq_param.frame_cropping_flag = 1;
                seq_param.frame_crop_right_offset = (self.width_mbaligned - width) / 2;
                seq_param.frame_crop_bottom_offset = (self.height_mbaligned - height) / 2;
            }

            seq_param
        }
    }

    fn create_rate_control_params(&mut self) -> Buffer {
        unsafe {
            // Build rate control parameter buffer
            //
            // Modifying the data in the buffer instead of on the stack since the
            // VAEncMiscParameterBuffer and VAEncMiscParameterRateControl must be packed after another
            let mut rate_control_params_buffer = self.context.create_buffer_empty(
                ffi::VABufferType_VAEncMiscParameterBufferType,
                size_of::<ffi::VAEncMiscParameterBuffer>()
                    + size_of::<ffi::VAEncMiscParameterRateControl>(),
            );
            let mut mapped = rate_control_params_buffer.map();
            let misc_param = mapped
                .data()
                .cast::<ffi::VAEncMiscParameterBuffer>()
                .as_mut()
                .unwrap();
            misc_param.type_ = ffi::VAEncMiscParameterType_VAEncMiscParameterTypeRateControl;
            let rate_control_params = misc_param
                .data
                .as_mut_ptr()
                .cast::<ffi::VAEncMiscParameterRateControl>()
                .as_mut()
                .unwrap();

            *rate_control_params = zeroed();

            // TODO: more rate control options
            rate_control_params.bits_per_second = self.target_bitrate;
            rate_control_params.target_percentage = 66;
            rate_control_params.window_size = 1000;
            rate_control_params.initial_qp = 26;
            rate_control_params.min_qp = 26;
            rate_control_params.rc_flags.value = ffi::VA_RC_CBR;

            if let Some((min_qp, max_qp)) = self.h264_config.qp {
                rate_control_params.min_qp = min_qp;
                rate_control_params.max_qp = max_qp;
            }

            drop(mapped);

            rate_control_params_buffer
        }
    }

    fn create_picture_params(
        &mut self,
        frame_info: &FrameEncodeInfo,
        ref_surface: &Surface,
        coded_buffer: &Buffer,
    ) -> ffi::VAEncPictureParameterBufferH264 {
        unsafe {
            let mut pic_param = zeroed::<ffi::VAEncPictureParameterBufferH264>();

            pic_param.frame_num = frame_info.frame_num;
            pic_param.CurrPic.picture_id = ref_surface.id();
            pic_param.CurrPic.frame_idx = frame_info.frame_num.into();

            pic_param.CurrPic.flags = if matches!(
                frame_info.frame_type,
                FrameType::Idr | FrameType::I | FrameType::P
            ) {
                ffi::VA_PICTURE_H264_SHORT_TERM_REFERENCE
            } else {
                0
            };

            pic_param.CurrPic.TopFieldOrderCnt = frame_info.pic_order_cnt_lsb.into();
            pic_param.CurrPic.BottomFieldOrderCnt = pic_param.CurrPic.TopFieldOrderCnt;

            log::trace!("\tpic_params.frame_num: {}", pic_param.frame_num,);
            log::trace!(
                "\tpic_param.CurrPic.frame_idx: {}",
                pic_param.CurrPic.frame_idx
            );
            log::trace!(
                "\tpic_param.CurrPic.TopFieldOrderCnt: {}",
                pic_param.CurrPic.TopFieldOrderCnt
            );

            match frame_info.frame_type {
                FrameType::P | FrameType::B => {
                    let iter = self.reference_frames.iter().rev().take(self.max_ref_frames);
                    fill_pic_list(&mut pic_param.ReferenceFrames, iter);
                }
                FrameType::I | FrameType::Idr => {
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
                .set_idr_pic_flag((frame_info.frame_type == FrameType::Idr) as u32);
            pic_param
                .pic_fields
                .bits
                .set_reference_pic_flag((frame_info.frame_type != FrameType::B) as u32);
            pic_param.pic_fields.bits.set_entropy_coding_mode_flag(1);
            pic_param
                .pic_fields
                .bits
                .set_deblocking_filter_control_present_flag(1);

            pic_param.coded_buf = coded_buffer.id();
            pic_param.last_picture = 0; // TODO: set on flush
            pic_param.pic_init_qp = 24; // TODO: configurable

            pic_param
        }
    }

    fn create_slice_params(
        &mut self,
        frame_info: &FrameEncodeInfo,
    ) -> ffi::VAEncSliceParameterBufferH264 {
        unsafe {
            let mut slice_params = zeroed::<ffi::VAEncSliceParameterBufferH264>();

            slice_params.num_macroblocks = self.width_mbaligned * self.height_mbaligned / (16 * 16);
            slice_params.slice_type = match frame_info.frame_type {
                FrameType::P => 0,
                FrameType::B => 1,
                FrameType::Idr | FrameType::I => 2,
            };

            match frame_info.frame_type {
                FrameType::P => {
                    let iter = self.reference_frames.iter().rev().take(self.max_ref_frames);

                    fill_pic_list(&mut slice_params.RefPicList0, iter);
                }
                FrameType::B => {
                    assert!(self.max_ref_frames >= 2);

                    let mut iter = self.reference_frames.iter().rev().take(self.max_ref_frames);

                    fill_pic_list(&mut slice_params.RefPicList1, iter.next());
                    fill_pic_list(&mut slice_params.RefPicList0, iter);
                }
                FrameType::I => {}
                FrameType::Idr => {
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
            slice_params.pic_order_cnt_lsb = frame_info.pic_order_cnt_lsb;

            log::trace!(
                "\tslice_params.pic_order_cnt_lsb: {}",
                slice_params.pic_order_cnt_lsb
            );

            slice_params
        }
    }

    fn create_packed_param(&self, type_: u32, buf: &[u8], bufs: &mut Vec<Buffer>) {
        let params = ffi::VAEncPackedHeaderParameterBuffer {
            type_,
            bit_length: (buf.len() * 8) as _,
            has_emulation_bytes: 0,
            va_reserved: Default::default(),
        };

        let packed_header_params = self.context.create_buffer_with_data(
            ffi::VABufferType_VAEncPackedHeaderParameterBufferType,
            &params,
        );

        let b = self
            .context
            .create_buffer_from_bytes(ffi::VABufferType_VAEncPackedHeaderDataBufferType, buf);

        bufs.push(packed_header_params);
        bufs.push(b);
    }
}

fn upload_yuv_to_surface(
    src_data: [&[u8]; 3],
    src_strides: [usize; 3],
    src_width: u32,
    src_height: u32,
    src_surface: &mut Surface,
) {
    let mut src_image = src_surface.derive_image();
    let offsets = src_image.ffi().offsets;
    let strides = src_image.ffi().pitches;
    let fourcc = src_image.ffi().format.fourcc;

    let mut mapped_src_image = src_image.map();

    let mapped_data = mapped_src_image.data();

    match fourcc {
        ffi::VA_FOURCC_NV12 => unsafe {
            let y = mapped_data.add(offsets[0] as usize);

            for row in 0..src_height {
                copy_nonoverlapping(
                    src_data[0].as_ptr().add(row as usize * src_strides[0]),
                    y.add((row * strides[0]) as usize),
                    src_width as usize,
                );
            }

            let uv = mapped_data.add(offsets[1] as usize);

            for row in 0..src_height / 2 {
                copy_nonoverlapping(
                    src_data[1].as_ptr().add(row as usize * src_strides[1]),
                    uv.add((row * strides[1]) as usize),
                    src_width as usize,
                );
            }
        },
        _ => todo!("unsupported fourcc: {fourcc}"),
    }
}

fn macro_block_align(v: u32) -> u32 {
    (v + 0xF) & !0xF
}

fn debug_pic_list(list: &[ffi::VAPictureH264]) -> Vec<u32> {
    list.iter()
        .take_while(|p| p.flags != ffi::VA_PICTURE_H264_INVALID)
        .map(|p| p.frame_idx)
        .collect::<Vec<_>>()
}

fn fill_pic_list<'a>(
    list: &mut [ffi::VAPictureH264],
    iter: impl IntoIterator<Item = &'a (Surface, ffi::VAPictureH264)>,
) {
    let mut iter = iter.into_iter();
    for picture in list {
        if let Some((_, ref_frame)) = iter.next() {
            *picture = *ref_frame;
        } else {
            picture.picture_id = ffi::VA_INVALID_SURFACE;
            picture.flags = ffi::VA_PICTURE_H264_INVALID;
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

#[cfg(test)]
mod tests {
    use crate::encoder::FramePattern;

    use super::*;
    use ezk_image::resize::ResizeAlg;
    use ezk_image::{
        ColorInfo, ColorPrimaries, ColorSpace, ColorTransfer, ImageRef, PixelFormat, YuvColorInfo,
    };
    use scap::frame::Frame;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::time::Instant;

    #[test]
    fn haha() {
        env_logger::init();
        let display = Display::open_drm("/dev/dri/renderD128").unwrap();

        println!("profile: {:?}", display.profiles());

        let mut encoder = VaH264Encoder::new(
            &display,
            H264EncoderConfig {
                profile: crate::Profile::High,
                level: crate::Level::Level_4_1,
                resolution: (1920, 1080),
                qp: Some((20, 28)),
                frame_pattern: FramePattern {
                    intra_idr_period: 60,
                    intra_period: 30,
                    ip_period: 4,
                },
                bitrate: Some(6_000_000),
                max_bitrate: Some(6_000_000),
                max_slice_len: None,
            },
        );

        if scap::has_permission() {
            scap::request_permission();
        }

        let mut resizer = ezk_image::resize::Resizer::new(ResizeAlg::Nearest);

        let mut capturer = scap::capturer::Capturer::build(scap::capturer::Options {
            fps: 30,
            ..Default::default()
        })
        .unwrap();

        capturer.start_capture();

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open("lol.h264")
            .unwrap();

        let mut bgrx_target = ezk_image::Image::blank(
            PixelFormat::BGRA,
            1920,
            1080,
            ColorInfo::YUV(YuvColorInfo {
                transfer: ColorTransfer::Linear,
                full_range: false,
                primaries: ColorPrimaries::BT709,
                space: ColorSpace::BT709,
            }),
        );

        let mut nv12 = ezk_image::Image::blank(
            PixelFormat::NV12,
            1920,
            1080,
            ColorInfo::YUV(YuvColorInfo {
                transfer: ColorTransfer::Linear,
                full_range: false,
                primaries: ColorPrimaries::BT709,
                space: ColorSpace::BT709,
            }),
        );

        let mut i = 0;
        let mut last_frame = Instant::now();
        while let Ok(frame) = capturer.get_next_frame() {
            let now = Instant::now();
            println!("Time since last frame: {:?}", now - last_frame);
            last_frame = now;
            i += 1;
            if i > 500 {
                break;
            }

            let bgrx = match frame {
                Frame::BGRx(bgrx) => bgrx,
                _ => todo!(),
            };

            let bgrx_original = ezk_image::Image::from_buffer(
                PixelFormat::BGRA,
                bgrx.data,
                None,
                bgrx.width as usize,
                bgrx.height as usize,
                ColorInfo::YUV(YuvColorInfo {
                    transfer: ColorTransfer::Linear,
                    full_range: false,
                    primaries: ColorPrimaries::BT709,
                    space: ColorSpace::BT709,
                }),
            )
            .unwrap();

            resizer.resize(&bgrx_original, &mut bgrx_target).unwrap();

            ezk_image::convert_multi_thread(&bgrx_target, &mut nv12).unwrap();

            let mut planes = nv12.planes();
            let (y, y_stride) = planes.next().unwrap();
            let (uv, uv_stride) = planes.next().unwrap();

            encoder.encode_frame([y, uv, &[]], [y_stride, uv_stride, 0], 1920, 1080);

            while let Some(buf) = encoder.poll_result() {
                println!("buf: {:?}", &buf[..8]);
                file.write_all(&buf).unwrap();
            }
        }
    }
}
