use crate::H264EncoderConfig;
use libva::{Buffer, Config, Context, Display, Surface, ffi};
use std::{
    collections::VecDeque,
    mem::{take, zeroed},
    ptr::copy_nonoverlapping,
};

mod bitstream;

// 16 is the maximum number of reference frames allowed by H.264
const MAX_SURFACES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub enum FrameType {
    // Uses previous frames as reference
    P,
    // Uses previous and future frames as reference
    B,
    // Intra frame, standalone complete picture, no references
    I,
    // Intra Frame preceded by a SPS/PPS set. Clears all reference frames
    IDR,
}

/// Describes the pattern in which frames are created
///
/// # Examples
///
/// ```rust
/// # use ezk_h264::libva::{FrameType, FrameType::*, FrameTypePattern};
/// # fn eval<const N: usize>(pattern: FrameTypePattern) -> [FrameType; N] {
/// #    let mut ret = [P; N];
/// #    let mut n = 0;
/// #    while n < N {
/// #        ret[n] = pattern.frame_type_of_nth_frame(n as _);
/// #        n += 1;
/// #    }
/// #    ret
/// # }
/// // Only create I frames
/// let pattern = FrameTypePattern { idr_period: 32, i_period: Some(1), p_period: None };
/// assert_eq!(eval(pattern), [IDR, I, I, I, I, I, I, I, I, I, I, I, I, I, I, I]);
///
/// // Create I & P Frames
/// let pattern = FrameTypePattern { idr_period: 32, i_period: Some(4), p_period: None };
/// assert_eq!(eval(pattern), [IDR, P, P, P, I, P, P, P, I, P, P, P, I, P, P, P]);
///
/// // Insert some IDR frames, required for livestream or video conferences
/// let pattern = FrameTypePattern { idr_period: 8, i_period: Some(4), p_period: None };
/// assert_eq!(eval(pattern), [IDR, P, P, P, I, P, P, P, IDR, P, P, P, I, P, P, P]);
///
/// // B frames are only created if `p_period` is specified
/// let pattern = FrameTypePattern { idr_period: 32, i_period: Some(8), p_period: Some(4) };
/// assert_eq!(eval(pattern), [IDR, B, B, B, P, B, B, B, I, B, B, B, P, B, B, B]);
/// // B frames are only created if `p_period` is specified
///
/// let pattern = FrameTypePattern { idr_period: 8, i_period: None, p_period: Some(4) };
/// assert_eq!(eval(pattern), [IDR, B, B, B, P, B, B, P, IDR, B, B, B, P, B, B, P]);
/// ```
pub struct FrameTypePattern {
    /// Period in which to create IDR frames
    ///
    /// Must be a multiple of `i_period` (or `p_period`) if set
    pub idr_period: u32,

    /// Period in which to create I frames
    ///
    /// Must be a multiple of `p_period` if set
    pub i_period: Option<u32>,

    /// How often to insert create frames, instead of B frames
    ///
    /// B Frames are not inserted if this is set to `None` or `Some(1)`
    pub p_period: Option<u32>,
}

impl FrameTypePattern {
    pub const fn frame_type_of_nth_frame(&self, n: u32) -> FrameType {
        // Always start with an IDR frame
        if n == 0 {
            return FrameType::IDR;
        }

        // Emit IDR frame every idr_period frames
        if n % self.idr_period == 0 {
            return FrameType::IDR;
        }

        // Emit I frame every i_period frames
        if let Some(i_period) = self.i_period
            && n % i_period == 0
        {
            return FrameType::I;
        }

        // Emit P frame every p_period frames
        if let Some(p_period) = self.p_period {
            if n % p_period == 0 {
                return FrameType::P;
            } else {
                // Emit B-Frame if a P or I frame follows in this GOP, else emit a P-Frame
                let mut i = n + 1;

                loop {
                    match self.frame_type_of_nth_frame(i) {
                        FrameType::P | FrameType::I => return FrameType::B,
                        FrameType::B => i += 1,
                        FrameType::IDR => return FrameType::P,
                    }
                }
            }
        }

        FrameType::P
    }
}

pub struct VaH264Encoder {
    h264_config: H264EncoderConfig,
    display: Display,
    config: Config,
    context: Context,

    /// Indicates if packed headers are supported
    support_packed_headers: bool,

    // Resolution macro block aligned (next 16x16 block boundary)
    width_mbaligned: u32,
    height_mbaligned: u32,

    // Maximum bitrate for rate control
    target_bitrate: u32,

    /// Frame type pattern used to emit frames
    frame_type_pattern: FrameTypePattern,

    num_submitted_frames: u32,
    num_encoded_frames: u32,
    current_idr_display: u32,

    /// Pool of preallocated source surfaces
    available_src_surfaces: Vec<Surface>,
    /// Pool of preallocated surfaces for reference frames
    available_ref_surfaces: Vec<Surface>,

    /// Active reference pictures and their display frame index, cleared when rendering an IDR frame
    reference_frames: Vec<(Surface, ffi::VAPictureH264)>,

    /// Source pictures with their display index that should be rendered into B-Frames
    /// once a P or I Frame has been rendered and can be used as reference
    backlogged_b_frames: Vec<(Surface, u32)>,

    // TODO: counters
    // total frame counter. submitted: u64
    // and the rest can be derived?
    max_pic_order_cnt_lsb: i32,
    pic_order_cnt_msb_ref: i32,
    pic_order_cnt_lsb_ref: i32,

    output: VecDeque<Buffer>,
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
        }

        // Test if packed headers are available, and enable some if they are
        let packed_headers_attr =
            attributes[ffi::VAConfigAttribType_VAConfigAttribEncPackedHeaders as usize];
        let packed_headers_attr_supported =
            packed_headers_attr.value != ffi::VA_ATTRIB_NOT_SUPPORTED;
        if packed_headers_attr_supported {
            config_attributes.push(ffi::VAConfigAttrib {
                type_: ffi::VAConfigAttribType_VAConfigAttribEncPackedHeaders,
                value: packed_headers_attr.value
                    & (ffi::VA_ENC_PACKED_HEADER_SEQUENCE
                        | ffi::VA_ENC_PACKED_HEADER_PICTURE
                        | ffi::VA_ENC_PACKED_HEADER_SLICE
                        | ffi::VA_ENC_PACKED_HEADER_MISC),
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

        let idr_period = h264_config.gop.unwrap_or(60);

        VaH264Encoder {
            h264_config,
            display: display.clone(),
            config,
            context,
            support_packed_headers: packed_headers_attr_supported,
            width_mbaligned,
            height_mbaligned,
            target_bitrate: h264_config.bitrate.unwrap_or(6_000_000),
            frame_type_pattern: FrameTypePattern {
                idr_period,
                i_period: None,
                p_period: Some(2),
            },
            num_submitted_frames: 0,
            num_encoded_frames: 0,
            available_src_surfaces: src_surfaces,
            available_ref_surfaces: ref_surfaces,
            reference_frames: Vec::new(),
            backlogged_b_frames: Vec::new(),
            max_pic_order_cnt_lsb: 1 << (idr_period as f32).log2().ceil() as i32,
            pic_order_cnt_msb_ref: 0,
            pic_order_cnt_lsb_ref: 0,
            current_idr_display: 0,
            output: VecDeque::new(),
        }
    }

    pub fn pop_result(&mut self) -> Option<Buffer> {
        self.output.pop_front()
    }

    pub fn encode_frame(
        &mut self,
        src_data: [&[u8]; 3],
        src_strides: [usize; 3],
        src_width: u32,
        src_height: u32,
    ) {
        let mut src_surface = self.available_src_surfaces.pop().unwrap();
        upload_yuv_to_surface(
            src_data,
            src_strides,
            src_width,
            src_height,
            &mut src_surface,
        );

        let frame_type = self
            .frame_type_pattern
            .frame_type_of_nth_frame(self.num_submitted_frames);

        // B-Frames are not encoded immediately, they are queued until after a I or P frame is encoded
        if frame_type == FrameType::B {
            self.backlogged_b_frames
                .push((src_surface, self.num_submitted_frames));
            self.num_submitted_frames += 1;
            return;
        }

        if frame_type == FrameType::IDR {
            self.current_idr_display = self.num_submitted_frames;
        }

        self.encode_surface(self.num_submitted_frames, src_surface, frame_type);

        if matches!(frame_type, FrameType::IDR | FrameType::I | FrameType::P) {
            let backlogged_b_frames = take(&mut self.backlogged_b_frames);

            // Process backlogged B-Frames
            for (src_surface, src_display_index) in backlogged_b_frames {
                self.encode_surface(src_display_index, src_surface, FrameType::B);
            }
        }

        if frame_type == FrameType::IDR {
            // Just encoded an IDR frame, put all reference surfaces back into the surface pool,
            // except for the latest one, which is the IDR frame itself
            self.available_ref_surfaces.extend(
                self.reference_frames
                    .drain(..self.reference_frames.len() - 1)
                    .map(|(ref_surface, _)| ref_surface),
            );
        }

        self.num_submitted_frames += 1;
    }

    fn encode_surface(&mut self, display_index: u32, src_surface: Surface, frame_type: FrameType) {
        log::trace!(
            "encode surface frame_type={frame_type:?} encoding_index: {} display_index: {display_index}",
            self.num_encoded_frames
        );

        // EncCodec buffer size is estimated from the input image resolution. Currently using a higher value to ensure
        // proper output even with worst case input
        let coded_buffer_size =
            (self.width_mbaligned as f64 * self.height_mbaligned as f64 * 2.5) as usize;

        let coded_buffer = self
            .context
            .create_buffer_empty(ffi::VABufferType_VAEncCodedBufferType, coded_buffer_size);

        self.context.begin_picture(&src_surface);

        let mut bufs = Vec::new();

        let seq_param = self.create_seq_params();
        let pic_param = self.create_picture_params(
            self.num_encoded_frames,
            display_index,
            frame_type,
            &coded_buffer,
        );
        let slice_param =
            self.create_slice_params(self.num_encoded_frames, display_index, frame_type);
        let packed_slice_params =
            bitstream::write_slice_header(&seq_param, &pic_param, &slice_param);

        if frame_type == FrameType::IDR {
            let rc_params_buf = self.create_rate_control_params();

            let packed_sequence_param = bitstream::write_sps_rbsp(&self.h264_config, &seq_param);
            let packed_picture_param = bitstream::write_pps_rbsp(&pic_param);

            bufs.push(self.context.create_buffer_with_data(
                ffi::VABufferType_VAEncSequenceParameterBufferType,
                &seq_param,
            ));
            bufs.push(rc_params_buf);
            bufs.push(self.context.create_buffer_with_data(
                ffi::VABufferType_VAEncPictureParameterBufferType,
                &pic_param,
            ));

            {
                let (a, b) = self.create_packed_param(
                    ffi::VAEncPackedHeaderTypeH264_VAEncPackedHeaderH264_SPS,
                    &packed_sequence_param,
                );
                bufs.extend([a, b]);
            }

            {
                let (a, b) = self.create_packed_param(
                    ffi::VAEncPackedHeaderTypeH264_VAEncPackedHeaderH264_PPS,
                    &packed_picture_param,
                );
                bufs.extend([a, b]);
            }

            bufs.push(self.context.create_buffer_with_data(
                ffi::VABufferType_VAEncSliceParameterBufferType,
                &slice_param,
            ));

            {
                let (a, b) = self.create_packed_param(
                    ffi::VAEncPackedHeaderTypeH264_VAEncPackedHeaderH264_Slice,
                    &packed_slice_params,
                );
                bufs.extend([a, b]);
            }
        } else {
            bufs.push(self.context.create_buffer_with_data(
                ffi::VABufferType_VAEncPictureParameterBufferType,
                &pic_param,
            ));

            bufs.push(self.context.create_buffer_with_data(
                ffi::VABufferType_VAEncSliceParameterBufferType,
                &slice_param,
            ));

            {
                let (a, b) = self.create_packed_param(
                    ffi::VAEncPackedHeaderTypeH264_VAEncPackedHeaderH264_Slice,
                    &packed_slice_params,
                );
                bufs.extend([a, b]);
            }
        }

        self.context.render_picture(&bufs);

        self.context.end_picture();

        drop(bufs); // use bufs after `end_picture` to make sure they're available

        // Put the source surface back into the pool
        self.available_src_surfaces.push(src_surface);

        self.num_encoded_frames += 1;

        self.output.push_back(coded_buffer);
    }

    fn create_seq_params(&mut self) -> ffi::VAEncSequenceParameterBufferH264 {
        unsafe {
            let mut seq_param = zeroed::<ffi::VAEncSequenceParameterBufferH264>();

            seq_param.level_idc = self.h264_config.level.level_idc();
            seq_param.picture_width_in_mbs =
                (macro_block_align(self.h264_config.resolution.0) / 16) as u16;
            seq_param.picture_height_in_mbs =
                (macro_block_align(self.h264_config.resolution.1) / 16) as u16;

            seq_param.intra_period = self.frame_type_pattern.i_period.unwrap_or(0);
            seq_param.intra_idr_period = self.frame_type_pattern.idr_period;
            seq_param.ip_period = self.frame_type_pattern.p_period.unwrap_or(0);

            seq_param.max_num_ref_frames = 2; // TODO: configurable?
            seq_param.seq_fields.bits.set_frame_mbs_only_flag(1);
            seq_param.time_scale = 50; // TODO: configurable
            seq_param.num_units_in_tick = 1; // TODO: configurable

            // Calculate the picture order count bit count
            let log2_max_pic_order_count_lsb =
                (seq_param.intra_idr_period as f32).log2().ceil() as u32;
            // It is stored at an offset to 4
            let log2_max_pic_order_count_lsb_minus4 =
                log2_max_pic_order_count_lsb.saturating_sub(4).clamp(0, 12);
            seq_param
                .seq_fields
                .bits
                .set_log2_max_pic_order_cnt_lsb_minus4(log2_max_pic_order_count_lsb_minus4);

            seq_param
                .seq_fields
                .bits
                .set_log2_max_frame_num_minus4(16 - 4);
            seq_param.seq_fields.bits.set_frame_mbs_only_flag(1); // We're never going to do interlaced encoding
            seq_param
                .seq_fields
                .bits
                .set_chroma_format_idc(ffi::VA_RT_FORMAT_YUV420); // TODO: configurable this is currently harcoded to yuv420
            seq_param.seq_fields.bits.set_direct_8x8_inference_flag(1);

            let (width, height) = self.h264_config.resolution;

            if width != self.width_mbaligned || height != self.height_mbaligned {
                seq_param.frame_cropping_flag = 1;
                seq_param.frame_crop_right_offset = (self.width_mbaligned - width) / 2;
                seq_param.frame_crop_bottom_offset = (self.height_mbaligned - height) / 2;
            }

            seq_param
        }
    }

    fn create_packed_param(&self, type_: u32, buf: &[u8]) -> (Buffer, Buffer) {
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

        (packed_header_params, b)
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
            mapped
                .data()
                .cast::<ffi::VAEncMiscParameterBuffer>()
                .as_mut()
                .unwrap()
                .type_ = ffi::VAEncMiscParameterType_VAEncMiscParameterTypeRateControl;
            let rate_control_params = mapped
                .data()
                .byte_add(size_of::<ffi::VAEncMiscParameterBuffer>())
                .cast::<ffi::VAEncMiscParameterRateControl>()
                .as_mut()
                .unwrap();

            *rate_control_params = zeroed();

            // TODO: more rate control options
            rate_control_params.bits_per_second = self.target_bitrate;
            if let Some((min_qp, max_qp)) = self.h264_config.qp {
                rate_control_params.min_qp = min_qp;
                rate_control_params.max_qp = max_qp;
            }

            drop(mapped);

            rate_control_params_buffer
        }
    }

    fn calc_top_field_order_cnt(&mut self, frame_type: FrameType, pic_order_cnt_lsb: i32) -> i32 {
        log::trace!(
            "calc_picture_order_count frame_type={frame_type:?}, pic_order_cnt_lsb={pic_order_cnt_lsb}"
        );

        let (prev_pic_order_cnt_msb, prev_pic_order_cnt_lsb) = if frame_type == FrameType::IDR {
            (0, 0)
        } else {
            (self.pic_order_cnt_msb_ref, self.pic_order_cnt_lsb_ref)
        };

        let pic_order_cnt_msb = if (pic_order_cnt_lsb < prev_pic_order_cnt_lsb)
            && ((prev_pic_order_cnt_lsb - pic_order_cnt_lsb) >= (self.max_pic_order_cnt_lsb / 2))
        {
            prev_pic_order_cnt_msb + self.max_pic_order_cnt_lsb
        } else if (pic_order_cnt_lsb > prev_pic_order_cnt_lsb)
            && ((pic_order_cnt_lsb - prev_pic_order_cnt_lsb) > (self.max_pic_order_cnt_lsb / 2))
        {
            prev_pic_order_cnt_msb - self.max_pic_order_cnt_lsb
        } else {
            prev_pic_order_cnt_msb
        };

        let top_field_order_cnt = pic_order_cnt_msb + pic_order_cnt_lsb;

        if frame_type != FrameType::B {
            self.pic_order_cnt_msb_ref = pic_order_cnt_msb;
            self.pic_order_cnt_lsb_ref = pic_order_cnt_lsb;
        }

        top_field_order_cnt
    }

    fn create_picture_params(
        &mut self,
        encoding_index: u32,
        display_index: u32,
        frame_type: FrameType,
        coded_buffer: &Buffer,
    ) -> ffi::VAEncPictureParameterBufferH264 {
        unsafe {
            let ref_surface = if let Some(ref_surface) = self.available_ref_surfaces.pop() {
                ref_surface
            } else {
                self.reference_frames.remove(0).0
            };

            let mut pic_param = zeroed::<ffi::VAEncPictureParameterBufferH264>();

            pic_param.CurrPic.picture_id = ref_surface.id();
            pic_param.CurrPic.frame_idx = display_index - self.current_idr_display;
            pic_param.CurrPic.TopFieldOrderCnt = self.calc_top_field_order_cnt(
                frame_type,
                (display_index as i32 - self.current_idr_display as i32)
                    % self.max_pic_order_cnt_lsb,
            );
            pic_param.CurrPic.BottomFieldOrderCnt = pic_param.CurrPic.TopFieldOrderCnt;

            if matches!(frame_type, FrameType::IDR | FrameType::I | FrameType::P) {
                // Store the reference frame
                self.reference_frames.push((ref_surface, pic_param.CurrPic));
            } else {
                self.available_ref_surfaces.push(ref_surface);
            }

            if frame_type == FrameType::P {
                pic_param.ReferenceFrames[0] = self.reference_frames.last().unwrap().1;

                for pic in &mut pic_param.ReferenceFrames[1..] {
                    pic.picture_id = ffi::VA_INVALID_SURFACE;
                    pic.flags = ffi::VA_PICTURE_H264_INVALID;
                }
            }

            if frame_type == FrameType::B {
                let curr_frame_idx = display_index - self.current_idr_display;

                let a = self
                    .reference_frames
                    .iter()
                    .rev()
                    .find(|(_, p)| p.frame_idx < curr_frame_idx)
                    .unwrap();

                let b = self
                    .reference_frames
                    .iter()
                    .find(|(_, p)| p.frame_idx > curr_frame_idx)
                    .unwrap();

                pic_param.ReferenceFrames[0] = a.1;
                pic_param.ReferenceFrames[1] = b.1;

                for pic in &mut pic_param.ReferenceFrames[2..] {
                    pic.picture_id = ffi::VA_INVALID_SURFACE;
                    pic.flags = ffi::VA_PICTURE_H264_INVALID;
                }
            }

            // let mut reference_frames = self.reference_frames.iter();
            //
            //
            // for pic in &mut pic_param.ReferenceFrames {
            //     if let Some((ref_surface, ref_display_index)) = reference_frames.next() {
            //         pic.picture_id = ref_surface.id();
            //         pic.frame_idx = *ref_display_index;
            //     } else {
            //         pic.picture_id = ffi::VA_INVALID_SURFACE;
            //         pic.flags = ffi::VA_PICTURE_H264_INVALID;
            //     }
            // }

            pic_param
                .pic_fields
                .bits
                .set_idr_pic_flag((frame_type == FrameType::IDR) as u32);
            pic_param
                .pic_fields
                .bits
                .set_reference_pic_flag((frame_type != FrameType::B) as u32);
            pic_param.pic_fields.bits.set_entropy_coding_mode_flag(1); // TODO: configurable?
            pic_param
                .pic_fields
                .bits
                .set_deblocking_filter_control_present_flag(1); // TODO: configurable?

            pic_param.frame_num =
                ((encoding_index - self.current_idr_display) % u16::MAX as u32) as u16;
            pic_param.coded_buf = coded_buffer.id();
            pic_param.last_picture = 0; // TODO: set on flush
            pic_param.pic_init_qp = 10; // TODO: configurable

            pic_param
        }
    }

    fn create_slice_params(
        &mut self,
        encoding_index: u32,
        display_index: u32,
        frame_type: FrameType,
    ) -> ffi::VAEncSliceParameterBufferH264 {
        unsafe {
            let mut slice_params = zeroed::<ffi::VAEncSliceParameterBufferH264>();

            slice_params.num_macroblocks = self.width_mbaligned * self.height_mbaligned / (16 * 16);
            slice_params.slice_type = match frame_type {
                FrameType::P => 0,
                FrameType::B => 1,
                FrameType::IDR | FrameType::I => 2,
            };

            match frame_type {
                FrameType::P => {
                    slice_params.RefPicList0[0] = self.reference_frames.last().unwrap().1;

                    for pic in &mut slice_params.RefPicList0[1..] {
                        pic.picture_id = ffi::VA_INVALID_SURFACE;
                        pic.flags = ffi::VA_PICTURE_H264_INVALID;
                    }
                }
                FrameType::B => {
                    let curr_frame_idx = display_index - self.current_idr_display;

                    let a = self
                        .reference_frames
                        .iter()
                        .rev()
                        .find(|(_, p)| p.frame_idx < curr_frame_idx)
                        .unwrap();

                    let b = self
                        .reference_frames
                        .iter()
                        .find(|(_, p)| p.frame_idx > curr_frame_idx)
                        .unwrap();

                    slice_params.RefPicList0[0] = a.1;
                    slice_params.RefPicList1[0] = b.1;

                    for pic in &mut slice_params.RefPicList0[1..] {
                        pic.picture_id = ffi::VA_INVALID_SURFACE;
                        pic.flags = ffi::VA_PICTURE_H264_INVALID;
                    }

                    for pic in &mut slice_params.RefPicList1[1..] {
                        pic.picture_id = ffi::VA_INVALID_SURFACE;
                        pic.flags = ffi::VA_PICTURE_H264_INVALID;
                    }
                }
                FrameType::I => {}
                FrameType::IDR => {
                    // TODO: avoid overflow here, idr_pic_id just needs to be unique
                    slice_params.idr_pic_id = self.current_idr_display as u16;
                }
            }

            slice_params.direct_spatial_mv_pred_flag = 1;
            slice_params.pic_order_cnt_lsb = (display_index - self.current_idr_display) as u16
                % self.max_pic_order_cnt_lsb as u16;

            slice_params
        }
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
                    src_data[0].as_ptr().add(row as usize * src_strides[1]),
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
    use super::*;
    use rand::RngCore;
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::slice::from_raw_parts;
    use std::time::Instant;

    #[test]
    fn haha() {
        env_logger::init();
        let display = libva::Display::open_drm("/dev/dri/renderD129").unwrap();

        println!("profile: {:?}", display.profiles());

        let mut encoder = VaH264Encoder::new(
            &display,
            H264EncoderConfig {
                profile: crate::Profile::Main,
                level: crate::Level::Level_4_2,
                resolution: (1920, 1080),
                qp: None,
                gop: Some(10),
                bitrate: None,
                max_bitrate: None,
                max_slice_len: None,
            },
        );

        let mut openh264_decoder = openh264::decoder::Decoder::new().unwrap();

        let mut y = vec![0; 1920 * 1080];
        let mut uv = vec![0; (1920 / 2) * 1080];

        // rand::rng().fill_bytes(&mut y);
        // rand::rng().fill_bytes(&mut uv);

        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open("lol.h264")
            .unwrap();

        let mut parser = h264_parser::AnnexBParser::new();

        for i in 0..300 {
            rand::rng().fill_bytes(&mut y[..1920 * 100]);
            rand::rng().fill_bytes(&mut uv[..1920 * 100]);

            let ts = Instant::now();
            encoder.encode_frame([&y, &uv, &[]], [1920, 1920, 0], 1920, 1080);

            while let Some(mut buffer) = encoder.pop_result() {
                println!("After encode - {:?}", ts.elapsed());

                let mut mapped = buffer.map();

                let mut mapped_ptr = mapped.data();

                while !mapped_ptr.is_null() {
                    let mut x = unsafe { *mapped_ptr.cast::<ffi::VACodedBufferSegment>() };
                    mapped_ptr = x.next;

                    println!(
                        "After mapped - {} kbytes \t {:?}\t x={x:?}",
                        x.size / 1000,
                        ts.elapsed()
                    );

                    let buf = x.buf.cast::<u8>().cast_const();
                    let buf = unsafe { from_raw_parts(buf, x.size as usize) };

                    file.write_all(&buf).unwrap();
                    parser.push(buf);
                }

                // println!("{:X?}", &buf[..50]);
                // println!("{:X?}", &buf[buf.len() - 50..]);

                // for packet in openh264::nal_units(buf) {
                //     openh264_decoder.decode(packet).unwrap();
                // }

                // std::thread::sleep(Duration::from_millis(6));
            }
        }

        drop(file);

        // while let Some(x) = parser.next_access_unit().unwrap() {
        //     println!("{x:?}");
        //     println!()
        // }
    }
}
