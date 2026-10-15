use ezk_image::{
    ColorInfo, ColorSpace, ConvertError, Image, ImageError, ImageRef, PixelFormat, YuvColorInfo,
    convert_multi_thread,
};

use crate::{Buffer, Context, Display, FourCC, RtFormat, Surface, VaError, ffi, map_pixel_format};
use std::{
    collections::VecDeque,
    mem::zeroed,
    slice::{from_raw_parts, from_raw_parts_mut},
};

#[derive(Debug, Clone, Copy)]
pub struct VaEncoderImplConfig {
    pub user: VaEncoderConfig,
    pub va_rt_format: RtFormat,
    pub num_dpb_slots: u32,
    pub num_encode_slots: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct VaEncoderConfig {
    pub max_encode_resolution: [u32; 2],
    pub initial_encode_resolution: [u32; 2],
    pub rate_control: VaEncoderRateControlConfig,
}

#[derive(Debug, Clone, Copy)]
pub struct VaEncoderRateControlConfig {
    pub mode: VaEncoderRateControlMode,
    pub window_size: u32,
    pub initial_qp: u8,
    pub min_qp: u8,
    pub max_qp: u8,
    pub bitrate: u32,
    pub target_percentage: u32,
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct VaEncoderRateControlMode: u32 {
        const NONE = ffi::VA_RC_NONE;
        const CBR = ffi::VA_RC_CBR;
        const VBR = ffi::VA_RC_VBR;
        const VCM = ffi::VA_RC_VCM;
        const CQP = ffi::VA_RC_CQP;
        const VBR_CONSTRAINED = ffi::VA_RC_VBR_CONSTRAINED;
        const ICQ = ffi::VA_RC_ICQ;
        const MB = ffi::VA_RC_MB;
        const CFS = ffi::VA_RC_CFS;
        const PARALLEL = ffi::VA_RC_PARALLEL;
        const QVBR = ffi::VA_RC_QVBR;
        const AVBR = ffi::VA_RC_AVBR;
        const TCBRC = ffi::VA_RC_TCBRC;
    }
}

#[derive(Debug, thiserror::Error)]
pub enum VaEncoderCapabilitiesError {
    #[error("Profile {0:?} is not supported")]
    UnsupportedProfile(ffi::VAProfile),
    #[error("Failed to get entrypoints for profile {0:?}")]
    FailedToGetEntrypoints(#[source] VaError),
    #[error("No encode entrypoint for profile {0:?}")]
    UnsupportedEncodeProfile(ffi::VAProfile),
    #[error("Failed to get config attributes {0}")]
    FailedToGetConfigAttributes(#[source] VaError),
    #[error("Failed to get image formats {0}")]
    FailedToGetImageFormats(#[source] VaError),
}

#[derive(Debug, thiserror::Error)]
pub enum VaEncoderCreateError {
    #[error("Failed to create va config")]
    FailedToCreateConfig(#[source] VaError),
    #[error("Failed to create va surfaces")]
    FailedToCreateSurfaces(#[source] VaError),
    #[error("Failed to create va context")]
    FailedToCreateContext(#[source] VaError),
    #[error("Failed to create coded buffer")]
    FailedToCreateCodedBuffer(#[source] VaError),
}

#[derive(Debug, thiserror::Error)]
pub enum VaEncodeFrameError {
    #[error("Failed to create destination image from VAImage")]
    FailedToCreateDestinationImage(#[from] ImageError),

    #[error("Failed to convert/copy input image to VAImage")]
    FailedToConvert(#[from] ConvertError),

    #[error(transparent)]
    Va(#[from] VaError),
}

#[derive(Debug)]
pub struct VaEncoderCapabilities {
    display: Display,

    va_profile: ffi::VAProfile,
    va_entrypoint: ffi::VAEntrypoint,

    support_packed_headers: bool,
    support_packed_header_sequence: bool,
    support_packed_header_picture: bool,
    support_packed_header_slice: bool,

    // e.g. ffi::VA_RT_FORMAT_YUV420
    pub rt_formats: RtFormat,

    pub rc_modes: VaEncoderRateControlMode,

    pub max_reference_frames: u32,

    pub max_width: u32,
    pub max_height: u32,

    pub max_quality_level: Option<u32>,

    // Slice structures
    pub slice_structure_support_power_of_two_rows: bool,
    pub slice_structure_support_arbitrary_macroblocks: bool,
    pub slice_structure_support_equal_rows: bool,
    pub slice_structure_support_max_slice_size: bool,
    pub slice_structure_support_arbitrary_rows: bool,
    pub slice_structure_support_equal_multi_rows: bool,

    pub image_formats: Vec<FourCC>,
}

impl VaEncoderCapabilities {
    pub fn new(
        display: &Display,
        va_profile: ffi::VAProfile,
    ) -> Result<VaEncoderCapabilities, VaEncoderCapabilitiesError> {
        type E = VaEncoderCapabilitiesError;

        let va_entrypoint = display
            .entrypoints(va_profile)
            .map_err(E::FailedToGetEntrypoints)?
            .into_iter()
            .find(|&e| {
                e == ffi::VAEntrypoint_VAEntrypointEncSlice
                    || e == ffi::VAEntrypoint_VAEntrypointEncSliceLP
            })
            .ok_or(E::UnsupportedEncodeProfile(va_profile))?;

        let attrs = display
            .get_config_attributes(va_profile, va_entrypoint)
            .map_err(E::FailedToGetConfigAttributes)?;

        let mut support_packed_headers = false;
        let mut support_packed_header_sequence = false;
        let mut support_packed_header_picture = false;
        let mut support_packed_header_slice = false;

        {
            let value =
                attrs[ffi::VAConfigAttribType_VAConfigAttribEncPackedHeaders as usize].value;

            if value != ffi::VA_ATTRIB_NOT_SUPPORTED {
                support_packed_headers = true;
                support_packed_header_sequence = (value & ffi::VA_ENC_PACKED_HEADER_SEQUENCE) != 0;
                support_packed_header_picture = (value & ffi::VA_ENC_PACKED_HEADER_PICTURE) != 0;
                support_packed_header_slice = (value & ffi::VA_ENC_PACKED_HEADER_SLICE) != 0;
            }
        }

        let rc_modes = attrs[ffi::VAConfigAttribType_VAConfigAttribRateControl as usize].value;
        let rt_formats = attrs[ffi::VAConfigAttribType_VAConfigAttribRTFormat as usize].value;
        let max_reference_frames =
            attrs[ffi::VAConfigAttribType_VAConfigAttribEncMaxRefFrames as usize].value;
        let max_width = attrs[ffi::VAConfigAttribType_VAConfigAttribMaxPictureWidth as usize].value;
        let max_height =
            attrs[ffi::VAConfigAttribType_VAConfigAttribMaxPictureHeight as usize].value;

        let max_quality_level = {
            let value = attrs[ffi::VAConfigAttribType_VAConfigAttribEncQualityRange as usize].value;

            if value == ffi::VA_ATTRIB_NOT_SUPPORTED {
                None
            } else {
                Some(value)
            }
        };

        // EncSliceStructure
        let enc_slice_structures =
            attrs[ffi::VAConfigAttribType_VAConfigAttribEncSliceStructure as usize].value;

        let mut slice_structure_support_power_of_two_rows = false;
        let mut slice_structure_support_arbitrary_macroblocks = false;
        let mut slice_structure_support_equal_rows = false;
        let mut slice_structure_support_max_slice_size = false;
        let mut slice_structure_support_arbitrary_rows = false;
        let mut slice_structure_support_equal_multi_rows = false;

        if enc_slice_structures != ffi::VA_ATTRIB_NOT_SUPPORTED {
            slice_structure_support_power_of_two_rows =
                enc_slice_structures & ffi::VA_ENC_SLICE_STRUCTURE_POWER_OF_TWO_ROWS != 0;
            slice_structure_support_arbitrary_macroblocks =
                enc_slice_structures & ffi::VA_ENC_SLICE_STRUCTURE_ARBITRARY_MACROBLOCKS != 0;
            slice_structure_support_equal_rows =
                enc_slice_structures & ffi::VA_ENC_SLICE_STRUCTURE_EQUAL_ROWS != 0;
            slice_structure_support_max_slice_size =
                enc_slice_structures & ffi::VA_ENC_SLICE_STRUCTURE_MAX_SLICE_SIZE != 0;
            slice_structure_support_arbitrary_rows =
                enc_slice_structures & ffi::VA_ENC_SLICE_STRUCTURE_ARBITRARY_ROWS != 0;
            slice_structure_support_equal_multi_rows =
                enc_slice_structures & ffi::VA_ENC_SLICE_STRUCTURE_EQUAL_MULTI_ROWS != 0;
        }

        let image_formats = display
            .image_formats()
            .map_err(E::FailedToGetConfigAttributes)?
            .into_iter()
            .map(|image_format| FourCC::from_bits_retain(image_format.fourcc))
            .collect();

        Ok(VaEncoderCapabilities {
            display: display.clone(),
            va_profile,
            va_entrypoint,
            support_packed_headers,
            support_packed_header_sequence,
            support_packed_header_picture,
            support_packed_header_slice,
            rt_formats: RtFormat::from_bits_retain(rt_formats),
            rc_modes: VaEncoderRateControlMode::from_bits_retain(rc_modes),
            max_reference_frames,
            max_width,
            max_height,
            max_quality_level,
            slice_structure_support_power_of_two_rows,
            slice_structure_support_arbitrary_macroblocks,
            slice_structure_support_equal_rows,
            slice_structure_support_max_slice_size,
            slice_structure_support_arbitrary_rows,
            slice_structure_support_equal_multi_rows,
            image_formats,
        })
    }

    pub fn profile(&self) -> ffi::VAProfile {
        self.va_profile
    }

    pub fn supported_pixel_formats(&self) -> Vec<PixelFormat> {
        self.image_formats
            .iter()
            .copied()
            .filter_map(map_pixel_format)
            .collect()
    }

    pub fn create_encoder(
        &self,
        config: VaEncoderImplConfig,
    ) -> Result<VaEncoder, VaEncoderCreateError> {
        type E = VaEncoderCreateError;

        let mut config_attributes = Vec::new();
        config_attributes.push(ffi::VAConfigAttrib {
            type_: ffi::VAConfigAttribType_VAConfigAttribRTFormat,
            value: config.va_rt_format.bits(),
        });

        if self.support_packed_headers {
            let mut value = 0;

            if self.support_packed_header_sequence {
                value |= ffi::VA_ENC_PACKED_HEADER_SEQUENCE
            }

            if self.support_packed_header_picture {
                value |= ffi::VA_ENC_PACKED_HEADER_PICTURE
            }

            if self.support_packed_header_slice {
                value |= ffi::VA_ENC_PACKED_HEADER_SLICE
            }

            config_attributes.push(ffi::VAConfigAttrib {
                type_: ffi::VAConfigAttribType_VAConfigAttribEncPackedHeaders,
                value,
            });
        }

        config_attributes.push(ffi::VAConfigAttrib {
            type_: ffi::VAConfigAttribType_VAConfigAttribRateControl,
            value: config.user.rate_control.mode.bits(),
        });

        let va_config = self
            .display
            .create_config(self.va_profile, self.va_entrypoint, &config_attributes)
            .map_err(E::FailedToCreateConfig)?;

        let input_surfaces = self
            .display
            .create_surfaces(
                config.va_rt_format.bits(),
                config.user.max_encode_resolution[0],
                config.user.max_encode_resolution[1],
                config.num_encode_slots,
                &[],
            )
            .map_err(E::FailedToCreateSurfaces)?;

        let reference_surfaces = self
            .display
            .create_surfaces(
                config.va_rt_format.bits(),
                config.user.max_encode_resolution[0],
                config.user.max_encode_resolution[1],
                config.num_dpb_slots,
                &[],
            )
            .map_err(E::FailedToCreateSurfaces)?;

        let context = self
            .display
            .create_context(
                &va_config,
                config.user.max_encode_resolution[0] as i32,
                config.user.max_encode_resolution[1] as i32,
                ffi::VA_PROGRESSIVE as _,
                input_surfaces.iter().chain(reference_surfaces.iter()),
            )
            .map_err(E::FailedToCreateContext)?;

        // EncCodec buffer size is estimated from the input image resolution. Currently using a higher value to ensure
        // proper output even with worst case input
        let output_buffer_size = (config.user.max_encode_resolution[0] as f64
            * config.user.max_encode_resolution[1] as f64
            * 1.5) as usize;

        let encode_slots = input_surfaces
            .into_iter()
            .map(|surface| -> Result<VaEncodeSlot, VaError> {
                let output = context.create_buffer_empty(
                    ffi::VABufferType_VAEncCodedBufferType,
                    output_buffer_size,
                )?;

                Ok(VaEncodeSlot { surface, output })
            })
            .collect::<Result<Vec<_>, VaError>>()
            .map_err(E::FailedToCreateCodedBuffer)?;

        Ok(VaEncoder {
            context,
            max_encode_resolution: config.user.max_encode_resolution,
            current_encode_resolution: config.user.initial_encode_resolution,
            support_packed_header_sequence: self.support_packed_header_sequence,
            support_packed_header_picture: self.support_packed_header_picture,
            support_packed_header_slice: self.support_packed_header_slice, // TODO quality level
            rate_control: config.user.rate_control,
            quality_level: 0,
            encode_slots,
            in_flight: VecDeque::new(),
            dpb_slots: reference_surfaces,
            output: VecDeque::new(),
        })
    }
}

pub struct VaEncoder {
    context: Context,

    max_encode_resolution: [u32; 2],
    current_encode_resolution: [u32; 2],

    pub support_packed_header_sequence: bool,
    pub support_packed_header_picture: bool,
    pub support_packed_header_slice: bool,

    rate_control: VaEncoderRateControlConfig,
    quality_level: u32,

    encode_slots: Vec<VaEncodeSlot>,
    in_flight: VecDeque<VaEncodeSlot>,

    dpb_slots: Vec<Surface>,

    output: VecDeque<Vec<u8>>,
}

pub struct VaEncodeSlot {
    surface: Surface,
    output: Buffer,
}

impl VaEncodeSlot {
    pub fn output_buffer(&self) -> &Buffer {
        &self.output
    }
}

impl VaEncoder {
    pub fn context(&self) -> &Context {
        &self.context
    }

    pub fn max_encode_resolution(&self) -> [u32; 2] {
        self.max_encode_resolution
    }

    pub fn current_encode_resolution(&self) -> [u32; 2] {
        self.current_encode_resolution
    }

    pub fn dpb_slot_surface(&self, dpb_slot_index: usize) -> &Surface {
        &self.dpb_slots[dpb_slot_index]
    }

    fn read_out_encode_slot(&mut self, encode_slot: &mut VaEncodeSlot) -> Result<(), VaError> {
        let mut codec_buffer_mapped = encode_slot.output.map()?;
        let mut ptr = codec_buffer_mapped.data();

        while !ptr.is_null() {
            let segment = unsafe { ptr.cast::<ffi::VACodedBufferSegment>().read() };
            ptr = segment.next;

            let buf = segment.buf.cast::<u8>().cast_const();
            let buf = unsafe { from_raw_parts(buf, segment.size as usize) };

            self.output.push_back(buf.to_vec());
        }

        Ok(())
    }

    pub fn pop_encode_slot(&mut self) -> Result<Option<VaEncodeSlot>, VaError> {
        if let Some(encode_slot) = self.encode_slots.pop() {
            return Ok(Some(encode_slot));
        }

        let Some(mut encode_slot) = self.in_flight.pop_front() else {
            return Ok(None);
        };

        encode_slot.surface.sync()?;
        self.read_out_encode_slot(&mut encode_slot)?;

        Ok(Some(encode_slot))
    }

    pub fn poll_result(&mut self) -> Result<Option<Vec<u8>>, VaError> {
        if let Some(output) = self.output.pop_front() {
            return Ok(Some(output));
        }

        if let Some(encode_slot) = self.in_flight.front_mut() {
            let completed = encode_slot.surface.try_sync()?;
            if !completed {
                return Ok(None);
            }

            let mut encode_slot = self.in_flight.pop_front().unwrap();
            self.read_out_encode_slot(&mut encode_slot)?;
            self.encode_slots.push(encode_slot);
        }

        Ok(self.output.pop_front())
    }

    pub fn wait_result(&mut self) -> Result<Option<Vec<u8>>, VaError> {
        if let Some(output) = self.output.pop_front() {
            return Ok(Some(output));
        }

        if let Some(mut encode_slot) = self.in_flight.pop_front() {
            encode_slot.surface.sync()?;
            self.read_out_encode_slot(&mut encode_slot)?;
            self.encode_slots.push(encode_slot);
        }

        Ok(self.output.pop_front())
    }

    pub fn copy_image_to_encode_slot(
        &mut self,
        encode_slot: &mut VaEncodeSlot,
        image: &dyn ImageRef,
    ) -> Result<(), VaEncodeFrameError> {
        let mut dst = encode_slot.surface.derive_image()?;
        let dst_img = *dst.ffi();
        let dst_pixel_format = map_pixel_format(FourCC::from_bits_truncate(dst_img.format.fourcc))
            .expect("Unknown FourCC in input surface");

        // Safety: the mapped image must live for this entire scope
        unsafe {
            let mut mapped = dst.map()?;

            let mut planes = vec![];
            let mut strides = vec![];

            strides.push(dst_img.pitches[0] as usize);
            planes.push(from_raw_parts_mut(
                mapped.data().add(dst_img.offsets[0] as usize),
                (dst_img.offsets[1] - dst_img.offsets[0]) as usize,
            ));

            if dst_img.num_planes >= 2 {
                let next_start = if dst_img.num_planes == 2 {
                    dst_img.data_size
                } else {
                    dst_img.offsets[2]
                };

                strides.push(dst_img.pitches[1] as usize);
                planes.push(from_raw_parts_mut(
                    mapped.data().add(dst_img.offsets[1] as usize),
                    (next_start - dst_img.offsets[1]) as usize,
                ));
            }

            if dst_img.num_planes == 3 {
                strides.push(dst_img.pitches[2] as usize);
                planes.push(from_raw_parts_mut(
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
            )?;

            convert_multi_thread(image, &mut dst_image)?;
        }

        Ok(())
    }

    pub fn create_quality_params(&self) -> Result<Buffer, VaError> {
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

            enc_quality_params.quality_level = self.quality_level;

            drop(mapped);

            Ok(quality_params_buffer)
        }
    }

    pub fn create_rate_control_params(&self) -> Result<Buffer, VaError> {
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

            let VaEncoderRateControlConfig {
                mode: _,
                window_size,
                initial_qp,
                min_qp,
                max_qp,
                bitrate,
                target_percentage,
            } = self.rate_control;

            rate_control_params.window_size = window_size;
            rate_control_params.initial_qp = initial_qp.into();
            rate_control_params.min_qp = min_qp.into();
            rate_control_params.max_qp = max_qp.into();
            rate_control_params.target_percentage = target_percentage;
            rate_control_params.bits_per_second = bitrate;

            drop(mapped);

            Ok(rate_control_params_buffer)
        }
    }

    pub fn create_max_slice_size_params(&self, max_slice_size: u32) -> Result<Buffer, VaError> {
        unsafe {
            let mut quality_params_buffer = self.context.create_buffer_empty(
                ffi::VABufferType_VAEncMiscParameterBufferType,
                size_of::<ffi::VAEncMiscParameterBuffer>()
                    + size_of::<ffi::VAEncMiscParameterMaxSliceSize>(),
            )?;
            let mut mapped = quality_params_buffer.map()?;
            let misc_param = &mut *mapped.data().cast::<ffi::VAEncMiscParameterBuffer>();
            misc_param.type_ = ffi::VAEncMiscParameterType_VAEncMiscParameterTypeMaxSliceSize;

            let enc_max_slice_size_params = &mut *misc_param
                .data
                .as_mut_ptr()
                .cast::<ffi::VAEncMiscParameterMaxSliceSize>();

            *enc_max_slice_size_params = zeroed();

            enc_max_slice_size_params.max_slice_size = max_slice_size;

            drop(mapped);

            Ok(quality_params_buffer)
        }
    }

    pub fn create_packed_param(
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

    pub fn submit_encode_slot(
        &mut self,
        encode_slot: VaEncodeSlot,
        encode_params: Vec<Buffer>,
    ) -> Result<(), VaError> {
        let begin_picture_result = self.context.begin_picture(&encode_slot.surface);

        self.in_flight.push_back(encode_slot);

        let pipeline = begin_picture_result?;

        pipeline.render_picture(&encode_params)?;
        pipeline.end_picture()?;

        drop(encode_params);

        Ok(())
    }
}
