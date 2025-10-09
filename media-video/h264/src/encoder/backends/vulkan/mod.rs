use super::stateless::{H264EncoderBackend, H264EncoderBackendResources};
use crate::{
    Level, Profile,
    encoder::{
        H264Encoder, H264EncoderCapabilities, H264EncoderConfig, H264EncoderDevice, H264FrameRate,
        H264FrameType, H264RateControlConfig,
        backends::stateless::H264StatelessEncoder,
        util::{FrameEncodeInfo, macro_block_align},
    },
};
use ezk_image::{ColorInfo, ColorSpace, ImageRef, PixelFormat, YuvColorInfo, convert_multi_thread};
use std::{cmp, collections::VecDeque, mem::zeroed, ptr::null_mut};
use vulkan::{
    Buffer, CommandBuffer, Device, Fence, Image, ImageView, PhysicalDevice,
    REQUIRED_EXTENSIONS_BASE, REQUIRED_EXTENSIONS_ENCODE, RecordingCommandBuffer, Semaphore,
    VideoFeedbackQueryPool, VideoSession, VideoSessionParameters, VulkanError,
    ash::vk::{self, Handle},
    create_dpb,
};

const PARALLEL_ENCODINGS: u32 = 16;

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
        let (profile_idc, subsampling) = map_profile(profile).unwrap();

        let mut h264_profile_info =
            vk::VideoEncodeH264ProfileInfoKHR::default().std_profile_idc(profile_idc);

        let video_profile_info = vk::VideoProfileInfoKHR::default()
            .video_codec_operation(vk::VideoCodecOperationFlagsKHR::ENCODE_H264)
            .chroma_bit_depth(vk::VideoComponentBitDepthFlagsKHR::TYPE_8)
            .luma_bit_depth(vk::VideoComponentBitDepthFlagsKHR::TYPE_8)
            .chroma_subsampling(subsampling)
            .push_next(&mut h264_profile_info);

        // Video Coding Capabilities
        let (video_capabilities, video_encode_capabilities, video_encode_h264_capabilities) =
            self.video_capabilities::<vk::VideoEncodeH264CapabilitiesKHR>(video_profile_info)?;

        let video_formats = self.video_format_properties(&[video_profile_info])?;

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
            min_qp: video_encode_h264_capabilities.min_qp as u8,
            max_qp: video_encode_h264_capabilities.max_qp as u8,
            min_resolution: (
                video_capabilities.min_coded_extent.width,
                video_capabilities.min_coded_extent.height,
            ),
            max_resolution: (
                video_capabilities.max_coded_extent.width,
                video_capabilities.max_coded_extent.height,
            ),
            max_l0_p_references: video_encode_h264_capabilities.max_p_picture_l0_reference_count,
            max_l0_b_references: video_encode_h264_capabilities.max_b_picture_l0_reference_count,
            max_l1_b_references: video_encode_h264_capabilities.max_l1_reference_count,
            max_quality_level: video_encode_capabilities.max_quality_levels,
            formats,
        })
    }

    fn create_encoder(
        &mut self,
        config: H264EncoderConfig,
    ) -> Result<Self::Encoder, Self::CreateEncoderError> {
        let queue_family_properties = unsafe {
            self.instance()
                .instance()
                .get_physical_device_queue_family_properties(self.physical_device())
        };

        // TODO: check if theres a single queue with both TRANSFER & ENCODE and encode using a single queue
        let transfer_queue_family_index = queue_family_properties
            .iter()
            .position(|prop| {
                prop.queue_flags.contains(vk::QueueFlags::TRANSFER)
                    && !prop.queue_flags.contains(vk::QueueFlags::VIDEO_ENCODE_KHR)
            })
            .unwrap() as u32;

        let encode_queue_family_index = queue_family_properties
            .iter()
            .enumerate()
            .position(|(i, prop)| {
                prop.queue_flags.contains(vk::QueueFlags::VIDEO_ENCODE_KHR)
                    && i as u32 != transfer_queue_family_index
            })
            .unwrap() as u32;

        // Create device
        let extensions: Vec<_> = [
            REQUIRED_EXTENSIONS_BASE,
            REQUIRED_EXTENSIONS_ENCODE,
            &[c"VK_KHR_video_encode_h264"],
        ]
        .iter()
        .flat_map(|exts| exts.iter())
        .map(|ext| ext.as_ptr())
        .collect();

        let mut sync2_features_enable =
            vk::PhysicalDeviceSynchronization2Features::default().synchronization2(true);
        let queue_create_flags = [
            vk::DeviceQueueCreateInfo::default()
                .queue_family_index(transfer_queue_family_index)
                .queue_priorities(&[1.0]),
            vk::DeviceQueueCreateInfo::default()
                .queue_family_index(encode_queue_family_index)
                .queue_priorities(&[1.0]),
        ];
        let create_device_info = vk::DeviceCreateInfo::default()
            .enabled_extension_names(&extensions)
            .queue_create_infos(&queue_create_flags)
            .push_next(&mut sync2_features_enable);

        let device = unsafe {
            Device::create(self.instance(), self.physical_device(), &create_device_info)?
        };

        let (transfer_queue, encode_queue) = unsafe {
            let transfer_queue = device
                .device()
                .get_device_queue(transfer_queue_family_index, 0);
            let encode_queue = device
                .device()
                .get_device_queue(encode_queue_family_index, 0);

            assert!(!transfer_queue.is_null());
            assert!(!encode_queue.is_null());

            (transfer_queue, encode_queue)
        };

        let (profile_idc, subsampling) = map_profile(config.profile).unwrap();

        let mut h264_profile_info =
            vk::VideoEncodeH264ProfileInfoKHR::default().std_profile_idc(profile_idc);

        let video_profile_info = vk::VideoProfileInfoKHR::default()
            .video_codec_operation(vk::VideoCodecOperationFlagsKHR::ENCODE_H264)
            .chroma_bit_depth(vk::VideoComponentBitDepthFlagsKHR::TYPE_8)
            .luma_bit_depth(vk::VideoComponentBitDepthFlagsKHR::TYPE_8)
            .chroma_subsampling(subsampling)
            .push_next(&mut h264_profile_info);

        // Video Coding Capabilities
        let (video_capabilities, _video_encode_capabilities, video_encode_h264_capabilities) =
            self.video_capabilities::<vk::VideoEncodeH264CapabilitiesKHR>(video_profile_info)?;

        let max_references = cmp::max(
            video_encode_h264_capabilities.max_p_picture_l0_reference_count,
            video_encode_h264_capabilities.max_b_picture_l0_reference_count
                + video_encode_h264_capabilities.max_l1_reference_count,
        );
        let max_active_ref_images = cmp::min(
            max_references,
            video_capabilities.max_active_reference_pictures,
        );

        // Make only as many dpb slots as can be actively references, + 1 for the setup reference
        let max_dpb_slots = cmp::min(video_capabilities.max_dpb_slots, max_active_ref_images + 1);

        // Create Video session
        let create_info = vk::VideoSessionCreateInfoKHR::default()
            .max_coded_extent(vk::Extent2D {
                width: config.resolution.0,
                height: config.resolution.1,
            })
            .queue_family_index(encode_queue_family_index)
            .max_active_reference_pictures(max_active_ref_images)
            .max_dpb_slots(max_dpb_slots)
            .picture_format(vk::Format::G8_B8R8_2PLANE_420_UNORM)
            .reference_picture_format(vk::Format::G8_B8R8_2PLANE_420_UNORM)
            .video_profile(&video_profile_info)
            .std_header_version(&video_capabilities.std_header_version);

        let video_session = unsafe { VideoSession::create(&device, &create_info)? };

        let video_feedback_query_pool =
            VideoFeedbackQueryPool::create(&device, PARALLEL_ENCODINGS, video_profile_info)?;

        // Create video session parameters
        let video_session_parameters = create_video_session_parameters(
            &video_session,
            config.resolution.0,
            config.resolution.1,
            max_active_ref_images as u8,
            profile_idc,
            map_level(config.level).unwrap(),
            vk::native::StdVideoH264ChromaFormatIdc_STD_VIDEO_H264_CHROMA_FORMAT_IDC_420,
        )?;

        // Create command buffers
        let mut transfer_command_buffers = unsafe {
            CommandBuffer::create(&device, transfer_queue_family_index, PARALLEL_ENCODINGS)?
        };

        let mut encode_command_buffers = unsafe {
            CommandBuffer::create(&device, encode_queue_family_index, PARALLEL_ENCODINGS)?
        };

        let output_buffer_size: u64 =
            (config.resolution.0 as u64 * config.resolution.1 as u64 * 3) / 2;
        let mut encode_slots = vec![];

        for index in 0..PARALLEL_ENCODINGS {
            let input_image = create_input_image(
                &device,
                video_profile_info,
                config.resolution.0,
                config.resolution.1,
            )?;

            let input_image_view = {
                let create_info = vk::ImageViewCreateInfo::default()
                    .image(unsafe { input_image.image() })
                    .view_type(vk::ImageViewType::TYPE_2D)
                    .format(vk::Format::G8_B8R8_2PLANE_420_UNORM)
                    .components(vk::ComponentMapping::default())
                    .subresource_range(vk::ImageSubresourceRange {
                        aspect_mask: vk::ImageAspectFlags::COLOR,
                        base_mip_level: 0,
                        level_count: 1,
                        base_array_layer: 0,
                        layer_count: 1,
                    });

                unsafe { ImageView::create(&input_image, &create_info)? }
            };

            let input_staging_buffer = {
                let create_info = vk::BufferCreateInfo::default()
                    .size((config.resolution.0 as u64 * config.resolution.1 as u64 * 12) / 8) // TODO: don't hardcode this to NV12
                    .usage(vk::BufferUsageFlags::TRANSFER_SRC)
                    .sharing_mode(vk::SharingMode::EXCLUSIVE);

                unsafe { Buffer::create(&device, &create_info)? }
            };

            let output_buffer = {
                let profiles = [video_profile_info];
                let mut video_profile_list_info =
                    vk::VideoProfileListInfoKHR::default().profiles(&profiles);

                let create_info = vk::BufferCreateInfo::default()
                    .size(output_buffer_size)
                    .usage(
                        vk::BufferUsageFlags::VIDEO_ENCODE_DST_KHR
                            | vk::BufferUsageFlags::TRANSFER_SRC,
                    )
                    .push_next(&mut video_profile_list_info);

                unsafe { Buffer::create(&device, &create_info)? }
            };

            let transfer_semaphore = Semaphore::create(&device)?;
            let completion_fence = Fence::create(&device)?;

            encode_slots.push(EncodeSlot {
                index,
                is_idr: false,
                input_staging_buffer,
                input_image,
                input_image_view,
                output_buffer,
                transfer_semaphore,
                transfer_command_buffer: transfer_command_buffers.pop().unwrap(),
                encode_command_buffer: encode_command_buffers.pop().unwrap(),
                completion_fence,
            });
        }

        let dpb_slots: Vec<DpbSlot> = create_dpb(
            &device,
            video_profile_info,
            max_dpb_slots,
            config.resolution.0,
            config.resolution.1,
        )?
        .into_iter()
        .enumerate()
        .map(|(i, image_view)| DpbSlot {
            slot_index: i as u32,
            image_view,
            h264_reference_info: unsafe { zeroed() },
        })
        .rev()
        .collect();

        let encode_slot = &mut encode_slots[0];

        // Prepare layouts
        unsafe {
            let fence = Fence::create(&device)?;

            let recording = encode_slot
                .encode_command_buffer
                .begin(&vk::CommandBufferBeginInfo::default())?;

            // Transition all dpb slots to the correct layout
            for dpb_slot in &dpb_slots {
                dpb_slot.image_view.image().cmd_memory_barrier2(
                    recording.command_buffer(),
                    vk::ImageLayout::UNDEFINED,
                    vk::ImageLayout::VIDEO_ENCODE_DPB_KHR,
                    vk::QUEUE_FAMILY_IGNORED,
                    vk::QUEUE_FAMILY_IGNORED,
                    vk::PipelineStageFlags2::TOP_OF_PIPE,
                    vk::AccessFlags2::empty(),
                    vk::PipelineStageFlags2::VIDEO_ENCODE_KHR,
                    vk::AccessFlags2::VIDEO_ENCODE_WRITE_KHR,
                    dpb_slot.image_view.subresource_range().base_array_layer,
                );
            }

            recording.end()?;

            let command_buffers = [encode_slot.encode_command_buffer.command_buffer()];
            let submit_info = vk::SubmitInfo::default().command_buffers(&command_buffers);

            device
                .device()
                .queue_submit(encode_queue, &[submit_info], fence.fence())?;

            fence.wait(u64::MAX)?;
        };

        let backend = VkBackend {
            config,
            width: config.resolution.0,
            height: config.resolution.1,
            output_buffer_size,
            device,
            transfer_queue_family_index,
            encode_queue_family_index,
            transfer_queue,
            encode_queue,
            video_feedback_query_pool,
            video_session,
            video_session_parameters,
            video_session_needs_control: true,
            video_session_is_uninitialized: true,
            rate_control: RateControl::default(),
        };

        let resources = H264EncoderBackendResources {
            backend,
            encode_slots,
            dpb_slots,
        };

        Ok(VkH264Encoder {
            driver: H264StatelessEncoder::new(config, resources),
        })
    }
}

pub struct VkH264Encoder {
    driver: H264StatelessEncoder<VkBackend>,
}

impl H264Encoder for VkH264Encoder {
    type Error = VulkanError;

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

struct VkBackend {
    config: H264EncoderConfig,

    width: u32,
    height: u32,

    output_buffer_size: u64,

    device: Device,

    transfer_queue_family_index: u32,
    encode_queue_family_index: u32,

    transfer_queue: vk::Queue,
    encode_queue: vk::Queue,

    video_feedback_query_pool: VideoFeedbackQueryPool,

    video_session: VideoSession,
    video_session_parameters: VideoSessionParameters,
    video_session_needs_control: bool,
    video_session_is_uninitialized: bool,

    rate_control: Box<RateControl>,
}

struct EncodeSlot {
    /// Index used for the video feedback query pool
    index: u32,

    is_idr: bool,

    input_staging_buffer: Buffer,

    input_image: Image,
    input_image_view: ImageView,

    output_buffer: Buffer,

    transfer_semaphore: Semaphore,

    transfer_command_buffer: CommandBuffer,
    encode_command_buffer: CommandBuffer,

    completion_fence: Fence,
}

struct DpbSlot {
    slot_index: u32,
    image_view: ImageView,
    h264_reference_info: vk::native::StdVideoEncodeH264ReferenceInfo,
}

impl H264EncoderBackend for VkBackend {
    type EncodeSlot = EncodeSlot;
    type DpbSlot = DpbSlot;
    type Error = VulkanError;

    fn wait_encode_slot(&mut self, encode_slot: &mut Self::EncodeSlot) -> Result<(), Self::Error> {
        encode_slot.completion_fence.wait(u64::MAX)?;
        encode_slot.completion_fence.reset()?;
        Ok(())
    }

    fn poll_encode_slot(
        &mut self,
        encode_slot: &mut Self::EncodeSlot,
    ) -> Result<bool, Self::Error> {
        if encode_slot.completion_fence.wait(0)? {
            encode_slot.completion_fence.reset()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn read_out_encode_slot(
        &mut self,
        encode_slot: &mut Self::EncodeSlot,
        output: &mut VecDeque<Vec<u8>>,
    ) -> Result<(), Self::Error> {
        if encode_slot.is_idr {
            // Write out SPS & PPS to bitstream
            let mut h264_get_encoded_params =
                vk::VideoEncodeH264SessionParametersGetInfoKHR::default()
                    .write_std_sps(true)
                    .write_std_pps(true);

            let sps_pps = unsafe {
                self.video_session_parameters
                    .get_encoded_video_session_parameters(&mut h264_get_encoded_params)?
            };

            output.push_back(sps_pps);
        }

        unsafe {
            let bytes_written = self
                .video_feedback_query_pool
                .get_bytes_written(encode_slot.index)?;

            let mapped_buffer = encode_slot.output_buffer.map(bytes_written.into())?;

            output.push_back(mapped_buffer.data().to_vec());
        }

        Ok(())
    }

    fn upload_image_to_slot(
        &mut self,
        encode_slot: &mut Self::EncodeSlot,
        image: &dyn ImageRef,
    ) -> Result<(), Self::Error> {
        // TODO: bounds checks
        unsafe {
            let mapped_buffer = encode_slot.input_staging_buffer.map(
                (self.config.resolution.0 as u64 * self.config.resolution.1 as u64 * 12) / 8,
            )?;

            let dst_color = match image.color() {
                ColorInfo::RGB(rgb_color_info) => YuvColorInfo {
                    transfer: rgb_color_info.transfer,
                    primaries: rgb_color_info.primaries,
                    space: ColorSpace::BT709,
                    full_range: true,
                },
                ColorInfo::YUV(yuv_color_info) => yuv_color_info,
            };

            let mut dst = ezk_image::Image::from_buffer(
                PixelFormat::NV12,
                mapped_buffer.data_mut(),
                None,
                self.width as usize,
                self.height as usize,
                dst_color.into(),
            )
            .unwrap();

            convert_multi_thread(image, &mut dst).unwrap();
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
    ) -> Result<(), Self::Error> {
        log::trace!("Encode frame {frame_info:?}");

        encode_slot.is_idr = frame_info.frame_type == H264FrameType::Idr;

        unsafe {
            self.record_transfer_queue(encode_slot);
        };

        unsafe {
            self.record_encode_queue(
                encode_slot,
                frame_info,
                setup_reference,
                l0_references,
                l1_references,
            );
        }

        Ok(())
    }
}

impl VkBackend {
    unsafe fn record_transfer_queue(&mut self, encode_slot: &mut EncodeSlot) {
        // Record TRANSFER queue
        let recording = encode_slot
            .transfer_command_buffer
            .begin(&vk::CommandBufferBeginInfo::default())
            .unwrap();

        // Change image type
        encode_slot.input_image.cmd_memory_barrier2(
            recording.command_buffer(),
            vk::ImageLayout::UNDEFINED,
            vk::ImageLayout::TRANSFER_DST_OPTIMAL,
            vk::QUEUE_FAMILY_IGNORED,
            vk::QUEUE_FAMILY_IGNORED,
            vk::PipelineStageFlags2::TOP_OF_PIPE,
            vk::AccessFlags2::empty(),
            vk::PipelineStageFlags2::TRANSFER,
            vk::AccessFlags2::TRANSFER_WRITE,
            0,
        );

        // Copy
        let buffer_image_copy_plane0 =
            buffer_image_copy(vk::ImageAspectFlags::PLANE_0, self.width, self.height, 0);
        let buffer_image_copy_plane1 = buffer_image_copy(
            vk::ImageAspectFlags::PLANE_1,
            self.width / 2,
            self.height / 2,
            self.width as u64 * self.height as u64,
        );

        self.device.device().cmd_copy_buffer_to_image(
            recording.command_buffer(),
            encode_slot.input_staging_buffer.buffer(),
            encode_slot.input_image.image(),
            vk::ImageLayout::TRANSFER_DST_OPTIMAL,
            &[buffer_image_copy_plane0, buffer_image_copy_plane1],
        );

        encode_slot.input_image.cmd_memory_barrier2(
            recording.command_buffer(),
            vk::ImageLayout::TRANSFER_DST_OPTIMAL,
            vk::ImageLayout::VIDEO_ENCODE_SRC_KHR,
            self.transfer_queue_family_index,
            self.encode_queue_family_index,
            vk::PipelineStageFlags2::TRANSFER,
            vk::AccessFlags2::TRANSFER_WRITE,
            vk::PipelineStageFlags2::NONE,
            vk::AccessFlags2::empty(),
            0,
        );

        recording.end().unwrap();

        let signal_semaphores = [encode_slot.transfer_semaphore.semaphore()];
        let command_buffers = [encode_slot.transfer_command_buffer.command_buffer()];
        let submit_info = vk::SubmitInfo::default()
            .command_buffers(&command_buffers)
            .signal_semaphores(&signal_semaphores);

        self.device
            .device()
            .queue_submit(self.transfer_queue, &[submit_info], vk::Fence::null())
            .unwrap();
    }

    unsafe fn record_encode_queue(
        &mut self,
        encode_slot: &mut EncodeSlot,
        frame_info: FrameEncodeInfo,
        setup_reference: &mut DpbSlot,
        l0_references: &[&DpbSlot],
        l1_references: &[&DpbSlot],
    ) {
        // Begin recording the encode queue
        let mut recording = encode_slot
            .encode_command_buffer
            .begin(&vk::CommandBufferBeginInfo::default())
            .unwrap();

        // Reset query for this encode
        self.video_feedback_query_pool
            .cmd_reset_query(recording.command_buffer(), encode_slot.index);

        // Transition the input image to the encode queue
        encode_slot.input_image.cmd_memory_barrier2(
            recording.command_buffer(),
            vk::ImageLayout::VIDEO_ENCODE_SRC_KHR,
            vk::ImageLayout::VIDEO_ENCODE_SRC_KHR,
            self.transfer_queue_family_index,
            self.encode_queue_family_index,
            vk::PipelineStageFlags2::NONE,
            vk::AccessFlags2::empty(),
            vk::PipelineStageFlags2::VIDEO_ENCODE_KHR,
            vk::AccessFlags2::VIDEO_ENCODE_READ_KHR,
            0,
        );

        // Barrier the setup dpb slot
        setup_reference.image_view.image().cmd_memory_barrier2(
            recording.command_buffer(),
            vk::ImageLayout::VIDEO_ENCODE_DPB_KHR,
            vk::ImageLayout::VIDEO_ENCODE_DPB_KHR,
            vk::QUEUE_FAMILY_IGNORED,
            vk::QUEUE_FAMILY_IGNORED,
            vk::PipelineStageFlags2::VIDEO_ENCODE_KHR,
            vk::AccessFlags2::VIDEO_ENCODE_READ_KHR | vk::AccessFlags2::VIDEO_ENCODE_WRITE_KHR,
            vk::PipelineStageFlags2::VIDEO_ENCODE_KHR,
            vk::AccessFlags2::VIDEO_ENCODE_WRITE_KHR,
            setup_reference
                .image_view
                .subresource_range()
                .base_array_layer,
        );

        // Barrier the active reference dpb slots
        for dpb_slot in l0_references.iter().chain(l1_references.iter()) {
            dpb_slot.image_view.image().cmd_memory_barrier2(
                recording.command_buffer(),
                vk::ImageLayout::VIDEO_ENCODE_DPB_KHR,
                vk::ImageLayout::VIDEO_ENCODE_DPB_KHR,
                vk::QUEUE_FAMILY_IGNORED,
                vk::QUEUE_FAMILY_IGNORED,
                vk::PipelineStageFlags2::VIDEO_ENCODE_KHR,
                vk::AccessFlags2::VIDEO_ENCODE_WRITE_KHR | vk::AccessFlags2::VIDEO_ENCODE_READ_KHR,
                vk::PipelineStageFlags2::VIDEO_ENCODE_KHR,
                vk::AccessFlags2::VIDEO_ENCODE_READ_KHR,
                dpb_slot.image_view.subresource_range().base_array_layer,
            );
        }

        let primary_pic_type = match frame_info.frame_type {
            H264FrameType::P => vk::native::StdVideoH264PictureType_STD_VIDEO_H264_PICTURE_TYPE_P,
            H264FrameType::B => vk::native::StdVideoH264PictureType_STD_VIDEO_H264_PICTURE_TYPE_B,
            H264FrameType::I => vk::native::StdVideoH264PictureType_STD_VIDEO_H264_PICTURE_TYPE_I,
            H264FrameType::Idr => {
                vk::native::StdVideoH264PictureType_STD_VIDEO_H264_PICTURE_TYPE_IDR
            }
        };

        // Update the actual reference info of the setup reference slot
        setup_reference.h264_reference_info = vk::native::StdVideoEncodeH264ReferenceInfo {
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

        let setup_reference_resource_info = vk::VideoPictureResourceInfoKHR::default()
            .image_view_binding(setup_reference.image_view.image_view())
            .coded_extent(vk::Extent2D {
                width: self.width,
                height: self.height,
            });

        let mut setup_reference_h264_slot = vk::VideoEncodeH264DpbSlotInfoKHR::default()
            .std_reference_info(&setup_reference.h264_reference_info);
        let setup_reference_slot = vk::VideoReferenceSlotInfoKHR::default()
            .picture_resource(&setup_reference_resource_info)
            .slot_index(setup_reference.slot_index as i32)
            .push_next(&mut setup_reference_h264_slot);

        // Prepare active reference images stuff
        let mut reference_slots_resources: Vec<_> = l0_references
            .iter()
            .chain(l1_references.iter())
            .map(|slot| {
                let h264_dpb_slot_info = vk::VideoEncodeH264DpbSlotInfoKHR::default()
                    .std_reference_info(&slot.h264_reference_info);

                let picture_resource_info = vk::VideoPictureResourceInfoKHR::default()
                    .image_view_binding(slot.image_view.image_view())
                    .coded_extent(vk::Extent2D {
                        width: self.width,
                        height: self.height,
                    });

                (slot.slot_index, picture_resource_info, h264_dpb_slot_info)
            })
            .collect();

        let mut reference_slots: Vec<_> = reference_slots_resources
            .iter_mut()
            .map(|(slot_index, picture_resource, h264_dpb_slot)| {
                vk::VideoReferenceSlotInfoKHR::default()
                    .picture_resource(picture_resource)
                    .slot_index(*slot_index as i32)
                    .push_next(h264_dpb_slot)
            })
            .collect();

        reference_slots.push(setup_reference_slot);
        reference_slots.last_mut().unwrap().slot_index = -1;

        log::trace!(
            "\treference slots: {:?}",
            reference_slots
                .iter()
                .map(|slot| slot.slot_index)
                .collect::<Vec<_>>()
        );

        let mut begin_info = vk::VideoBeginCodingInfoKHR::default()
            .video_session(self.video_session.video_session())
            .video_session_parameters(self.video_session_parameters.video_session_parameters())
            .reference_slots(&reference_slots);

        if !self.video_session_is_uninitialized {
            begin_info.p_next = (&raw const self.rate_control.info).cast();
        }

        // Issue the begin video coding command
        let cmd_begin_video_coding = self
            .device
            .video_queue_device()
            .fp()
            .cmd_begin_video_coding_khr;
        (cmd_begin_video_coding)(recording.command_buffer(), &raw const begin_info);

        if self.video_session_needs_control {
            // Update the rate control configs after begin_video_coding, so the rate control passed reflects the current
            // state of the video session.
            self.rate_control.update_from_config(&self.config);

            self.control_video_coding(&mut recording, self.video_session_is_uninitialized);

            self.video_session_is_uninitialized = false;
            self.video_session_needs_control = false;
        }

        let input_picture_resource = vk::VideoPictureResourceInfoKHR::default()
            .image_view_binding(encode_slot.input_image_view.image_view())
            .coded_offset(vk::Offset2D { x: 0, y: 0 })
            .coded_extent(vk::Extent2D {
                width: self.width,
                height: self.height,
            })
            .base_array_layer(0);

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

        let mut ref_lists = zeroed::<vk::native::StdVideoEncodeH264ReferenceListsInfo>();

        let mut l0_iter = l0_references
            .iter()
            .map(|dpb_slot| dpb_slot.slot_index as u8);
        ref_lists
            .RefPicList0
            .fill_with(|| l0_iter.next().unwrap_or(0xFF));

        let mut l1_iter = l1_references
            .iter()
            .map(|dpb_slot| dpb_slot.slot_index as u8);
        ref_lists
            .RefPicList1
            .fill_with(|| l1_iter.next().unwrap_or(0xFF));

        ref_lists.num_ref_idx_l0_active_minus1 = l0_references.len().saturating_sub(1) as u8;
        ref_lists.num_ref_idx_l1_active_minus1 = l1_references.len().saturating_sub(1) as u8;

        log::trace!("\tRefPicList0: {}", debug_list(&ref_lists.RefPicList0));
        log::trace!("\tRefPicList1: {}", debug_list(&ref_lists.RefPicList1));

        let h264_picture_info = vk::native::StdVideoEncodeH264PictureInfo {
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

        let mut h264_encode_info = vk::VideoEncodeH264PictureInfoKHR::default()
            .generate_prefix_nalu(false)
            .nalu_slice_entries(&nalu_slices)
            .std_picture_info(&h264_picture_info);

        // Do not include the setup reference in the vk::VideoEncodeInfoKHR::reference_slots
        reference_slots.truncate(reference_slots.len() - 1);

        let encode_info = vk::VideoEncodeInfoKHR::default()
            .src_picture_resource(input_picture_resource)
            .dst_buffer(encode_slot.output_buffer.buffer())
            .dst_buffer_range(self.output_buffer_size) // TODO: actually use the value here of the buffer
            .reference_slots(&reference_slots)
            .flags(vk::VideoEncodeFlagsKHR::empty())
            .setup_reference_slot(&setup_reference_slot)
            .push_next(&mut h264_encode_info);

        self.video_feedback_query_pool
            .cmd_begin_query(recording.command_buffer(), encode_slot.index);

        let cmd_encode_video = self
            .device
            .video_encode_queue_device()
            .fp()
            .cmd_encode_video_khr;
        (cmd_encode_video)(recording.command_buffer(), &raw const encode_info);

        self.video_feedback_query_pool
            .cmd_end_query(recording.command_buffer(), encode_slot.index);

        let end_video_coding_info = vk::VideoEndCodingInfoKHR::default();
        let cmd_end_video_coding = self
            .device
            .video_queue_device()
            .fp()
            .cmd_end_video_coding_khr;
        cmd_end_video_coding(recording.command_buffer(), &raw const end_video_coding_info);

        // Finish up everything
        recording.end().unwrap();

        let command_buffer_infos = [vk::CommandBufferSubmitInfo::default()
            .command_buffer(encode_slot.encode_command_buffer.command_buffer())];
        let wait_semaphore_infos = [vk::SemaphoreSubmitInfo::default()
            .semaphore(encode_slot.transfer_semaphore.semaphore())
            .stage_mask(vk::PipelineStageFlags2::VIDEO_ENCODE_KHR)];
        let submit_info = vk::SubmitInfo2::default()
            .command_buffer_infos(&command_buffer_infos)
            .wait_semaphore_infos(&wait_semaphore_infos);

        self.device
            .device()
            .queue_submit2(
                self.encode_queue,
                &[submit_info],
                encode_slot.completion_fence.fence(),
            )
            .unwrap();
    }

    unsafe fn control_video_coding(
        &self,
        command_buffer: &mut RecordingCommandBuffer<'_>,
        reset: bool,
    ) {
        let maybe_reset_flag = if reset {
            vk::VideoCodingControlFlagsKHR::RESET
        } else {
            vk::VideoCodingControlFlagsKHR::empty()
        };

        let mut video_coding_control_info = vk::VideoCodingControlInfoKHR::default()
            .flags(vk::VideoCodingControlFlagsKHR::ENCODE_RATE_CONTROL | maybe_reset_flag);

        video_coding_control_info.p_next = (&raw const self.rate_control.info).cast();

        let cmd_control_video_coding = self
            .device
            .video_queue_device()
            .fp()
            .cmd_control_video_coding_khr;

        (cmd_control_video_coding)(
            command_buffer.command_buffer(),
            &raw const video_coding_control_info,
        );
    }
}

fn debug_list(list: &[u8]) -> String {
    format!(
        "{:?}",
        list.iter().take_while(|x| **x != 0xFF).collect::<Vec<_>>()
    )
}

fn buffer_image_copy(
    aspect_mask: vk::ImageAspectFlags,
    width: u32,
    height: u32,
    offset: u64,
) -> vk::BufferImageCopy {
    let image_subresource = vk::ImageSubresourceLayers {
        aspect_mask,
        mip_level: 0,
        base_array_layer: 0,
        layer_count: 1,
    };

    vk::BufferImageCopy::default()
        .buffer_offset(offset)
        .buffer_row_length(0)
        .buffer_image_height(0)
        .image_subresource(image_subresource)
        .image_offset(vk::Offset3D { x: 0, y: 0, z: 0 })
        .image_extent(vk::Extent3D {
            width,
            height,
            depth: 1,
        })
}

fn create_input_image(
    device: &Device,
    video_profile_info: vk::VideoProfileInfoKHR<'_>,
    width: u32,
    height: u32,
) -> Result<Image, VulkanError> {
    let profiles = [video_profile_info];
    let mut video_profile_list_info = vk::VideoProfileListInfoKHR::default().profiles(&profiles);
    let create_info = vk::ImageCreateInfo::default()
        .image_type(vk::ImageType::TYPE_2D)
        .format(vk::Format::G8_B8R8_2PLANE_420_UNORM)
        .extent(vk::Extent3D {
            width,
            height,
            depth: 1,
        })
        .mip_levels(1)
        .array_layers(1)
        .tiling(vk::ImageTiling::OPTIMAL)
        .sharing_mode(vk::SharingMode::EXCLUSIVE)
        .initial_layout(vk::ImageLayout::UNDEFINED)
        .samples(vk::SampleCountFlags::TYPE_1)
        .usage(vk::ImageUsageFlags::VIDEO_ENCODE_SRC_KHR | vk::ImageUsageFlags::TRANSFER_DST)
        .push_next(&mut video_profile_list_info);

    unsafe { Image::create(device, &create_info) }
}

#[allow(clippy::too_many_arguments)]
fn create_video_session_parameters(
    video_session: &VideoSession,
    width: u32,
    height: u32,
    max_num_ref_frames: u8,
    profile_idc: vk::native::StdVideoH264ProfileIdc,
    level_idc: vk::native::StdVideoH264LevelIdc,
    chrome_format_idc: vk::native::StdVideoH264ChromaFormatIdc,
) -> Result<VideoSessionParameters, VulkanError> {
    let (width_mbaligned, height_mbaligned) = (macro_block_align(width), macro_block_align(height));

    let mut seq_params: vk::native::StdVideoH264SequenceParameterSet = unsafe { zeroed() };
    seq_params.profile_idc = profile_idc;
    seq_params.level_idc = level_idc;
    seq_params.chroma_format_idc = chrome_format_idc;

    seq_params.log2_max_frame_num_minus4 = 16 - 4;
    seq_params.log2_max_pic_order_cnt_lsb_minus4 = 16 - 4;
    seq_params.max_num_ref_frames = max_num_ref_frames;
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

    let video_session_parameters_create_info = vk::VideoSessionParametersCreateInfoKHR::default()
        .video_session(unsafe { video_session.video_session() })
        .push_next(&mut video_encode_h264_session_parameters_create_info);

    unsafe { VideoSessionParameters::create(video_session, &video_session_parameters_create_info) }
}

fn map_profile(
    profile: Profile,
) -> Option<(
    vk::native::StdVideoH264ProfileIdc,
    vk::VideoChromaSubsamplingFlagsKHR,
)> {
    match profile {
        Profile::Baseline => Some((
            vk::native::StdVideoH264ProfileIdc_STD_VIDEO_H264_PROFILE_IDC_BASELINE,
            vk::VideoChromaSubsamplingFlagsKHR::TYPE_420,
        )),
        Profile::ConstrainedBaseline => None,
        Profile::Main => Some((
            vk::native::StdVideoH264ProfileIdc_STD_VIDEO_H264_PROFILE_IDC_MAIN,
            vk::VideoChromaSubsamplingFlagsKHR::TYPE_420,
        )),
        Profile::Extended => None,
        Profile::High => Some((
            vk::native::StdVideoH264ProfileIdc_STD_VIDEO_H264_PROFILE_IDC_HIGH,
            vk::VideoChromaSubsamplingFlagsKHR::TYPE_420,
        )),
        Profile::High10 => None,
        Profile::High422 => None,
        Profile::High444Predictive => Some((
            vk::native::StdVideoH264ProfileIdc_STD_VIDEO_H264_PROFILE_IDC_HIGH_444_PREDICTIVE,
            vk::VideoChromaSubsamplingFlagsKHR::TYPE_444,
        )),
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
