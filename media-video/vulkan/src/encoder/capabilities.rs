use crate::{
    Buffer, CommandBuffer, Device, Fence, PhysicalDevice, Semaphore, VideoFeedbackQueryPool,
    VideoSession, VideoSessionParameters, VulkanError, create_dpb,
    encoder::{
        DpbSlot, Input, RateControlInfos, VulkanEncodeSlot, VulkanEncodeSlotSeparateQueueData,
        VulkanEncoder, VulkanEncoderImplConfig, VulkanEncoderSeparateQueueData,
        codec::VulkanEncCodec,
    },
    image::ImageMemoryBarrier,
};
use ash::vk;
use std::{collections::VecDeque, mem::zeroed, pin::Pin, time::Instant};

#[derive(Debug, thiserror::Error)]
pub enum VulkanEncoderCapabilitiesError {
    #[error("Failed to find a transfer | compute | graphics queue")]
    FailedToFindMainQueue,
    #[error("Failed to find a encode queue")]
    FailedToFindEncodeQueue,
    #[error(transparent)]
    VideoCapabilities(VulkanError),
}

#[derive(Debug)]
pub struct VulkanEncoderCapabilities<C: VulkanEncCodec> {
    pub physical_device: PhysicalDevice,

    pub video_codec_profile_info: C::ProfileInfo<'static>,
    pub video_profile_info: vk::VideoProfileInfoKHR<'static>,

    pub video_capabilities: vk::VideoCapabilitiesKHR<'static>,
    pub video_encode_capabilities: vk::VideoEncodeCapabilitiesKHR<'static>,
    pub video_encode_codec_capabilities: C::Capabilities<'static>,
}

impl<C: VulkanEncCodec> VulkanEncoderCapabilities<C> {
    pub fn new(
        physical_device: &PhysicalDevice,
        mut codec_profile_info: C::ProfileInfo<'static>,
    ) -> Result<VulkanEncoderCapabilities<C>, VulkanEncoderCapabilitiesError> {
        let video_profile_info = vk::VideoProfileInfoKHR::default()
            .video_codec_operation(C::ENCODE_OPERATION)
            .chroma_bit_depth(vk::VideoComponentBitDepthFlagsKHR::TYPE_8)
            .luma_bit_depth(vk::VideoComponentBitDepthFlagsKHR::TYPE_8)
            .chroma_subsampling(vk::VideoChromaSubsamplingFlagsKHR::TYPE_420);

        let (video_capabilities, video_encode_capabilities, video_encode_codec_capabilities) =
            physical_device
                .video_capabilities::<C::Capabilities<'static>>(
                    video_profile_info.push_next(&mut codec_profile_info),
                )
                .map_err(|e| VulkanEncoderCapabilitiesError::VideoCapabilities(e.into()))?;

        Ok(VulkanEncoderCapabilities {
            physical_device: physical_device.clone(),
            video_codec_profile_info: codec_profile_info,
            video_profile_info,
            video_capabilities,
            video_encode_capabilities,
            video_encode_codec_capabilities,
        })
    }

    pub fn create_encoder(
        &self,
        device: &Device,
        config: VulkanEncoderImplConfig,
        parameters: &mut C::ParametersCreateInfo<'_>,
        rate_control: Option<Pin<Box<RateControlInfos<C>>>>,
    ) -> Result<VulkanEncoder<C>, VulkanError> {
        let graphics_queue_family_index = device.graphics_queue_family_index();
        let encode_queue_family_index = device.encode_queue_family_index();

        let graphics_queue = device.graphics_queue();
        let encode_queue = device.encode_queue();

        let mut video_encode_usage_info = vk::VideoEncodeUsageInfoKHR::default()
            .video_usage_hints(config.user.usage_hints)
            .video_content_hints(config.user.content_hints)
            .tuning_mode(config.user.tuning_mode);

        let mut video_codec_profile_info = self.video_codec_profile_info;
        let video_profile_info = self
            .video_profile_info
            .push_next(&mut video_codec_profile_info)
            .push_next(&mut video_encode_usage_info);

        // Create video session
        let create_info = vk::VideoSessionCreateInfoKHR::default()
            .max_coded_extent(config.user.max_encode_resolution)
            .queue_family_index(encode_queue_family_index)
            .max_active_reference_pictures(config.max_active_references)
            .max_dpb_slots(config.num_dpb_slots)
            .picture_format(vk::Format::G8_B8R8_2PLANE_420_UNORM)
            .reference_picture_format(vk::Format::G8_B8R8_2PLANE_420_UNORM)
            .video_profile(&video_profile_info)
            .std_header_version(&self.video_capabilities.std_header_version);

        let video_session = unsafe { VideoSession::create(device, &create_info)? };

        // Create video session parameters
        let video_session_parameters = VideoSessionParameters::create(&video_session, parameters)?;

        // Create command buffers
        let mut command_buffers =
            CommandBuffer::create(device, graphics_queue_family_index, config.num_encode_slots)?;

        let mut separate_encode_command_buffers =
            if graphics_queue_family_index == encode_queue_family_index {
                None
            } else {
                Some(CommandBuffer::create(
                    device,
                    encode_queue_family_index,
                    config.num_encode_slots,
                )?)
            };

        let mut inputs = Input::create(
            device,
            video_profile_info,
            config.user.input_as_vulkan_image,
            config.user.input_pixel_format,
            config.user.max_input_resolution,
            config.user.max_encode_resolution,
            config.num_encode_slots,
        )?;

        let output_buffer_size: u64 = (config.user.max_encode_resolution.width as u64
            * config.user.max_encode_resolution.height as u64)
            .next_multiple_of(self.video_capabilities.min_bitstream_buffer_size_alignment);
        let mut encode_slots = vec![];

        for index in 0..config.num_encode_slots {
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

                unsafe { Buffer::create(device, &create_info)? }
            };

            let separate_queue_data = match &mut separate_encode_command_buffers {
                Some(separate_encode_command_buffers) => {
                    let command_buffer = separate_encode_command_buffers.pop().unwrap();
                    let semaphore = Semaphore::create(device)?;

                    Some(VulkanEncodeSlotSeparateQueueData {
                        semaphore,
                        command_buffer,
                    })
                }
                None => None,
            };

            let completion_fence = Fence::create(device)?;

            encode_slots.push(VulkanEncodeSlot {
                index,
                emit_parameters: false,
                // Fake placeholder value
                submitted_at: Instant::now(),
                input: inputs.pop().unwrap(),
                output_buffer,
                command_buffer: command_buffers.pop().unwrap(),
                separate_queue_data,
                completion_fence,
            });
        }

        let dpb_views = create_dpb(
            device,
            video_profile_info,
            config.num_dpb_slots,
            config.user.max_encode_resolution,
            vk::ImageUsageFlags::VIDEO_ENCODE_DPB_KHR,
            self.video_capabilities
                .flags
                .contains(vk::VideoCapabilityFlagsKHR::SEPARATE_REFERENCE_IMAGES),
        )?;

        let dpb_slots: Vec<DpbSlot<C>> = dpb_views
            .into_iter()
            .map(|image_view| DpbSlot {
                image_view,
                std_reference_info: unsafe { zeroed() },
            })
            .collect();

        let encode_slot = &mut encode_slots[0];

        // Prepare layouts
        unsafe {
            let fence = Fence::create(device)?;

            let command_buffer = match &mut encode_slot.separate_queue_data {
                Some(separate_queue_data) => &mut separate_queue_data.command_buffer,
                None => &mut encode_slot.command_buffer,
            };

            let recording = command_buffer.begin(&vk::CommandBufferBeginInfo::default())?;

            // Transition all dpb slots to the correct layout
            for dpb_slot in &dpb_slots {
                dpb_slot.image_view.image().cmd_memory_barrier(
                    &recording,
                    ImageMemoryBarrier::dst(
                        vk::ImageLayout::VIDEO_ENCODE_DPB_KHR,
                        vk::PipelineStageFlags2::VIDEO_ENCODE_KHR,
                        vk::AccessFlags2::VIDEO_ENCODE_WRITE_KHR,
                    ),
                    dpb_slot.image_view.subresource_range().base_array_layer,
                );
            }

            recording.end()?;

            let command_buffers = [command_buffer.handle()];
            let submit_info = vk::SubmitInfo::default().command_buffers(&command_buffers);

            device
                .ash()
                .queue_submit(encode_queue, &[submit_info], fence.handle())?;

            fence.wait(u64::MAX)?;
        };

        let video_feedback_query_pool =
            VideoFeedbackQueryPool::create(device, config.num_encode_slots, video_profile_info)?;

        let separate_queue_data = if graphics_queue_family_index == encode_queue_family_index {
            None
        } else {
            Some(VulkanEncoderSeparateQueueData {
                encode_queue_family_index,
                encode_queue,
            })
        };

        Ok(VulkanEncoder {
            max_input_extent: config.user.max_input_resolution,
            max_encode_extent: config.user.max_encode_resolution,
            current_encode_extent: config.user.initial_encode_resolution,
            output_buffer_size,
            video_session,
            video_session_parameters,
            video_session_is_uninitialized: true,
            video_feedback_query_pool,
            graphics_queue_family_index,
            graphics_queue,
            separate_queue_data,
            current_rc: None,
            next_rc: rate_control,
            encode_slots,
            in_flight: VecDeque::new(),
            dpb_slots,
            output: VecDeque::new(),
        })
    }
}
