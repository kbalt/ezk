use crate::{
    Buffer, CommandBuffer, Device, Fence, Image, ImageView, PhysicalDevice, RecordingCommandBuffer,
    Semaphore, VideoFeedbackQueryPool, VideoSession, VideoSessionParameters, VulkanError,
    create_dpb,
};
use ash::vk::{self, Handle};
use ezk_image::{ColorInfo, ColorSpace, ImageRef, PixelFormat, YuvColorInfo, convert_multi_thread};
use std::{collections::VecDeque, ffi::CStr, mem::zeroed};

const PARALLEL_ENCODINGS: u32 = 16;

pub trait VulkanEncCodec {
    const ENCODE_OPERATION: vk::VideoCodecOperationFlagsKHR;
    const EXTENSION: &'static CStr;
    type ProfileInfo<'a>: vk::ExtendsVideoProfileInfoKHR;
    type Capabilities<'a>: vk::ExtendsVideoCapabilitiesKHR + Default;
    type ParametersCreateInfo<'a>: vk::ExtendsVideoSessionParametersCreateInfoKHR;
    type ParametersAddInfo<'a>: vk::ExtendsVideoSessionParametersUpdateInfoKHR;

    type StdReferenceInfo;
    type DpbSlotInfo<'a>: vk::ExtendsVideoReferenceSlotInfoKHR;

    fn slot_info_from_std(std_reference_info: &Self::StdReferenceInfo) -> Self::DpbSlotInfo<'_>;

    type PictureInfo<'a>: vk::ExtendsVideoEncodeInfoKHR;

    type RateControlInfo<'a>: vk::ExtendsVideoBeginCodingInfoKHR
        + vk::ExtendsVideoCodingControlInfoKHR;
    type RateControlLayerInfo<'a>: vk::ExtendsVideoEncodeRateControlLayerInfoKHR;

    fn get_encoded_video_session_parameters(
        video_session_parameters: &VideoSessionParameters,
    ) -> Vec<u8>;
}

pub struct H264;

impl VulkanEncCodec for H264 {
    const ENCODE_OPERATION: vk::VideoCodecOperationFlagsKHR =
        vk::VideoCodecOperationFlagsKHR::ENCODE_H264;
    const EXTENSION: &'static CStr = ash::khr::video_encode_h264::NAME;
    type ProfileInfo<'a> = vk::VideoEncodeH264ProfileInfoKHR<'a>;
    type Capabilities<'a> = vk::VideoEncodeH264CapabilitiesKHR<'a>;
    type ParametersCreateInfo<'a> = vk::VideoEncodeH264SessionParametersCreateInfoKHR<'a>;
    type ParametersAddInfo<'a> = vk::VideoEncodeH264SessionParametersAddInfoKHR<'a>;

    type StdReferenceInfo = vk::native::StdVideoEncodeH264ReferenceInfo;
    type DpbSlotInfo<'a> = vk::VideoEncodeH264DpbSlotInfoKHR<'a>;

    fn slot_info_from_std(std_reference_info: &Self::StdReferenceInfo) -> Self::DpbSlotInfo<'_> {
        vk::VideoEncodeH264DpbSlotInfoKHR::default().std_reference_info(std_reference_info)
    }

    type PictureInfo<'a> = vk::VideoEncodeH264PictureInfoKHR<'a>;

    type RateControlInfo<'a> = vk::VideoEncodeH264RateControlInfoKHR<'a>;
    type RateControlLayerInfo<'a> = vk::VideoEncodeH264RateControlLayerInfoKHR<'a>;

    fn get_encoded_video_session_parameters(
        video_session_parameters: &VideoSessionParameters,
    ) -> Vec<u8> {
        let mut info = vk::VideoEncodeH264SessionParametersGetInfoKHR::default()
            .write_std_sps(true)
            .write_std_pps(true);

        unsafe {
            video_session_parameters
                .get_encoded_video_session_parameters(&mut info)
                .unwrap()
        }
    }
}

pub struct H265;

impl VulkanEncCodec for H265 {
    const ENCODE_OPERATION: vk::VideoCodecOperationFlagsKHR =
        vk::VideoCodecOperationFlagsKHR::ENCODE_H265;
    const EXTENSION: &'static CStr = ash::khr::video_encode_h265::NAME;
    type ProfileInfo<'a> = vk::VideoEncodeH265ProfileInfoKHR<'a>;
    type Capabilities<'a> = vk::VideoEncodeH265CapabilitiesKHR<'a>;
    type ParametersCreateInfo<'a> = vk::VideoEncodeH265SessionParametersCreateInfoKHR<'a>;
    type ParametersAddInfo<'a> = vk::VideoEncodeH265SessionParametersAddInfoKHR<'a>;
    type DpbSlotInfo<'a> = vk::VideoEncodeH265DpbSlotInfoKHR<'a>;

    type StdReferenceInfo = vk::native::StdVideoEncodeH265ReferenceInfo;

    fn slot_info_from_std(std_reference_info: &Self::StdReferenceInfo) -> Self::DpbSlotInfo<'_> {
        vk::VideoEncodeH265DpbSlotInfoKHR::default().std_reference_info(std_reference_info)
    }

    type PictureInfo<'a> = vk::VideoEncodeH265PictureInfoKHR<'a>;

    type RateControlInfo<'a> = vk::VideoEncodeH265RateControlInfoKHR<'a>;
    type RateControlLayerInfo<'a> = vk::VideoEncodeH265RateControlLayerInfoKHR<'a>;

    fn get_encoded_video_session_parameters(
        video_session_parameters: &VideoSessionParameters,
    ) -> Vec<u8> {
        let mut info = vk::VideoEncodeH265SessionParametersGetInfoKHR::default()
            .write_std_sps(true)
            .write_std_pps(true)
            .write_std_vps(true);

        unsafe {
            video_session_parameters
                .get_encoded_video_session_parameters(&mut info)
                .unwrap()
        }
    }
}

pub struct VulkanEncoderCapabilities<'a, C: VulkanEncCodec> {
    pub physical_device: &'a PhysicalDevice,

    pub video_profile_info: vk::VideoProfileInfoKHR<'a>,
    pub video_capabilities: vk::VideoCapabilitiesKHR<'a>,
    pub video_encode_capabilities: vk::VideoEncodeCapabilitiesKHR<'a>,
    pub video_encode_codec_capabilities: C::Capabilities<'a>,

    pub transfer_queue_family_index: u32,
    pub encode_queue_family_index: u32,
}

impl<'a, C: VulkanEncCodec + 'a> VulkanEncoderCapabilities<'a, C> {
    pub fn new(
        physical_device: &'a PhysicalDevice,
        codec_profile_info: &'a mut C::ProfileInfo<'a>,
    ) -> VulkanEncoderCapabilities<'a, C> {
        let queue_family_properties = physical_device.queue_family_properties();

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

        let video_profile_info = vk::VideoProfileInfoKHR::default()
            .video_codec_operation(C::ENCODE_OPERATION)
            .chroma_bit_depth(vk::VideoComponentBitDepthFlagsKHR::TYPE_8)
            .luma_bit_depth(vk::VideoComponentBitDepthFlagsKHR::TYPE_8)
            .chroma_subsampling(vk::VideoChromaSubsamplingFlagsKHR::TYPE_420)
            .push_next(codec_profile_info);

        let (video_capabilities, video_encode_capabilities, video_encode_codec_capabilities) =
            physical_device
                .video_capabilities::<C::Capabilities<'a>>(video_profile_info)
                .unwrap();

        VulkanEncoderCapabilities {
            physical_device,
            video_profile_info,
            video_capabilities,
            video_encode_capabilities,
            video_encode_codec_capabilities,
            transfer_queue_family_index,
            encode_queue_family_index,
        }
    }

    pub fn create_encoder(
        self,
        parameters: &mut C::ParametersCreateInfo<'a>,
        max_coded_extent: vk::Extent2D,
        max_active_ref_images: u32,
        max_dpb_slots: u32,
    ) -> VulkanEncoder<C> {
        // Create the device
        let extensions = [
            ash::khr::video_queue::NAME.as_ptr(),
            ash::khr::video_encode_queue::NAME.as_ptr(),
            C::EXTENSION.as_ptr(),
        ];

        let mut synchronization2_features =
            vk::PhysicalDeviceSynchronization2Features::default().synchronization2(true);

        let queue_create_flags = [
            vk::DeviceQueueCreateInfo::default()
                .queue_family_index(self.transfer_queue_family_index)
                .queue_priorities(&[1.0]),
            vk::DeviceQueueCreateInfo::default()
                .queue_family_index(self.encode_queue_family_index)
                .queue_priorities(&[1.0]),
        ];

        let create_device_info = vk::DeviceCreateInfo::default()
            .enabled_extension_names(&extensions)
            .queue_create_infos(&queue_create_flags)
            .push_next(&mut synchronization2_features);

        let device = unsafe {
            Device::create(
                self.physical_device.instance(),
                self.physical_device.physical_device(),
                &create_device_info,
            )
            .unwrap()
        };

        let (transfer_queue, encode_queue) = unsafe {
            let transfer_queue = device
                .device()
                .get_device_queue(self.transfer_queue_family_index, 0);
            let encode_queue = device
                .device()
                .get_device_queue(self.encode_queue_family_index, 0);

            assert!(!transfer_queue.is_null());
            assert!(!encode_queue.is_null());

            (transfer_queue, encode_queue)
        };

        // Create video sessionu
        let create_info = vk::VideoSessionCreateInfoKHR::default()
            .max_coded_extent(max_coded_extent)
            .queue_family_index(self.encode_queue_family_index)
            .max_active_reference_pictures(max_active_ref_images)
            .max_dpb_slots(max_dpb_slots)
            .picture_format(vk::Format::G8_B8R8_2PLANE_420_UNORM)
            .reference_picture_format(vk::Format::G8_B8R8_2PLANE_420_UNORM)
            .video_profile(&self.video_profile_info)
            .std_header_version(&self.video_capabilities.std_header_version);

        let video_session = unsafe { VideoSession::create(&device, &create_info).unwrap() };

        // Create video session parameters
        let video_session_parameters_create_info =
            vk::VideoSessionParametersCreateInfoKHR::default()
                .video_session(unsafe { video_session.video_session() })
                .push_next(parameters);

        let video_session_parameters = unsafe {
            VideoSessionParameters::create(&video_session, &video_session_parameters_create_info)
                .unwrap()
        };

        // Create command buffers
        let mut transfer_command_buffers = unsafe {
            CommandBuffer::create(
                &device,
                self.transfer_queue_family_index,
                PARALLEL_ENCODINGS,
            )
            .unwrap()
        };

        let mut encode_command_buffers = unsafe {
            CommandBuffer::create(&device, self.encode_queue_family_index, PARALLEL_ENCODINGS)
                .unwrap()
        };

        let output_buffer_size: u64 =
            (max_coded_extent.width as u64 * max_coded_extent.height as u64 * 3) / 2;
        let mut encode_slots = vec![];

        for index in 0..PARALLEL_ENCODINGS {
            let input_image =
                create_input_image(&device, self.video_profile_info, max_coded_extent).unwrap();

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

                unsafe { ImageView::create(&input_image, &create_info).unwrap() }
            };

            let input_staging_buffer = {
                // TODO: don't hardcode this to NV12
                let size =
                    (max_coded_extent.width as u64 * max_coded_extent.height as u64 * 12) / 8;

                let create_info = vk::BufferCreateInfo::default()
                    .size(size)
                    .usage(vk::BufferUsageFlags::TRANSFER_SRC)
                    .sharing_mode(vk::SharingMode::EXCLUSIVE);

                unsafe { Buffer::create(&device, &create_info).unwrap() }
            };

            let output_buffer = {
                let profiles = [self.video_profile_info];
                let mut video_profile_list_info =
                    vk::VideoProfileListInfoKHR::default().profiles(&profiles);

                let create_info = vk::BufferCreateInfo::default()
                    .size(output_buffer_size)
                    .usage(
                        vk::BufferUsageFlags::VIDEO_ENCODE_DST_KHR
                            | vk::BufferUsageFlags::TRANSFER_SRC,
                    )
                    .push_next(&mut video_profile_list_info);

                unsafe { Buffer::create(&device, &create_info).unwrap() }
            };

            let transfer_semaphore = Semaphore::create(&device).unwrap();
            let completion_fence = Fence::create(&device).unwrap();

            encode_slots.push(VulkanEncodeSlot {
                index,
                emit_parameters: false,
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

        let dpb_views = create_dpb(
            &device,
            self.video_profile_info,
            max_dpb_slots,
            max_coded_extent,
            vk::ImageUsageFlags::VIDEO_ENCODE_DPB_KHR,
        )
        .unwrap();

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
            let fence = Fence::create(&device).unwrap();

            let recording = encode_slot
                .encode_command_buffer
                .begin(&vk::CommandBufferBeginInfo::default())
                .unwrap();

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

            recording.end().unwrap();

            let command_buffers = [encode_slot.encode_command_buffer.command_buffer()];
            let submit_info = vk::SubmitInfo::default().command_buffers(&command_buffers);

            device
                .device()
                .queue_submit(encode_queue, &[submit_info], fence.fence())
                .unwrap();

            fence.wait(u64::MAX).unwrap();
        };

        let video_feedback_query_pool =
            VideoFeedbackQueryPool::create(&device, PARALLEL_ENCODINGS, self.video_profile_info)
                .unwrap();

        VulkanEncoder {
            max_coded_extent,
            output_buffer_size,
            video_session,
            video_session_parameters,
            video_session_needs_control: true,
            video_session_is_uninitialized: true,
            transfer_queue_family_index: self.transfer_queue_family_index,
            encode_queue_family_index: self.encode_queue_family_index,
            transfer_queue,
            encode_queue,
            video_feedback_query_pool,
            encode_slots,
            in_flight: VecDeque::new(),
            dpb_slots,
            output: VecDeque::new(),
        }
    }
}

fn create_input_image(
    device: &Device,
    video_profile_info: vk::VideoProfileInfoKHR<'_>,
    extent: vk::Extent2D,
) -> Result<Image, VulkanError> {
    let profiles = [video_profile_info];
    let mut video_profile_list_info = vk::VideoProfileListInfoKHR::default().profiles(&profiles);
    let create_info = vk::ImageCreateInfo::default()
        .image_type(vk::ImageType::TYPE_2D)
        .format(vk::Format::G8_B8R8_2PLANE_420_UNORM)
        .extent(vk::Extent3D {
            width: extent.width,
            height: extent.height,
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

pub struct VulkanEncoder<C: VulkanEncCodec> {
    max_coded_extent: vk::Extent2D,
    output_buffer_size: u64,

    video_session: VideoSession,
    video_session_parameters: VideoSessionParameters,
    video_session_needs_control: bool,
    video_session_is_uninitialized: bool,

    transfer_queue_family_index: u32,
    encode_queue_family_index: u32,

    transfer_queue: vk::Queue,
    encode_queue: vk::Queue,

    video_feedback_query_pool: VideoFeedbackQueryPool,

    encode_slots: Vec<VulkanEncodeSlot>,
    in_flight: VecDeque<VulkanEncodeSlot>,

    dpb_slots: Vec<DpbSlot<C>>,

    output: VecDeque<Vec<u8>>,
}

pub struct VulkanEncodeSlot {
    /// Index used for the video feedback query pool
    index: u32,

    emit_parameters: bool,

    input_staging_buffer: Buffer,

    input_image: Image,
    input_image_view: ImageView,

    output_buffer: Buffer,

    transfer_semaphore: Semaphore,

    transfer_command_buffer: CommandBuffer,
    encode_command_buffer: CommandBuffer,

    completion_fence: Fence,
}

struct DpbSlot<C: VulkanEncCodec> {
    image_view: ImageView,
    std_reference_info: C::StdReferenceInfo,
}

impl<C: VulkanEncCodec> VulkanEncoder<C> {
    fn wait_encode_slot(&mut self, encode_slot: &mut VulkanEncodeSlot) {
        assert!(encode_slot.completion_fence.wait(u64::MAX).unwrap());
        encode_slot.completion_fence.reset().unwrap();
    }

    fn read_out_encode_slot(&mut self, encode_slot: &mut VulkanEncodeSlot) {
        if encode_slot.emit_parameters {
            let parameters =
                C::get_encoded_video_session_parameters(&self.video_session_parameters);

            self.output.push_back(parameters);
        }

        unsafe {
            let bytes_written = self
                .video_feedback_query_pool
                .get_bytes_written(encode_slot.index)
                .unwrap();

            let mapped_buffer = encode_slot.output_buffer.map(bytes_written.into()).unwrap();

            self.output.push_back(mapped_buffer.data().to_vec());
        }
    }

    pub fn pop_encode_slot(&mut self) -> Option<VulkanEncodeSlot> {
        if let Some(encode_slot) = self.encode_slots.pop() {
            return Some(encode_slot);
        }

        let mut encode_slot = self.in_flight.pop_front()?;

        self.wait_encode_slot(&mut encode_slot);
        self.read_out_encode_slot(&mut encode_slot);

        Some(encode_slot)
    }

    pub fn poll_result(&mut self) -> Option<Vec<u8>> {
        if let Some(output) = self.output.pop_front() {
            return Some(output);
        }

        if let Some(encode_slot) = self.in_flight.front_mut() {
            let completed = encode_slot.completion_fence.wait(0).unwrap();
            if !completed {
                return None;
            }

            encode_slot.completion_fence.reset().unwrap();

            let mut encode_slot = self.in_flight.pop_front().unwrap();
            self.read_out_encode_slot(&mut encode_slot);
            self.encode_slots.push(encode_slot);
        }

        self.output.pop_front()
    }

    pub fn wait_result(&mut self) -> Option<Vec<u8>> {
        if let Some(output) = self.output.pop_front() {
            return Some(output);
        }

        if let Some(mut encode_slot) = self.in_flight.pop_front() {
            self.wait_encode_slot(&mut encode_slot);
            self.read_out_encode_slot(&mut encode_slot);
            self.encode_slots.push(encode_slot);
        }

        self.output.pop_front()
    }

    pub fn upload_image_to_encode_slot(
        &mut self,
        encode_slot: &mut VulkanEncodeSlot,
        image: &dyn ImageRef,
    ) {
        unsafe {
            let width = self.max_coded_extent.width;
            let height = self.max_coded_extent.height;

            let mapped_buffer = encode_slot
                .input_staging_buffer
                .map((width as u64 * height as u64 * 12) / 8)
                .unwrap();

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
                width as usize,
                height as usize,
                dst_color.into(),
            )
            .unwrap();

            convert_multi_thread(image, &mut dst).unwrap();
        }
    }

    pub fn submit_encode_slot(
        &mut self,
        mut encode_slot: VulkanEncodeSlot,
        references: Vec<usize>,
        setup_reference: usize,
        setup_std_reference_info: C::StdReferenceInfo,
        picture_info: C::PictureInfo<'_>,
        emit_parameters: bool,
    ) {
        encode_slot.emit_parameters = emit_parameters;

        log::trace!(
            "Submit encode slot: references: {references:?}, setup_reference: {setup_reference}, emit_parameters: {emit_parameters}"
        );

        unsafe {
            self.record_transfer_queue(&mut encode_slot);

            self.record_encode_queue(
                &mut encode_slot,
                references,
                setup_reference,
                setup_std_reference_info,
                picture_info,
            );

            self.in_flight.push_back(encode_slot);
        }
    }

    unsafe fn record_transfer_queue(&mut self, encode_slot: &mut VulkanEncodeSlot) {
        let device = self.video_session.device();

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
        let buffer_image_copy_plane0 = buffer_image_copy(
            vk::ImageAspectFlags::PLANE_0,
            self.max_coded_extent.width,
            self.max_coded_extent.height,
            0,
        );
        let buffer_image_copy_plane1 = buffer_image_copy(
            vk::ImageAspectFlags::PLANE_1,
            self.max_coded_extent.width / 2,
            self.max_coded_extent.height / 2,
            self.max_coded_extent.width as u64 * self.max_coded_extent.height as u64,
        );

        device.device().cmd_copy_buffer_to_image(
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

        device
            .device()
            .queue_submit(self.transfer_queue, &[submit_info], vk::Fence::null())
            .unwrap();
        device.device().device_wait_idle().unwrap();
    }

    unsafe fn record_encode_queue(
        &mut self,
        encode_slot: &mut VulkanEncodeSlot,
        reference_indices: Vec<usize>,
        setup_reference_index: usize,
        setup_std_reference_info: C::StdReferenceInfo,
        mut picture_info: C::PictureInfo<'_>,
    ) {
        let device = self.video_session.device();

        // Begin recording the encode queue
        let recording = encode_slot
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
        self.dpb_slots[setup_reference_index].std_reference_info = setup_std_reference_info;
        let setup_reference = &self.dpb_slots[setup_reference_index];

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

        let setup_reference_picture_resource_info = vk::VideoPictureResourceInfoKHR::default()
            .image_view_binding(setup_reference.image_view.image_view())
            .coded_extent(self.max_coded_extent);
        let mut setup_reference_dpb_slot_info =
            C::slot_info_from_std(&setup_reference.std_reference_info);
        let setup_reference_slot_info = vk::VideoReferenceSlotInfoKHR::default()
            .picture_resource(&setup_reference_picture_resource_info)
            .slot_index(setup_reference_index as i32)
            .push_next(&mut setup_reference_dpb_slot_info);

        // Barrier the active reference dpb slots
        for dpb_slot in &reference_indices {
            let dpb_slot = &self.dpb_slots[*dpb_slot];

            dpb_slot.image_view.image().cmd_memory_barrier2(
                recording.command_buffer(),
                vk::ImageLayout::VIDEO_ENCODE_DPB_KHR,
                vk::ImageLayout::VIDEO_ENCODE_DPB_KHR,
                vk::QUEUE_FAMILY_IGNORED,
                vk::QUEUE_FAMILY_IGNORED,
                vk::PipelineStageFlags2::VIDEO_ENCODE_KHR,
                vk::AccessFlags2::VIDEO_ENCODE_READ_KHR | vk::AccessFlags2::VIDEO_ENCODE_WRITE_KHR,
                vk::PipelineStageFlags2::VIDEO_ENCODE_KHR,
                vk::AccessFlags2::VIDEO_ENCODE_READ_KHR,
                dpb_slot.image_view.subresource_range().base_array_layer,
            );
        }

        let mut reference_slots_resources: Vec<_> = reference_indices
            .iter()
            .map(|index| {
                let slot = &self.dpb_slots[*index];

                let dpb_slot_info = C::slot_info_from_std(&slot.std_reference_info);

                let picture_resource_info = vk::VideoPictureResourceInfoKHR::default()
                    .image_view_binding(slot.image_view.image_view())
                    .coded_extent(self.max_coded_extent);

                (*index, picture_resource_info, dpb_slot_info)
            })
            .collect();

        let mut reference_slots: Vec<_> = reference_slots_resources
            .iter_mut()
            .map(|(slot_index, picture_resource, dpb_slot_info)| {
                vk::VideoReferenceSlotInfoKHR::default()
                    .picture_resource(picture_resource)
                    .slot_index(*slot_index as i32)
                    .push_next(dpb_slot_info)
            })
            .collect();

        reference_slots.push(setup_reference_slot_info);
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

        // TODO
        //if !self.video_session_is_uninitialized {
        //    begin_info.p_next = (&raw const self.rate_control.info).cast();
        //}

        // Issue the begin video coding command
        let cmd_begin_video_coding = device.video_queue_device().fp().cmd_begin_video_coding_khr;
        (cmd_begin_video_coding)(recording.command_buffer(), &raw const begin_info);

        if self.video_session_needs_control {
            // Update the rate control configs after begin_video_coding, so the rate control passed reflects the current
            // state of the video session.
            //self.rate_control.update_from_config(&self.config); // TODO

            self.control_video_coding(&recording, self.video_session_is_uninitialized);

            self.video_session_is_uninitialized = false;
            self.video_session_needs_control = false;
        }

        let src_picture_resource_info = vk::VideoPictureResourceInfoKHR::default()
            .image_view_binding(encode_slot.input_image_view.image_view())
            .coded_offset(vk::Offset2D { x: 0, y: 0 })
            .coded_extent(self.max_coded_extent)
            .base_array_layer(0);

        // Do not include the setup reference in the vk::VideoEncodeInfoKHR::reference_slots
        reference_slots.truncate(reference_slots.len() - 1);

        let encode_info = vk::VideoEncodeInfoKHR::default()
            .src_picture_resource(src_picture_resource_info)
            .dst_buffer(encode_slot.output_buffer.buffer())
            .dst_buffer_range(self.output_buffer_size) // TODO: actually use the value here of the buffer
            .reference_slots(&reference_slots)
            .flags(vk::VideoEncodeFlagsKHR::empty())
            .setup_reference_slot(&setup_reference_slot_info)
            .push_next(&mut picture_info);

        self.video_feedback_query_pool
            .cmd_begin_query(recording.command_buffer(), encode_slot.index);

        let cmd_encode_video = device.video_encode_queue_device().fp().cmd_encode_video_khr;
        (cmd_encode_video)(recording.command_buffer(), &raw const encode_info);

        self.video_feedback_query_pool
            .cmd_end_query(recording.command_buffer(), encode_slot.index);

        let end_video_coding_info = vk::VideoEndCodingInfoKHR::default();
        let cmd_end_video_coding = device.video_queue_device().fp().cmd_end_video_coding_khr;
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

        device
            .device()
            .queue_submit2(
                self.encode_queue,
                &[submit_info],
                encode_slot.completion_fence.fence(),
            )
            .unwrap();

        device.device().device_wait_idle().unwrap();
    }

    unsafe fn control_video_coding(
        &self,
        command_buffer: &RecordingCommandBuffer<'_>,
        reset: bool,
    ) {
        let maybe_reset_flag = if reset {
            vk::VideoCodingControlFlagsKHR::RESET
        } else {
            vk::VideoCodingControlFlagsKHR::empty()
        };

        let mut video_coding_control_info = vk::VideoCodingControlInfoKHR::default().flags(
            // vk::VideoCodingControlFlagsKHR::ENCODE_RATE_CONTROL |
            maybe_reset_flag,
        );

        // video_coding_control_info.p_next = (&raw const self.rate_control.info).cast();

        let cmd_control_video_coding = self
            .video_session
            .device()
            .video_queue_device()
            .fp()
            .cmd_control_video_coding_khr;

        (cmd_control_video_coding)(
            command_buffer.command_buffer(),
            &raw const video_coding_control_info,
        );
    }
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
