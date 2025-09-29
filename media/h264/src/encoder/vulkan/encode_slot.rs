use std::mem::zeroed;

use ash::vk::{self, Extent2D, Handle, TaggedStructure};

use crate::encoder::{
    FrameEncodeInfo, FrameType, H264EncoderConfig,
    vulkan::{Device, DpbSlot},
};

pub(super) struct EncodeSlot {
    /// Index used for the video feedback query pool
    index: u32,

    input_staging_buffer: vk::Buffer,
    input_staging_memory: vk::DeviceMemory,

    input_image: vk::Image,
    input_image_memory: vk::DeviceMemory,
    input_image_view: vk::ImageView,

    output_buffer: vk::Buffer,
    output_memory: vk::DeviceMemory,

    transfer_semaphore: vk::Semaphore,

    transfer_command_buffer: vk::CommandBuffer,
    encode_command_buffer: vk::CommandBuffer,

    completion_fence: vk::Fence,
}

impl EncodeSlot {
    pub(super) unsafe fn new(
        config: &H264EncoderConfig,
        physical_device_memory_properties: &vk::PhysicalDeviceMemoryProperties,
        device: &Device,
        video_profile_info: vk::VideoProfileInfoKHR,
        index: u32,
        transfer_command_buffer: vk::CommandBuffer,
        encode_command_buffer: vk::CommandBuffer,
    ) -> Self {
        let (input_image, input_image_memory) = create_input_image(
            &physical_device_memory_properties,
            &device,
            video_profile_info,
            config.resolution.0,
            config.resolution.1,
        );

        let input_image_view =
            super::create_image_view(&device, input_image, vk::ImageAspectFlags::COLOR, 0);

        let (input_staging_buffer, input_staging_memory) = create_input_staging_buffer(
            &device,
            &physical_device_memory_properties,
            (config.resolution.0 as u64 * config.resolution.1 as u64 * 12) / 8,
        );

        let (output_buffer, output_memory) = create_output_buffer(
            &device,
            &physical_device_memory_properties,
            video_profile_info,
        );

        let transfer_semaphore = device
            .device()
            .create_semaphore(
                &vk::SemaphoreCreateInfo::default().flags(vk::SemaphoreCreateFlags::empty()),
                None,
            )
            .unwrap();
        if transfer_semaphore.is_null() {
            panic!();
        }

        let completion_fence = device
            .device()
            .create_fence(&vk::FenceCreateInfo::default(), None)
            .unwrap();

        EncodeSlot {
            index,
            input_staging_buffer,
            input_staging_memory,
            input_image,
            input_image_memory,
            input_image_view,
            output_buffer,
            output_memory,
            transfer_semaphore,
            transfer_command_buffer,
            encode_command_buffer,
            completion_fence,
        }
    }

    pub(super) unsafe fn wait_for_completion(&mut self, device: &Device) {
        device
            .device()
            .wait_for_fences(&[self.completion_fence], true, 0)
            .unwrap();
        device
            .device()
            .reset_fences(&[self.completion_fence])
            .unwrap();
    }

    pub(super) unsafe fn encode_frame(
        &mut self,
        device: &Device,
        video_session: vk::VideoSessionKHR,
        video_session_parameters: vk::VideoSessionParametersKHR,
        frame_info: &FrameEncodeInfo,
        active_references: &[DpbSlot],
        setup_reference: &DpbSlot,
        yuv_data: &[u8],
        width: u32,
        height: u32,
        transfer_queue_family_index: u32,
        encode_queue_family_index: u32,
        transfer_queue: vk::Queue,
        encode_queue: vk::Queue,
        video_encode_feedback_query_pool: vk::QueryPool,
    ) {
        self.copy_yuv_into_staging_buffer(device, yuv_data);

        self.record_transfer_queue(
            device,
            width,
            height,
            transfer_queue_family_index,
            encode_queue_family_index,
            transfer_queue,
        );

        self.record_encode_queue(
            device,
            video_session,
            video_session_parameters,
            frame_info,
            active_references,
            setup_reference,
            width,
            height,
            transfer_queue_family_index,
            encode_queue_family_index,
            encode_queue,
            video_encode_feedback_query_pool,
        );
    }

    unsafe fn copy_yuv_into_staging_buffer(&mut self, device: &Device, yuv_data: &[u8]) {
        let data_ptr = device
            .device()
            .map_memory(
                self.input_staging_memory,
                0,
                yuv_data.len() as u64,
                vk::MemoryMapFlags::empty(),
            )
            .unwrap();

        println!("Staging pointer: {data_ptr:p}");
        std::ptr::copy_nonoverlapping(yuv_data.as_ptr(), data_ptr as *mut u8, yuv_data.len());
        device.device().unmap_memory(self.input_staging_memory);
    }

    unsafe fn record_transfer_queue(
        &mut self,
        device: &Device,
        width: u32,
        height: u32,
        transfer_queue_family_index: u32,
        encode_queue_family_index: u32,
        transfer_queue: vk::Queue,
    ) {
        device
            .device()
            .begin_command_buffer(
                self.transfer_command_buffer,
                &vk::CommandBufferBeginInfo::default(),
            )
            .unwrap();

        // Change image type
        super::transition_image_layout(
            &device,
            self.transfer_command_buffer,
            self.input_image,
            vk::ImageLayout::UNDEFINED,
            vk::ImageLayout::TRANSFER_DST_OPTIMAL,
            vk::QUEUE_FAMILY_IGNORED,
            vk::QUEUE_FAMILY_IGNORED,
            vk::PipelineStageFlags2::TOP_OF_PIPE,
            vk::AccessFlags2::empty(),
            vk::PipelineStageFlags2::TRANSFER,
            vk::AccessFlags2::TRANSFER_WRITE,
        );

        // Copy
        let buffer_image_copy_plane0 =
            super::buffer_image_copy(vk::ImageAspectFlags::PLANE_0, width, height, 0);
        let buffer_image_copy_plane1 = super::buffer_image_copy(
            vk::ImageAspectFlags::PLANE_1,
            width / 2,
            height / 2,
            width as u64 * height as u64,
        );

        device.device().cmd_copy_buffer_to_image(
            self.transfer_command_buffer,
            self.input_staging_buffer,
            self.input_image,
            vk::ImageLayout::TRANSFER_DST_OPTIMAL,
            &[buffer_image_copy_plane0, buffer_image_copy_plane1],
        );

        super::transition_image_layout(
            &device,
            self.transfer_command_buffer,
            self.input_image,
            vk::ImageLayout::TRANSFER_DST_OPTIMAL,
            vk::ImageLayout::VIDEO_ENCODE_SRC_KHR,
            transfer_queue_family_index,
            encode_queue_family_index,
            vk::PipelineStageFlags2::TRANSFER,
            vk::AccessFlags2::TRANSFER_WRITE,
            vk::PipelineStageFlags2::NONE,
            vk::AccessFlags2::empty(),
        );

        device
            .device()
            .end_command_buffer(self.transfer_command_buffer)
            .unwrap();

        let signal_semaphores = [self.transfer_semaphore];
        let submit_info = vk::SubmitInfo::default()
            .command_buffers(std::slice::from_ref(&self.transfer_command_buffer))
            .signal_semaphores(&signal_semaphores);

        device
            .device()
            .queue_submit(transfer_queue, &[submit_info], vk::Fence::null())
            .unwrap();
    }

    unsafe fn record_encode_queue(
        &mut self,
        device: &Device,
        video_session: vk::VideoSessionKHR,
        video_session_parameters: vk::VideoSessionParametersKHR,
        frame_info: &FrameEncodeInfo,
        active_references: &[DpbSlot],
        setup_reference: &DpbSlot,
        width: u32,
        height: u32,
        transfer_queue_family_index: u32,
        encode_queue_family_index: u32,
        encode_queue: vk::Queue,
        video_encode_feedback_query_pool: vk::QueryPool,
    ) {
        // Setup infos for the SETUP reference slot
        let setup_ref_image_resource_info = vk::VideoPictureResourceInfoKHR::default()
            .image_view_binding(setup_reference.image_view)
            .coded_extent(Extent2D { width, height });
        let mut setup_ref_image_h264_reference_info =
            zeroed::<vk::native::StdVideoEncodeH264ReferenceInfo>();
        setup_ref_image_h264_reference_info.FrameNum = frame_info.frame_num.into();
        setup_ref_image_h264_reference_info.PicOrderCnt = frame_info.pic_order_cnt_lsb.into();
        setup_ref_image_h264_reference_info.primary_pic_type = match frame_info.frame_type {
            FrameType::P => vk::native::StdVideoH264PictureType_STD_VIDEO_H264_PICTURE_TYPE_P,
            FrameType::B => vk::native::StdVideoH264PictureType_STD_VIDEO_H264_PICTURE_TYPE_B,
            FrameType::I => vk::native::StdVideoH264PictureType_STD_VIDEO_H264_PICTURE_TYPE_I,
            FrameType::Idr => vk::native::StdVideoH264PictureType_STD_VIDEO_H264_PICTURE_TYPE_IDR,
        };
        let mut setup_ref_image_h264_dpb_slot_info = vk::VideoEncodeH264DpbSlotInfoKHR::default()
            .std_reference_info(&setup_ref_image_h264_reference_info);
        let setup_ref_image_slot_info = vk::VideoReferenceSlotInfoKHR::default()
            .picture_resource(&setup_ref_image_resource_info)
            .slot_index(setup_reference.slot_index as i32)
            .push(&mut setup_ref_image_h264_dpb_slot_info);

        // Setup infos the ACTIVE reference slots
        let mut active_ref_image_resource_infos: Vec<_> = active_references
            .iter()
            .map(|slot| {
                let h264_dpb_slot_info = vk::VideoEncodeH264DpbSlotInfoKHR::default()
                    .std_reference_info(&slot.h264_reference_info);
                let picture_resource_info = vk::VideoPictureResourceInfoKHR::default()
                    .image_view_binding(slot.image_view)
                    .coded_extent(Extent2D { width, height });

                (slot.slot_index, picture_resource_info, h264_dpb_slot_info)
            })
            .collect();
        let active_ref_image_slot_infos: Vec<_> = active_ref_image_resource_infos
            .iter_mut()
            .map(|(slot_index, picture_resource, h264_dpb_slot)| {
                vk::VideoReferenceSlotInfoKHR::default()
                    .picture_resource(picture_resource)
                    .slot_index(*slot_index as i32)
                    .push(h264_dpb_slot)
            })
            .collect();

        // Begin recording the encode queue
        device
            .device()
            .begin_command_buffer(
                self.encode_command_buffer,
                &vk::CommandBufferBeginInfo::default(),
            )
            .unwrap();

        // Reset query for this encode
        device.device().cmd_reset_query_pool(
            self.encode_command_buffer,
            video_encode_feedback_query_pool,
            self.index,
            1,
        );

        super::transition_image_layout(
            &device,
            self.encode_command_buffer,
            self.input_image,
            vk::ImageLayout::VIDEO_ENCODE_SRC_KHR,
            vk::ImageLayout::VIDEO_ENCODE_SRC_KHR,
            transfer_queue_family_index,
            encode_queue_family_index,
            vk::PipelineStageFlags2::NONE,
            vk::AccessFlags2::empty(),
            vk::PipelineStageFlags2::VIDEO_ENCODE_KHR,
            vk::AccessFlags2::VIDEO_ENCODE_READ_KHR,
        );

        // Build the reference slots list for the begin video coding command
        let mut use_reference_slots = active_ref_image_slot_infos.clone();
        use_reference_slots.push(setup_ref_image_slot_info);
        use_reference_slots.last_mut().unwrap().slot_index = -1;

        let begin_info = vk::VideoBeginCodingInfoKHR::default()
            .video_session(video_session)
            .video_session_parameters(video_session_parameters)
            .reference_slots(&use_reference_slots);

        // Issue the begin video coding command
        device
            .video_queue_device()
            .cmd_begin_video_coding(self.encode_command_buffer, &begin_info);

        if frame_info.frame_num == 0 {
            let mut video_encode_h264_rate_control_info =
                vk::VideoEncodeH264RateControlInfoKHR::default();
            let mut video_encode_quality_level_info = vk::VideoEncodeQualityLevelInfoKHR::default();
            let mut video_encode_rate_control_info = vk::VideoEncodeRateControlInfoKHR::default();

            let video_coding_control_info = vk::VideoCodingControlInfoKHR::default()
                .flags(vk::VideoCodingControlFlagsKHR::RESET)
                .push(&mut video_encode_h264_rate_control_info)
                .push(&mut video_encode_quality_level_info)
                .push(&mut video_encode_rate_control_info);

            device
                .video_queue_device()
                .cmd_control_video_coding(self.encode_command_buffer, &video_coding_control_info);
        }

        let src_picture_resource_plane0 = vk::VideoPictureResourceInfoKHR::default()
            .image_view_binding(self.input_image_view)
            .coded_offset(vk::Offset2D { x: 0, y: 0 })
            .coded_extent(vk::Extent2D { width, height })
            .base_array_layer(0);

        let mut std_slice_header = zeroed::<vk::native::StdVideoEncodeH264SliceHeader>();
        std_slice_header.slice_type = match frame_info.frame_type {
            FrameType::P => vk::native::StdVideoH264SliceType_STD_VIDEO_H264_SLICE_TYPE_P,
            FrameType::B => vk::native::StdVideoH264SliceType_STD_VIDEO_H264_SLICE_TYPE_B,
            FrameType::I => vk::native::StdVideoH264SliceType_STD_VIDEO_H264_SLICE_TYPE_I,
            FrameType::Idr => vk::native::StdVideoH264SliceType_STD_VIDEO_H264_SLICE_TYPE_I,
        };
        std_slice_header.flags.set_direct_spatial_mv_pred_flag(1);

        let nalu_slices = [vk::VideoEncodeH264NaluSliceInfoKHR::default()
            // .constant_qp(26)
            .std_slice_header(&std_slice_header)];
        let mut ref_lists = zeroed::<vk::native::StdVideoEncodeH264ReferenceListsInfo>();
        let mut l0 = active_ref_image_slot_infos
            .iter()
            .map(|x| x.slot_index as u8);
        ref_lists
            .RefPicList0
            .fill_with(|| l0.next().unwrap_or(0xFF));
        ref_lists.RefPicList1[..].fill(0xFF);
        ref_lists.num_ref_idx_l0_active_minus1 =
            (active_ref_image_slot_infos.len().saturating_sub(1)) as u8;
        let mut h264_picture_info = zeroed::<vk::native::StdVideoEncodeH264PictureInfo>();
        h264_picture_info.PicOrderCnt = frame_info.pic_order_cnt_lsb.into();
        h264_picture_info.frame_num = frame_info.frame_num.into();
        h264_picture_info.idr_pic_id = frame_info.idr_pic_id;
        h264_picture_info.pRefLists = &raw const ref_lists;
        h264_picture_info.primary_pic_type = match frame_info.frame_type {
            FrameType::P => vk::native::StdVideoH264PictureType_STD_VIDEO_H264_PICTURE_TYPE_P,
            FrameType::B => vk::native::StdVideoH264PictureType_STD_VIDEO_H264_PICTURE_TYPE_B,
            FrameType::I => vk::native::StdVideoH264PictureType_STD_VIDEO_H264_PICTURE_TYPE_I,
            FrameType::Idr => vk::native::StdVideoH264PictureType_STD_VIDEO_H264_PICTURE_TYPE_IDR,
        };
        h264_picture_info
            .flags
            .set_IdrPicFlag((frame_info.frame_type == FrameType::Idr) as u32);
        h264_picture_info
            .flags
            .set_is_reference((frame_info.frame_type != FrameType::B) as u32);

        let mut h264_encode_info = vk::VideoEncodeH264PictureInfoKHR::default()
            .generate_prefix_nalu(false)
            .nalu_slice_entries(&nalu_slices)
            .std_picture_info(&h264_picture_info);

        let encode_info = vk::VideoEncodeInfoKHR::default()
            .src_picture_resource(src_picture_resource_plane0)
            .dst_buffer(self.output_buffer)
            .dst_buffer_range(1024 * 1024) // TOD: actually use the value here of the buffer
            .reference_slots(&active_ref_image_slot_infos)
            .flags(vk::VideoEncodeFlagsKHR::empty())
            .setup_reference_slot(&setup_ref_image_slot_info)
            .push(&mut h264_encode_info);

        device.device().cmd_begin_query(
            self.encode_command_buffer,
            video_encode_feedback_query_pool,
            self.index,
            vk::QueryControlFlags::empty(),
        );

        device
            .video_encode_queue_device()
            .cmd_encode_video(self.encode_command_buffer, &encode_info);

        device.device().cmd_end_query(
            self.encode_command_buffer,
            video_encode_feedback_query_pool,
            self.index,
        );

        device.video_queue_device().cmd_end_video_coding(
            self.encode_command_buffer,
            &vk::VideoEndCodingInfoKHR::default(),
        );

        // Finish up everything
        device
            .device()
            .end_command_buffer(self.encode_command_buffer)
            .unwrap();

        let command_buffer_infos =
            [vk::CommandBufferSubmitInfo::default().command_buffer(self.encode_command_buffer)];
        let wait_semaphore_infos = [vk::SemaphoreSubmitInfo::default()
            .semaphore(self.transfer_semaphore)
            .stage_mask(vk::PipelineStageFlags2::VIDEO_ENCODE_KHR)];
        let submit_info = vk::SubmitInfo2::default()
            .command_buffer_infos(&command_buffer_infos)
            .wait_semaphore_infos(&wait_semaphore_infos);
        device
            .device()
            .queue_submit2(encode_queue, &[submit_info], self.completion_fence)
            .unwrap();
    }
}

unsafe fn create_input_image(
    physical_device_memory_properties: &vk::PhysicalDeviceMemoryProperties,
    device: &Device,
    video_profile_info: vk::VideoProfileInfoKHR<'_>,
    width: u32,
    height: u32,
) -> (vk::Image, vk::DeviceMemory) {
    let profiles = [video_profile_info];
    let mut video_profile_list_info = vk::VideoProfileListInfoKHR::default().profiles(&profiles);
    let input_image_info = vk::ImageCreateInfo::default()
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
        .push(&mut video_profile_list_info);

    let image = device
        .device()
        .create_image(&input_image_info, None)
        .unwrap();
    let memory_requirements = device.device().get_image_memory_requirements(image);

    let alloc_info = vk::MemoryAllocateInfo::default()
        .allocation_size(memory_requirements.size)
        .memory_type_index(
            super::find_memory_type(
                memory_requirements.memory_type_bits,
                vk::MemoryPropertyFlags::DEVICE_LOCAL,
                physical_device_memory_properties,
            )
            .unwrap(),
        );

    let memory = device.device().allocate_memory(&alloc_info, None).unwrap();
    device.device().bind_image_memory(image, memory, 0).unwrap();

    (image, memory)
}

unsafe fn create_input_staging_buffer(
    device: &Device,
    physical_device_memory_properties: &vk::PhysicalDeviceMemoryProperties,
    size: vk::DeviceSize,
) -> (vk::Buffer, vk::DeviceMemory) {
    let staging_buffer_info = vk::BufferCreateInfo::default()
        .size(size)
        .usage(vk::BufferUsageFlags::TRANSFER_SRC)
        .sharing_mode(vk::SharingMode::EXCLUSIVE);
    let staging_buffer = device
        .device()
        .create_buffer(&staging_buffer_info, None)
        .unwrap();
    let staging_mem_req = device
        .device()
        .get_buffer_memory_requirements(staging_buffer);
    let staging_alloc_info = vk::MemoryAllocateInfo::default()
        .allocation_size(staging_mem_req.size)
        .memory_type_index(
            super::find_memory_type(
                staging_mem_req.memory_type_bits,
                vk::MemoryPropertyFlags::HOST_VISIBLE | vk::MemoryPropertyFlags::HOST_COHERENT,
                physical_device_memory_properties,
            )
            .unwrap(),
        );
    let staging_memory = device
        .device()
        .allocate_memory(&staging_alloc_info, None)
        .unwrap();
    device
        .device()
        .bind_buffer_memory(staging_buffer, staging_memory, 0)
        .unwrap();

    (staging_buffer, staging_memory)
}

unsafe fn create_output_buffer(
    device: &Device,
    physical_device_memory_properties: &vk::PhysicalDeviceMemoryProperties,
    video_profile_info: vk::VideoProfileInfoKHR<'_>,
) -> (vk::Buffer, vk::DeviceMemory) {
    let profiles = [video_profile_info];
    let mut video_profile_list_info = vk::VideoProfileListInfoKHR::default().profiles(&profiles);

    let output_buffer_info = vk::BufferCreateInfo::default()
        .size(1024 * 1024)
        .usage(vk::BufferUsageFlags::VIDEO_ENCODE_DST_KHR | vk::BufferUsageFlags::TRANSFER_SRC)
        .push(&mut video_profile_list_info);

    let output_buffer = device
        .device()
        .create_buffer(&output_buffer_info, None)
        .unwrap();
    let output_memory_requirement = device
        .device()
        .get_buffer_memory_requirements(output_buffer);

    let output_alloc_info = vk::MemoryAllocateInfo::default()
        .allocation_size(output_memory_requirement.size)
        .memory_type_index(
            super::find_memory_type(
                output_memory_requirement.memory_type_bits,
                vk::MemoryPropertyFlags::HOST_VISIBLE,
                physical_device_memory_properties,
            )
            .unwrap(),
        );

    let output_memory = device
        .device()
        .allocate_memory(&output_alloc_info, None)
        .unwrap();

    device
        .device()
        .bind_buffer_memory(output_buffer, output_memory, 0)
        .unwrap();

    (output_buffer, output_memory)
}
