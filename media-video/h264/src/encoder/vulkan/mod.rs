use crate::{
    Level, Profile,
    encoder::{
        H264EncoderConfig, H264FrameRate, H264FrameType, H264RateControlConfig,
        util::{FrameEncodeInfo, H264EncoderState, macro_block_align},
    },
};
use std::{
    collections::VecDeque,
    error::Error,
    mem::{take, zeroed},
    ptr::null_mut,
};
use vulkan::{
    Buffer, CommandBuffer, Device, Fence, Image, ImageView, Instance, REQUIRED_EXTENSIONS_BASE,
    REQUIRED_EXTENSIONS_ENCODE, Semaphore, VideoFeedbackQueryPool, VideoSession,
    VideoSessionParameters,
    ash::{
        Entry,
        vk::{self, Handle, TaggedStructure},
    },
    create_dpb,
};

const PARALLEL_ENCODINGS: u32 = 16;

pub struct VkH264Encoder {
    config: H264EncoderConfig,
    state: H264EncoderState,

    width: u32,
    height: u32,

    device: Device,

    transfer_queue_family_index: u32,
    encode_queue_family_index: u32,

    transfer_queue: vk::Queue,
    encode_queue: vk::Queue,

    video_feedback_query_pool: VideoFeedbackQueryPool,

    video_session: VideoSession,
    video_session_parameters: VideoSessionParameters,

    available_encode_slots: Vec<EncodeSlot>,
    in_flight: VecDeque<EncodeSlot>,

    max_l0_p_ref_images: u32,
    max_l0_b_ref_images: u32,
    max_l1_b_ref_images: u32,

    /// Unused reference slots
    available_ref_images: Vec<DpbSlot>,
    dpb_in_correct_layout: bool,

    /// Active (in use) reference slots
    ///
    /// back contains oldest reference pictures
    /// front contains most recent reference pictures
    active_ref_images: VecDeque<DpbSlot>,

    backlogged_b_frames: Vec<(FrameEncodeInfo, EncodeSlot)>,

    output: VecDeque<Vec<u8>>,
}

struct EncodeSlot {
    /// Index used for the video feedback query pool
    index: u32,

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

impl VkH264Encoder {
    #[allow(unsafe_op_in_unsafe_fn, clippy::missing_safety_doc)]
    pub unsafe fn new(config: H264EncoderConfig) -> Result<Self, Box<dyn Error>> {
        let entry = unsafe { Entry::load().unwrap() };

        let instance = Instance::load(&entry).unwrap();

        let devices = dbg!(instance.instance().enumerate_physical_devices().unwrap());

        let physical_device = devices[1];

        let queue_family_properties = instance
            .instance()
            .get_physical_device_queue_family_properties(physical_device);

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
            .push(&mut sync2_features_enable);

        let device = Device::create(&instance, physical_device, &create_device_info).unwrap();

        let encode_queue = device
            .device()
            .get_device_queue(encode_queue_family_index, 0);
        if encode_queue.is_null() {
            panic!();
        }

        let transfer_queue = device
            .device()
            .get_device_queue(transfer_queue_family_index, 0);
        if transfer_queue.is_null() {
            panic!();
        }

        let state = H264EncoderState::new(config.frame_pattern);
        let (width, height) = config.resolution;
        let profile_idc = map_profile(config.profile).unwrap();
        let level_idc = map_level(config.level).unwrap();

        let mut h264_profile_info = vk::VideoEncodeH264ProfileInfoKHR::default()
            .std_profile_idc(map_profile(config.profile).unwrap());

        let video_profile_info = vk::VideoProfileInfoKHR::default()
            .video_codec_operation(vk::VideoCodecOperationFlagsKHR::ENCODE_H264)
            .chroma_bit_depth(vk::VideoComponentBitDepthFlagsKHR::TYPE_8)
            .luma_bit_depth(vk::VideoComponentBitDepthFlagsKHR::TYPE_8)
            .chroma_subsampling(vk::VideoChromaSubsamplingFlagsKHR::TYPE_420)
            .push(&mut h264_profile_info);

        // Video Coding Capabilities
        let (video_capabilities, video_encode_capabilities, video_encode_h264_capabilities) =
            get_video_capabilities(&instance, physical_device, video_profile_info);

        println!("{video_capabilities:#?}");
        println!("{video_encode_capabilities:#?}");
        println!("{video_encode_h264_capabilities:#?}");

        let max_dpb_slots = video_capabilities.max_dpb_slots;
        let max_active_ref_images = video_capabilities.max_active_reference_pictures;
        let max_l0_p_ref_images = video_encode_h264_capabilities.max_p_picture_l0_reference_count;
        let max_l0_b_ref_images = video_encode_h264_capabilities.max_b_picture_l0_reference_count;
        let max_l1_b_ref_images = video_encode_h264_capabilities.max_l1_reference_count;

        // Create Video session

        let create_info = vk::VideoSessionCreateInfoKHR::default()
            .max_coded_extent(vk::Extent2D { width, height })
            .queue_family_index(encode_queue_family_index)
            .max_active_reference_pictures(max_active_ref_images)
            .max_dpb_slots(max_dpb_slots)
            .picture_format(vk::Format::G8_B8R8_2PLANE_420_UNORM)
            .reference_picture_format(vk::Format::G8_B8R8_2PLANE_420_UNORM)
            .video_profile(&video_profile_info)
            .std_header_version(&video_capabilities.std_header_version);

        let video_session = VideoSession::create(&device, &create_info).unwrap();

        get_video_format_properties(&instance, physical_device, video_profile_info);

        let video_feedback_query_pool =
            VideoFeedbackQueryPool::create(&device, PARALLEL_ENCODINGS, video_profile_info)
                .unwrap();

        // Create video session parameters
        let video_session_parameters = create_video_session_parameters(
            &state,
            &video_session,
            width,
            height,
            profile_idc,
            level_idc,
            vk::native::StdVideoH264ChromaFormatIdc_STD_VIDEO_H264_CHROMA_FORMAT_IDC_420,
        );

        // Create command buffers
        let mut transfer_command_buffers =
            CommandBuffer::create(&device, transfer_queue_family_index, PARALLEL_ENCODINGS)
                .unwrap();

        let mut encode_command_buffers =
            CommandBuffer::create(&device, encode_queue_family_index, PARALLEL_ENCODINGS).unwrap();

        let mut available_encode_slots = vec![];

        for index in 0..PARALLEL_ENCODINGS {
            let input_image = create_input_image(
                &device,
                video_profile_info,
                config.resolution.0,
                config.resolution.1,
            );

            let input_image_view = {
                let create_info = vk::ImageViewCreateInfo::default()
                    .image(input_image.image())
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

                ImageView::create(&input_image, &create_info).unwrap()
            };

            let input_staging_buffer = {
                let create_info = vk::BufferCreateInfo::default()
                    .size((config.resolution.0 as u64 * config.resolution.1 as u64 * 12) / 8)
                    .usage(vk::BufferUsageFlags::TRANSFER_SRC)
                    .sharing_mode(vk::SharingMode::EXCLUSIVE);

                Buffer::create(&device, &create_info).unwrap()
            };

            let output_buffer = {
                let profiles = [video_profile_info];
                let mut video_profile_list_info =
                    vk::VideoProfileListInfoKHR::default().profiles(&profiles);

                let create_info = vk::BufferCreateInfo::default()
                    .size(1024 * 1024)
                    .usage(
                        vk::BufferUsageFlags::VIDEO_ENCODE_DST_KHR
                            | vk::BufferUsageFlags::TRANSFER_SRC,
                    )
                    .push(&mut video_profile_list_info);

                Buffer::create(&device, &create_info).unwrap()
            };

            let transfer_semaphore = Semaphore::create(&device).unwrap();
            let completion_fence = Fence::create(&device).unwrap();

            available_encode_slots.push(EncodeSlot {
                index,
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

        let available_ref_images =
            create_dpb(&device, video_profile_info, max_dpb_slots, width, height)
                .unwrap()
                .into_iter()
                .enumerate()
                .map(|(i, image_view)| DpbSlot {
                    slot_index: i as u32,
                    image_view,
                    h264_reference_info: zeroed(),
                })
                .collect();

        Ok(VkH264Encoder {
            config,
            state,
            width,
            height,
            device,
            transfer_queue_family_index,
            encode_queue_family_index,
            transfer_queue,
            encode_queue,
            video_feedback_query_pool,
            video_session,
            video_session_parameters,
            available_encode_slots,
            in_flight: VecDeque::new(),
            max_l0_p_ref_images,
            max_l0_b_ref_images,
            max_l1_b_ref_images,
            available_ref_images,
            dpb_in_correct_layout: false,
            active_ref_images: VecDeque::new(),
            output: VecDeque::new(),
            backlogged_b_frames: Vec::new(),
        })
    }

    unsafe fn read_out_coded_buffer(&mut self, encode_slot: &mut EncodeSlot) {
        let bytes_written = self
            .video_feedback_query_pool
            .get_bytes_written(encode_slot.index)
            .unwrap();

        let mapped_buffer = encode_slot.output_buffer.map(bytes_written).unwrap();
        self.output.push_back(mapped_buffer.data().to_vec());
    }

    unsafe fn wait_for_slot_completion(&mut self, encode_slot: &mut EncodeSlot) {
        encode_slot.completion_fence.wait(u64::MAX).unwrap();
        encode_slot.completion_fence.reset().unwrap();
    }

    #[allow(unsafe_op_in_unsafe_fn, clippy::missing_safety_doc)]
    pub unsafe fn wait_result(&mut self) -> Option<Vec<u8>> {
        if let Some(buf) = self.output.pop_front() {
            return Some(buf);
        }

        if let Some(mut encode_slot) = self.in_flight.pop_front() {
            self.wait_for_slot_completion(&mut encode_slot);
            self.read_out_coded_buffer(&mut encode_slot);
            self.available_encode_slots.push(encode_slot);
        }

        self.output.pop_front()
    }

    #[allow(unsafe_op_in_unsafe_fn, clippy::missing_safety_doc)]
    pub unsafe fn poll_result(&mut self) -> Option<Vec<u8>> {
        if let Some(buf) = self.output.pop_front() {
            return Some(buf);
        }

        if let Some(encode_slot) = self.in_flight.front() {
            let completed = encode_slot.completion_fence.wait(0).unwrap();
            if !completed {
                return None;
            }

            encode_slot.completion_fence.reset().unwrap();
            let mut encode_slot = self.in_flight.pop_front().unwrap();

            self.read_out_coded_buffer(&mut encode_slot);

            self.available_encode_slots.push(encode_slot);
        }

        self.output.pop_front()
    }

    #[allow(unsafe_op_in_unsafe_fn, clippy::missing_safety_doc)]
    pub unsafe fn encode_frame(&mut self, yuv_data: &[u8]) {
        let frame_info = self.state.next();
        log::debug!("Submit {frame_info:?}");

        let mut encode_slot = if let Some(encode_slot) = self.available_encode_slots.pop() {
            encode_slot
        } else if let Some(mut encode_slot) = self.in_flight.pop_front() {
            self.wait_for_slot_completion(&mut encode_slot);
            self.read_out_coded_buffer(&mut encode_slot);
            encode_slot
        } else {
            unreachable!()
        };

        self.upload_yuv_to_encode_slot(&mut encode_slot, yuv_data);

        // B-Frames are not encoded immediately, they are queued until after an I or P-frame is encoded
        if frame_info.frame_type == H264FrameType::B {
            log::trace!("\tDeferring encode for later until a P or I frame has been encoded");
            self.backlogged_b_frames.push((frame_info, encode_slot));
            return;
        }

        if frame_info.frame_type == H264FrameType::Idr {
            assert!(self.backlogged_b_frames.is_empty());

            // Write out SPS & PPS to bitstream
            let mut h264_get_encoded_params =
                vk::VideoEncodeH264SessionParametersGetInfoKHR::default()
                    .write_std_sps(true)
                    .write_std_pps(true);

            self.output.push_back(
                self.video_session_parameters
                    .get_encoded_video_session_parameters(&mut h264_get_encoded_params)
                    .unwrap(),
            );

            // Reset DPB
            self.available_ref_images
                .extend(self.active_ref_images.drain(..));
        }

        self.process_encode_slot(frame_info, encode_slot);

        if matches!(frame_info.frame_type, H264FrameType::I | H264FrameType::P) {
            let backlogged_b_frames = take(&mut self.backlogged_b_frames);

            // Process backlogged B-Frames
            for (frame_info, encode_slot) in backlogged_b_frames {
                self.process_encode_slot(frame_info, encode_slot);
            }
        }
    }

    unsafe fn upload_yuv_to_encode_slot(&mut self, encode_slot: &mut EncodeSlot, yuv_data: &[u8]) {
        let mapped_buffer = encode_slot
            .input_staging_buffer
            .map(yuv_data.len() as u64)
            .unwrap();
        mapped_buffer.data_mut().copy_from_slice(yuv_data);
    }

    unsafe fn process_encode_slot(
        &mut self,
        frame_info: FrameEncodeInfo,
        mut encode_slot: EncodeSlot,
    ) {
        log::trace!("Encode frame {frame_info:?}");

        self.record_transfer_queue(&mut encode_slot);

        // Prepare setup reference image stuff
        let mut setup_reference = if let Some(slot) = self.available_ref_images.pop() {
            slot
        } else if let Some(slot) = self.active_ref_images.pop_back() {
            slot
        } else {
            unreachable!()
        };

        log::trace!("\tUsing dpb slot: {}", setup_reference.slot_index);

        self.record_encode_queue(&mut encode_slot, frame_info, &mut setup_reference);

        self.in_flight.push_back(encode_slot);

        if frame_info.frame_type == H264FrameType::B {
            self.available_ref_images.push(setup_reference);
        } else {
            self.active_ref_images.push_front(setup_reference);
        }
    }

    unsafe fn record_transfer_queue(&mut self, encode_slot: &mut EncodeSlot) {
        // Record TRANSFER queue
        self.device
            .device()
            .begin_command_buffer(
                encode_slot.transfer_command_buffer.command_buffer(),
                &vk::CommandBufferBeginInfo::default(),
            )
            .unwrap();

        // Change image type
        encode_slot.input_image.cmd_memory_barrier2(
            encode_slot.transfer_command_buffer.command_buffer(),
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
            encode_slot.transfer_command_buffer.command_buffer(),
            encode_slot.input_staging_buffer.buffer(),
            encode_slot.input_image.image(),
            vk::ImageLayout::TRANSFER_DST_OPTIMAL,
            &[buffer_image_copy_plane0, buffer_image_copy_plane1],
        );

        encode_slot.input_image.cmd_memory_barrier2(
            encode_slot.transfer_command_buffer.command_buffer(),
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

        self.device
            .device()
            .end_command_buffer(encode_slot.transfer_command_buffer.command_buffer())
            .unwrap();

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
    ) {
        // Begin recording the encode queue
        self.device
            .device()
            .begin_command_buffer(
                encode_slot.encode_command_buffer.command_buffer(),
                &vk::CommandBufferBeginInfo::default(),
            )
            .unwrap();

        if !self.dpb_in_correct_layout {
            self.dpb_in_correct_layout = true;

            for dpb_slot in self
                .available_ref_images
                .iter_mut()
                .chain(self.active_ref_images.iter_mut())
                .chain(Some(&mut *setup_reference))
            {
                dpb_slot.image_view.image().cmd_memory_barrier2(
                    encode_slot.encode_command_buffer.command_buffer(),
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
        }

        let primary_pic_type = match frame_info.frame_type {
            H264FrameType::P => vk::native::StdVideoH264PictureType_STD_VIDEO_H264_PICTURE_TYPE_P,
            H264FrameType::B => vk::native::StdVideoH264PictureType_STD_VIDEO_H264_PICTURE_TYPE_B,
            H264FrameType::I => vk::native::StdVideoH264PictureType_STD_VIDEO_H264_PICTURE_TYPE_I,
            H264FrameType::Idr => {
                vk::native::StdVideoH264PictureType_STD_VIDEO_H264_PICTURE_TYPE_IDR
            }
        };

        let setup_ref_image_resource_info = vk::VideoPictureResourceInfoKHR::default()
            .image_view_binding(setup_reference.image_view.image_view())
            .coded_extent(vk::Extent2D {
                width: self.width,
                height: self.height,
            });

        setup_reference.h264_reference_info.FrameNum = frame_info.frame_num.into();
        setup_reference.h264_reference_info.PicOrderCnt = frame_info.pic_order_cnt_lsb.into();
        setup_reference.h264_reference_info.primary_pic_type = primary_pic_type;

        let mut setup_ref_image_h264_dpb_slot_info = vk::VideoEncodeH264DpbSlotInfoKHR::default()
            .std_reference_info(&setup_reference.h264_reference_info);

        let setup_ref_image_slot_info = vk::VideoReferenceSlotInfoKHR::default()
            .picture_resource(&setup_ref_image_resource_info)
            .slot_index(setup_reference.slot_index as i32)
            .push(&mut setup_ref_image_h264_dpb_slot_info);

        // Prepare active reference images stuff
        let (max_l0_ref_slots, max_l1_ref_slots) = match frame_info.frame_type {
            H264FrameType::P => (self.max_l0_p_ref_images, 0),
            H264FrameType::B => (self.max_l0_b_ref_images, 1),
            H264FrameType::I | H264FrameType::Idr => (0, 0),
        };

        let mut active_ref_image_resource_infos: Vec<_> = self
            .active_ref_images
            .iter()
            .take((max_l0_ref_slots + max_l1_ref_slots) as usize)
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
        let active_ref_image_slot_infos: Vec<_> = active_ref_image_resource_infos
            .iter_mut()
            .map(|(slot_index, picture_resource, h264_dpb_slot)| {
                vk::VideoReferenceSlotInfoKHR::default()
                    .picture_resource(picture_resource)
                    .slot_index(*slot_index as i32)
                    .push(h264_dpb_slot)
            })
            .collect();

        // Reset query for this encode
        self.video_feedback_query_pool.cmd_reset_query(
            encode_slot.encode_command_buffer.command_buffer(),
            encode_slot.index,
        );

        encode_slot.input_image.cmd_memory_barrier2(
            encode_slot.encode_command_buffer.command_buffer(),
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

        // Build the reference slots list for the begin video coding command
        let mut use_reference_slots = active_ref_image_slot_infos.clone();
        use_reference_slots.push(setup_ref_image_slot_info);
        // TODO: marking setup slot as not active, validation layers are not complaining but not sure if its correct
        use_reference_slots.last_mut().unwrap().slot_index = -1;

        let begin_info = vk::VideoBeginCodingInfoKHR::default()
            .video_session(self.video_session.video_session())
            .video_session_parameters(self.video_session_parameters.video_session_parameters())
            .reference_slots(&use_reference_slots);

        // Issue the begin video coding command
        self.device.video_queue_device().cmd_begin_video_coding(
            encode_slot.encode_command_buffer.command_buffer(),
            &begin_info,
        );

        if frame_info.frame_type == H264FrameType::Idr
            && frame_info.frame_num == 0
            && frame_info.idr_pic_id == 1
        {
            self.control_video_coding(encode_slot);
        }

        let src_picture_resource_plane0 = vk::VideoPictureResourceInfoKHR::default()
            .image_view_binding(encode_slot.input_image_view.image_view())
            .coded_offset(vk::Offset2D { x: 0, y: 0 })
            .coded_extent(vk::Extent2D {
                width: self.width,
                height: self.height,
            })
            .base_array_layer(0);

        let mut std_slice_header = zeroed::<vk::native::StdVideoEncodeH264SliceHeader>();
        std_slice_header.slice_type = match frame_info.frame_type {
            H264FrameType::P => vk::native::StdVideoH264SliceType_STD_VIDEO_H264_SLICE_TYPE_P,
            H264FrameType::B => vk::native::StdVideoH264SliceType_STD_VIDEO_H264_SLICE_TYPE_B,
            H264FrameType::I => vk::native::StdVideoH264SliceType_STD_VIDEO_H264_SLICE_TYPE_I,
            H264FrameType::Idr => vk::native::StdVideoH264SliceType_STD_VIDEO_H264_SLICE_TYPE_I,
        };
        // TODO: add condition if this must be set
        std_slice_header
            .flags
            .set_num_ref_idx_active_override_flag(1);
        std_slice_header.flags.set_direct_spatial_mv_pred_flag(0);

        let nalu_slices = [vk::VideoEncodeH264NaluSliceInfoKHR::default()
            // .constant_qp(26)
            .std_slice_header(&std_slice_header)];
        let mut ref_lists = zeroed::<vk::native::StdVideoEncodeH264ReferenceListsInfo>();

        // Past references
        let mut reference_iter = active_ref_image_slot_infos
            .iter()
            .map(|slot_info| slot_info.slot_index as u8);

        let l1_count = fill_pic_list(
            &mut ref_lists.RefPicList1,
            (&mut reference_iter).take(max_l1_ref_slots as usize),
        );
        let l0_count = fill_pic_list(&mut ref_lists.RefPicList0, reference_iter);

        ref_lists.num_ref_idx_l0_active_minus1 = l0_count.saturating_sub(1);
        ref_lists.num_ref_idx_l1_active_minus1 = l1_count.saturating_sub(1);

        log::trace!("\tRefPicList0: {}", debug_list(&ref_lists.RefPicList0));
        log::trace!("\tRefPicList1: {}", debug_list(&ref_lists.RefPicList1));

        fn fill_pic_list(list: &mut [u8], iter: impl IntoIterator<Item = u8>) -> u8 {
            let mut count = 0;
            let mut iter = iter.into_iter();

            for slot_index in list {
                if let Some(v) = iter.next() {
                    count += 1;
                    *slot_index = v;
                } else {
                    *slot_index = 0xFF;
                }
            }

            count
        }

        fn debug_list(list: &[u8]) -> String {
            format!(
                "{:?}",
                list.iter().take_while(|x| **x != 0xFF).collect::<Vec<_>>()
            )
        }

        let mut h264_picture_info = zeroed::<vk::native::StdVideoEncodeH264PictureInfo>();
        h264_picture_info.PicOrderCnt = frame_info.pic_order_cnt_lsb.into();
        h264_picture_info.frame_num = frame_info.frame_num.into();
        h264_picture_info.idr_pic_id = frame_info.idr_pic_id;
        h264_picture_info.pRefLists = &raw const ref_lists;
        h264_picture_info.primary_pic_type = primary_pic_type;
        h264_picture_info
            .flags
            .set_IdrPicFlag((frame_info.frame_type == H264FrameType::Idr) as u32);
        h264_picture_info
            .flags
            .set_is_reference((frame_info.frame_type != H264FrameType::B) as u32);

        let mut h264_encode_info = vk::VideoEncodeH264PictureInfoKHR::default()
            .generate_prefix_nalu(false)
            .nalu_slice_entries(&nalu_slices)
            .std_picture_info(&h264_picture_info);

        let encode_info = vk::VideoEncodeInfoKHR::default()
            .src_picture_resource(src_picture_resource_plane0)
            .dst_buffer(encode_slot.output_buffer.buffer())
            .dst_buffer_range(1024 * 1024) // TOD: actually use the value here of the buffer
            .reference_slots(&active_ref_image_slot_infos)
            .flags(vk::VideoEncodeFlagsKHR::empty())
            .setup_reference_slot(&setup_ref_image_slot_info)
            .push(&mut h264_encode_info);

        self.video_feedback_query_pool.cmd_begin_query(
            encode_slot.encode_command_buffer.command_buffer(),
            encode_slot.index,
        );

        self.device.video_encode_queue_device().cmd_encode_video(
            encode_slot.encode_command_buffer.command_buffer(),
            &encode_info,
        );

        self.video_feedback_query_pool.cmd_end_query(
            encode_slot.encode_command_buffer.command_buffer(),
            encode_slot.index,
        );

        self.device.video_queue_device().cmd_end_video_coding(
            encode_slot.encode_command_buffer.command_buffer(),
            &vk::VideoEndCodingInfoKHR::default(),
        );

        // Finish up everything
        self.device
            .device()
            .end_command_buffer(encode_slot.encode_command_buffer.command_buffer())
            .unwrap();

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

    unsafe fn control_video_coding(&self, encode_slot: &mut EncodeSlot) {
        let mut h264_layer_rate_control_info =
            vk::VideoEncodeH264RateControlLayerInfoKHR::default();
        let mut layer_rate_control_info = vk::VideoEncodeRateControlLayerInfoKHR::default();

        let mut h264_rate_control_info = vk::VideoEncodeH264RateControlInfoKHR::default();
        let mut rate_control_info = vk::VideoEncodeRateControlInfoKHR::default();

        if let Some(H264FrameRate {
            numerator,
            denominator,
        }) = self.config.framerate
        {
            layer_rate_control_info.frame_rate_numerator = numerator;
            layer_rate_control_info.frame_rate_denominator = denominator;
        } else {
            layer_rate_control_info.frame_rate_numerator = 1;
            layer_rate_control_info.frame_rate_denominator = 1;
        }

        if let Some((min_qp, max_qp)) = self.config.qp {
            set_qp(&mut h264_layer_rate_control_info, min_qp, max_qp);
        }

        match self.config.rate_control {
            H264RateControlConfig::ConstantBitRate { bitrate } => {
                rate_control_info.rate_control_mode = vk::VideoEncodeRateControlModeFlagsKHR::CBR;
                layer_rate_control_info.average_bitrate = bitrate.into();
                layer_rate_control_info.max_bitrate = bitrate.into();
            }
            H264RateControlConfig::VariableBitRate {
                average_bitrate,
                max_bitrate,
            } => {
                rate_control_info.rate_control_mode = vk::VideoEncodeRateControlModeFlagsKHR::VBR;
                layer_rate_control_info.average_bitrate = average_bitrate.into();
                layer_rate_control_info.max_bitrate = max_bitrate.into();
            }
            H264RateControlConfig::ConstantQuality {
                const_qp,
                max_bitrate,
            } => {
                if let Some(max_bitrate) = max_bitrate {
                    // TODO: Trying to limit the bitrate using VBR, vulkan doesn't do CQP currently
                    rate_control_info.rate_control_mode =
                        vk::VideoEncodeRateControlModeFlagsKHR::VBR;
                    layer_rate_control_info.max_bitrate = max_bitrate.into();
                } else {
                    rate_control_info.rate_control_mode =
                        vk::VideoEncodeRateControlModeFlagsKHR::DISABLED;
                }

                set_qp(&mut h264_layer_rate_control_info, const_qp, const_qp);
            }
        }

        rate_control_info.virtual_buffer_size_in_ms = 100;

        let layers = [layer_rate_control_info.push(&mut h264_layer_rate_control_info)];
        let mut rate_control_info = rate_control_info.layers(&layers);

        let video_coding_control_info = vk::VideoCodingControlInfoKHR::default()
            .flags(
                vk::VideoCodingControlFlagsKHR::RESET, // | vk::VideoCodingControlFlagsKHR::ENCODE_RATE_CONTROL, TODO: reenable & fix RC
            )
            .push(&mut rate_control_info)
            .push(&mut h264_rate_control_info);

        self.device.video_queue_device().cmd_control_video_coding(
            encode_slot.encode_command_buffer.command_buffer(),
            &video_coding_control_info,
        );
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

unsafe fn create_input_image(
    device: &Device,
    video_profile_info: vk::VideoProfileInfoKHR<'_>,
    width: u32,
    height: u32,
) -> Image {
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
        .push(&mut video_profile_list_info);

    Image::create(device, &create_info).unwrap()
}

unsafe fn create_video_session_parameters(
    state: &H264EncoderState,
    video_session: &VideoSession,
    width: u32,
    height: u32,
    profile_idc: vk::native::StdVideoH264ProfileIdc,
    level_idc: vk::native::StdVideoH264LevelIdc,
    chrome_format_idc: vk::native::StdVideoH264ChromaFormatIdc,
) -> VideoSessionParameters {
    let (width_mbaligned, height_mbaligned) = (macro_block_align(width), macro_block_align(height));

    let mut seq_params: vk::native::StdVideoH264SequenceParameterSet = zeroed();
    seq_params.profile_idc = profile_idc;
    seq_params.level_idc = level_idc;
    seq_params.chroma_format_idc = chrome_format_idc;

    seq_params.log2_max_frame_num_minus4 = 16 - 4;
    seq_params.log2_max_pic_order_cnt_lsb_minus4 =
        state.log2_max_pic_order_cnt_lsb.try_into().unwrap();
    seq_params.max_num_ref_frames = 2; // TODO: configure
    seq_params.pic_width_in_mbs_minus1 = (width_mbaligned / 16) - 1;
    seq_params.pic_height_in_map_units_minus1 = (height_mbaligned / 16) - 1;
    seq_params.flags.set_frame_mbs_only_flag(1);
    seq_params.flags.set_direct_8x8_inference_flag(1);
    seq_params.flags.set_vui_parameters_present_flag(0);

    if width != width_mbaligned || height != height_mbaligned {
        seq_params.flags.set_frame_cropping_flag(1);

        seq_params.frame_crop_right_offset = (width_mbaligned - width) / 2;
        seq_params.frame_crop_bottom_offset = (height_mbaligned - height) / 2;
    }

    let mut pic_params: vk::native::StdVideoH264PictureParameterSet = zeroed();
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
        .video_session(video_session.video_session())
        .push(&mut video_encode_h264_session_parameters_create_info);

    VideoSessionParameters::create(video_session, &video_session_parameters_create_info).unwrap()
}

unsafe fn get_video_format_properties(
    instance: &Instance,
    physical_device: vk::PhysicalDevice,
    video_profile_info: vk::VideoProfileInfoKHR<'_>,
) -> Vec<vk::VideoFormatPropertiesKHR<'static>> {
    let profiles = [video_profile_info];
    let mut video_profile_list_info = vk::VideoProfileListInfoKHR::default().profiles(&profiles);
    let physical_device_video_format_info = vk::PhysicalDeviceVideoFormatInfoKHR::default()
        .image_usage(vk::ImageUsageFlags::VIDEO_ENCODE_SRC_KHR)
        .push(&mut video_profile_list_info);

    let len = instance
        .video_queue_instance()
        .get_physical_device_video_format_properties_len(
            physical_device,
            &physical_device_video_format_info,
        )
        .unwrap();

    let mut video_format_properties = vec![vk::VideoFormatPropertiesKHR::default(); len];
    instance
        .video_queue_instance()
        .get_physical_device_video_format_properties(
            physical_device,
            &physical_device_video_format_info,
            video_format_properties.as_mut_slice(),
        )
        .unwrap();

    dbg!(video_format_properties)
}

unsafe fn get_video_capabilities(
    instance: &Instance,
    physical_device: vk::PhysicalDevice,
    video_profile_info: vk::VideoProfileInfoKHR<'_>,
) -> (
    vk::VideoCapabilitiesKHR<'static>,
    vk::VideoEncodeCapabilitiesKHR<'static>,
    vk::VideoEncodeH264CapabilitiesKHR<'static>,
) {
    let mut h264_caps = vk::VideoEncodeH264CapabilitiesKHR::default();
    let mut encode_caps = vk::VideoEncodeCapabilitiesKHR {
        p_next: (&raw mut h264_caps).cast(),
        ..Default::default()
    };
    let mut caps = vk::VideoCapabilitiesKHR {
        p_next: (&raw mut encode_caps).cast(),
        ..Default::default()
    };

    instance
        .video_queue_instance()
        .get_physical_device_video_capabilities(physical_device, &video_profile_info, &mut caps)
        .unwrap();

    caps.p_next = null_mut();
    encode_caps.p_next = null_mut();
    h264_caps.p_next = null_mut();

    (caps, encode_caps, h264_caps)
}

fn map_profile(profile: Profile) -> Option<vk::native::StdVideoH264ProfileIdc> {
    match profile {
        Profile::Baseline => {
            Some(vk::native::StdVideoH264ProfileIdc_STD_VIDEO_H264_PROFILE_IDC_BASELINE)
        }
        Profile::ConstrainedBaseline => None,
        Profile::Main => Some(vk::native::StdVideoH264ProfileIdc_STD_VIDEO_H264_PROFILE_IDC_MAIN),
        Profile::Extended => None,
        Profile::High => Some(vk::native::StdVideoH264ProfileIdc_STD_VIDEO_H264_PROFILE_IDC_HIGH),
        Profile::High10 => Some(vk::native::StdVideoH264ProfileIdc_STD_VIDEO_H264_PROFILE_IDC_HIGH),
        Profile::High422 => {
            Some(vk::native::StdVideoH264ProfileIdc_STD_VIDEO_H264_PROFILE_IDC_HIGH)
        }
        Profile::High444Predictive => {
            Some(vk::native::StdVideoH264ProfileIdc_STD_VIDEO_H264_PROFILE_IDC_HIGH_444_PREDICTIVE)
        }
        Profile::High10Intra => {
            Some(vk::native::StdVideoH264ProfileIdc_STD_VIDEO_H264_PROFILE_IDC_HIGH)
        }
        Profile::High422Intra => {
            Some(vk::native::StdVideoH264ProfileIdc_STD_VIDEO_H264_PROFILE_IDC_HIGH)
        }
        Profile::High444Intra => {
            Some(vk::native::StdVideoH264ProfileIdc_STD_VIDEO_H264_PROFILE_IDC_HIGH)
        }
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

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::time::Instant;

    use super::*;
    use crate::encoder::config::{
        H264EncodeContentHint, H264EncodeTuningHint, H264EncodeUsageHint,
    };
    use crate::encoder::{H264FramePattern, H264RateControlConfig};
    use ezk_image::resize::{FilterType, ResizeAlg};
    use ezk_image::{
        ColorInfo, ColorPrimaries, ColorSpace, ColorTransfer, PixelFormat, YuvColorInfo,
    };
    use scap::frame::Frame;

    #[test]
    fn bb() {
        unsafe {
            env_logger::init();

            let mut encoder = VkH264Encoder::new(H264EncoderConfig {
                profile: crate::Profile::High,
                level: crate::Level::Level_4_2,
                resolution: (1920, 1080),
                framerate: None,
                qp: None,
                frame_pattern: H264FramePattern {
                    intra_idr_period: 120,
                    intra_period: 120,
                    ip_period: 4,
                },
                rate_control: H264RateControlConfig::ConstantBitRate { bitrate: 320_000 },
                usage_hint: H264EncodeUsageHint::Default,
                content_hint: H264EncodeContentHint::Default,
                tuning_hint: H264EncodeTuningHint::Default,
                max_slice_len: None,
            })
            .unwrap();

            if scap::has_permission() {
                scap::request_permission();
            }

            let mut resizer =
                ezk_image::resize::Resizer::new(ResizeAlg::Convolution(FilterType::Bilinear));

            let mut capturer = scap::capturer::Capturer::build(scap::capturer::Options {
                fps: 60,
                ..Default::default()
            })
            .unwrap();

            capturer.start_capture();

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

            let mut file = OpenOptions::new()
                .truncate(true)
                .create(true)
                .write(true)
                .open("vk.h264")
                .unwrap();

            let mut i = 0;
            while let Ok(frame) = capturer.get_next_frame() {
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

                let nv12 = match nv12.buffer() {
                    ezk_image::BufferKind::Whole(buf) => buf,
                    ezk_image::BufferKind::Split(..) => unreachable!(),
                };

                let now: Instant = Instant::now();

                encoder.encode_frame(nv12);

                println!("Took: {:?}", now.elapsed());
                while let Some(buf) = encoder.wait_result() {
                    file.write_all(&buf).unwrap();
                }
            }

            while let Some(buf) = encoder.wait_result() {
                file.write_all(&buf).unwrap();
            }
            std::mem::forget(encoder);
        }
    }
}
