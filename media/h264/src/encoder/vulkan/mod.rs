use crate::Profile;
use crate::encoder::{FrameType, H264EncoderConfig, H264EncoderState};
use ash::vk::{self, Extent2D, Handle, TaggedStructure};
use std::collections::VecDeque;
use std::error::Error;
use std::mem::{MaybeUninit, transmute, zeroed};
use std::ptr::null_mut;

mod device;
mod instance;

pub use device::Device;
pub use instance::Instance;

const NUM_SLOTS: u32 = 16;

struct EncodeSlot {
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

pub struct VkH264Encoder {
    state: H264EncoderState,

    width: u32,
    height: u32,

    width_mbaligned: u32,
    height_mbaligned: u32,

    device: Device,

    transfer_queue_family_index: u32,
    encode_queue_family_index: u32,

    transfer_queue: vk::Queue,
    encode_queue: vk::Queue,

    video_encode_feedback_query_pool: vk::QueryPool,

    video_session: vk::VideoSessionKHR,
    video_session_parameters: vk::VideoSessionParametersKHR,
    // Contains SPS & PPS NAL units
    encoded_video_session_parameters: Vec<u8>,

    available_encode_slots: Vec<EncodeSlot>,
    in_flight: VecDeque<EncodeSlot>,

    max_dpb_slots: u32,
    max_active_ref_images: u32,
    max_l0_p_ref_images: u32,
    max_l0_b_ref_images: u32,
    max_l1_b_ref_images: u32,

    /// DPB image resource
    ref_image: vk::Image,
    ref_image_memory: vk::DeviceMemory,

    /// Unused reference slots
    available_ref_images: Vec<DpbSlot>,

    /// Active (in use) reference slots
    ///
    /// back contains oldest reference pictures
    /// front contains most recent reference pictures
    active_ref_images: VecDeque<DpbSlot>,

    tmp_bitstream: Vec<u8>,
}

struct DpbSlot {
    slot_index: u32,
    image_view: vk::ImageView,
    h264_reference_info: vk::native::StdVideoEncodeH264ReferenceInfo,
}

impl VkH264Encoder {
    #[allow(unsafe_op_in_unsafe_fn, clippy::missing_safety_doc)]
    pub unsafe fn new(config: H264EncoderConfig) -> Result<Self, Box<dyn Error>> {
        let entry = ash::Entry::load().unwrap();

        let instance = Instance::load(&entry);

        let devices = dbg!(instance.instance().enumerate_physical_devices().unwrap());

        let physical_device = devices[1];

        let physical_device_memory_properties = dbg!(Box::new(
            instance
                .instance()
                .get_physical_device_memory_properties(physical_device)
        ));

        let queue_family_properties = dbg!(
            instance
                .instance()
                .get_physical_device_queue_family_properties(physical_device)
        );

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
        let extensions = [
            c"VK_KHR_sampler_ycbcr_conversion".as_ptr(),
            c"VK_KHR_maintenance1".as_ptr(),
            c"VK_KHR_synchronization2".as_ptr(),
            c"VK_KHR_bind_memory2".as_ptr(),
            c"VK_KHR_get_memory_requirements2".as_ptr(),
            c"VK_KHR_synchronization2".as_ptr(),
            c"VK_KHR_video_queue".as_ptr(),
            c"VK_KHR_video_encode_queue".as_ptr(),
            c"VK_KHR_video_encode_h264".as_ptr(),
        ];

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

        let device = instance.create_device(physical_device, &create_device_info);

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

        let video_session = create_video_session(
            &device,
            video_profile_info,
            &physical_device_memory_properties,
            encode_queue_family_index,
            &video_capabilities.std_header_version,
            video_capabilities.max_active_reference_pictures,
            video_capabilities.max_dpb_slots,
        );

        get_video_format_properties(&instance, physical_device, video_profile_info);

        let video_encode_feedback_query_pool = {
            let mut query_pool_video_encode_feedback_create_info =
                vk::QueryPoolVideoEncodeFeedbackCreateInfoKHR::default().encode_feedback_flags(
                    vk::VideoEncodeFeedbackFlagsKHR::BITSTREAM_BYTES_WRITTEN,
                );

            let mut video_profile_info = video_profile_info;
            let query_create_info = vk::QueryPoolCreateInfo::default()
                .query_type(vk::QueryType::VIDEO_ENCODE_FEEDBACK_KHR)
                .query_count(NUM_SLOTS)
                .extend(&mut video_profile_info)
                .push(&mut query_pool_video_encode_feedback_create_info);

            device
                .device()
                .create_query_pool(&query_create_info, None)
                .unwrap()
        };
        // Create video session parameters

        let (video_session_parameters, encoded_video_session_parameters) =
            create_video_session_parameters(&device, video_session);

        // Create command buffers
        let (transfer_command_pool, mut transfer_command_buffers) =
            create_command_pool(&device, transfer_queue_family_index, NUM_SLOTS);

        let (encode_command_pool, mut encode_command_buffers) =
            create_command_pool(&device, encode_queue_family_index, NUM_SLOTS);

        let (ref_image, ref_image_memory) = create_ref_image(
            &physical_device_memory_properties,
            &device,
            video_profile_info,
            max_dpb_slots,
            config.resolution.0,
            config.resolution.1,
        );

        let mut available_encode_slots = vec![];

        for index in 0..NUM_SLOTS {
            let (input_image, input_image_memory) = create_input_image(
                &physical_device_memory_properties,
                &device,
                video_profile_info,
                config.resolution.0,
                config.resolution.1,
            );

            let input_image_view =
                create_image_view(&device, input_image, vk::ImageAspectFlags::COLOR, 0);

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

            let fence = device
                .device()
                .create_fence(&vk::FenceCreateInfo::default(), None)
                .unwrap();

            available_encode_slots.push(EncodeSlot {
                index,
                input_staging_buffer,
                input_staging_memory,
                input_image,
                input_image_memory,
                input_image_view,
                output_buffer,
                output_memory,
                transfer_semaphore,
                transfer_command_buffer: transfer_command_buffers.pop().unwrap(),
                encode_command_buffer: encode_command_buffers.pop().unwrap(),
                completion_fence: fence,
            });
        }

        let mut available_ref_images = vec![];
        for i in (0..max_dpb_slots).rev() {
            let ref_image_view =
                create_image_view(&device, ref_image, vk::ImageAspectFlags::COLOR, i);
            available_ref_images.push(DpbSlot {
                slot_index: i,
                image_view: ref_image_view,
                h264_reference_info: zeroed(),
            });
        }

        Ok(VkH264Encoder {
            state: H264EncoderState::new(config.frame_pattern),
            width: config.resolution.0,
            height: config.resolution.1,
            width_mbaligned: macro_block_align(config.resolution.0),
            height_mbaligned: macro_block_align(config.resolution.1),
            device,
            transfer_queue_family_index,
            encode_queue_family_index,
            transfer_queue,
            encode_queue,
            video_encode_feedback_query_pool,
            video_session,
            video_session_parameters,
            encoded_video_session_parameters,
            available_encode_slots,
            in_flight: VecDeque::new(),
            max_dpb_slots,
            max_active_ref_images,
            max_l0_p_ref_images,
            max_l0_b_ref_images,
            max_l1_b_ref_images,
            ref_image,
            ref_image_memory,
            available_ref_images,
            active_ref_images: VecDeque::new(),
            tmp_bitstream: vec![],
        })
    }

    #[allow(unsafe_op_in_unsafe_fn, clippy::missing_safety_doc)]
    pub unsafe fn encode_frame(&mut self, yuv_data: &[u8]) {
        let frame_info = self.state.next();

        log::debug!("Encode {frame_info:?}");

        if frame_info.frame_type == FrameType::B {
            todo!("B-Frames not yet implemented");
        }

        if frame_info.frame_type == FrameType::Idr {
            self.tmp_bitstream
                .extend_from_slice(&self.encoded_video_session_parameters);
            self.available_ref_images
                .extend(self.active_ref_images.drain(..));
        }

        let mut encode_slot = if let Some(encode_slot) = self.available_encode_slots.pop() {
            encode_slot
        } else if let Some(encode_slot) = self.in_flight.pop_front() {
            self.device
                .device()
                .wait_for_fences(&[encode_slot.completion_fence], true, 0)
                .unwrap();
            self.device
                .device()
                .reset_fences(&[encode_slot.completion_fence])
                .unwrap();
            encode_slot
        } else {
            panic!("no stages in available_stages & in_flight")
        };

        self.upload_yuv_to_stage(&mut encode_slot, yuv_data);

        // Prepare setup reference image stuff
        let setup_ref_slot = if let Some(slot) = self.available_ref_images.pop() {
            slot
        } else if let Some(slot) = self.active_ref_images.pop_back() {
            slot
        } else {
            unreachable!()
        };

        let setup_ref_image_resource_info = vk::VideoPictureResourceInfoKHR::default()
            .image_view_binding(setup_ref_slot.image_view)
            .coded_extent(Extent2D {
                width: self.width,
                height: self.height,
            });
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
            .slot_index(setup_ref_slot.slot_index as i32)
            .push(&mut setup_ref_image_h264_dpb_slot_info);

        // Prepare active reference images stuff
        let mut active_ref_image_resource_infos: Vec<_> = self
            .active_ref_images
            .iter()
            .take(self.max_active_ref_images as usize)
            .take(self.max_l0_p_ref_images as usize)
            .map(|slot| {
                let h264_dpb_slot_info = vk::VideoEncodeH264DpbSlotInfoKHR::default()
                    .std_reference_info(&slot.h264_reference_info);
                let picture_resource_info = vk::VideoPictureResourceInfoKHR::default()
                    .image_view_binding(slot.image_view)
                    .coded_extent(Extent2D {
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

        // Record TRANSFER queue
        self.device
            .device()
            .begin_command_buffer(
                encode_slot.transfer_command_buffer,
                &vk::CommandBufferBeginInfo::default(),
            )
            .unwrap();

        // Change image type
        transition_image_layout_raw(
            &self.device,
            encode_slot.transfer_command_buffer,
            encode_slot.input_image,
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
            buffer_image_copy(vk::ImageAspectFlags::PLANE_0, self.width, self.height, 0);
        let buffer_image_copy_plane1 = buffer_image_copy(
            vk::ImageAspectFlags::PLANE_1,
            self.width / 2,
            self.height / 2,
            self.width as u64 * self.height as u64,
        );

        self.device.device().cmd_copy_buffer_to_image(
            encode_slot.transfer_command_buffer,
            encode_slot.input_staging_buffer,
            encode_slot.input_image,
            vk::ImageLayout::TRANSFER_DST_OPTIMAL,
            &[buffer_image_copy_plane0, buffer_image_copy_plane1],
        );

        transition_image_layout_raw(
            &self.device,
            encode_slot.transfer_command_buffer,
            encode_slot.input_image,
            vk::ImageLayout::TRANSFER_DST_OPTIMAL,
            vk::ImageLayout::VIDEO_ENCODE_SRC_KHR,
            self.transfer_queue_family_index,
            self.encode_queue_family_index,
            vk::PipelineStageFlags2::TRANSFER,
            vk::AccessFlags2::TRANSFER_WRITE,
            vk::PipelineStageFlags2::NONE,
            vk::AccessFlags2::empty(),
        );

        self.device
            .device()
            .end_command_buffer(encode_slot.transfer_command_buffer)
            .unwrap();

        let signal_semaphores = [encode_slot.transfer_semaphore];
        let submit_info = vk::SubmitInfo::default()
            .command_buffers(std::slice::from_ref(&encode_slot.transfer_command_buffer))
            .signal_semaphores(&signal_semaphores);

        self.device
            .device()
            .queue_submit(self.transfer_queue, &[submit_info], vk::Fence::null())
            .unwrap();

        // Begin recording the encode queue
        self.device
            .device()
            .begin_command_buffer(
                encode_slot.encode_command_buffer,
                &vk::CommandBufferBeginInfo::default(),
            )
            .unwrap();

        // Reset query for this encode
        self.device.device().cmd_reset_query_pool(
            encode_slot.encode_command_buffer,
            self.video_encode_feedback_query_pool,
            encode_slot.index,
            1,
        );

        transition_image_layout_raw(
            &self.device,
            encode_slot.encode_command_buffer,
            encode_slot.input_image,
            vk::ImageLayout::VIDEO_ENCODE_SRC_KHR,
            vk::ImageLayout::VIDEO_ENCODE_SRC_KHR,
            self.transfer_queue_family_index,
            self.encode_queue_family_index,
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
            .video_session(self.video_session)
            .video_session_parameters(self.video_session_parameters)
            .reference_slots(&use_reference_slots);

        // Issue the begin video coding command
        self.device
            .video_queue_device()
            .cmd_begin_video_coding(encode_slot.encode_command_buffer, &begin_info);

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

            self.device.video_queue_device().cmd_control_video_coding(
                encode_slot.encode_command_buffer,
                &video_coding_control_info,
            );
        }

        let src_picture_resource_plane0 = vk::VideoPictureResourceInfoKHR::default()
            .image_view_binding(encode_slot.input_image_view)
            .coded_offset(vk::Offset2D { x: 0, y: 0 })
            .coded_extent(vk::Extent2D {
                width: self.width,
                height: self.height,
            })
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
            .dst_buffer(encode_slot.output_buffer)
            .dst_buffer_range(1024 * 1024) // TOD: actually use the value here of the buffer
            .reference_slots(&active_ref_image_slot_infos)
            .flags(vk::VideoEncodeFlagsKHR::empty())
            .setup_reference_slot(&setup_ref_image_slot_info)
            .push(&mut h264_encode_info);

        self.device.device().cmd_begin_query(
            encode_slot.encode_command_buffer,
            self.video_encode_feedback_query_pool,
            encode_slot.index,
            vk::QueryControlFlags::empty(),
        );

        self.device
            .video_encode_queue_device()
            .cmd_encode_video(encode_slot.encode_command_buffer, &encode_info);

        self.device.device().cmd_end_query(
            encode_slot.encode_command_buffer,
            self.video_encode_feedback_query_pool,
            encode_slot.index,
        );

        self.device.video_queue_device().cmd_end_video_coding(
            encode_slot.encode_command_buffer,
            &vk::VideoEndCodingInfoKHR::default(),
        );

        // Finish up everything
        self.device
            .device()
            .end_command_buffer(encode_slot.encode_command_buffer)
            .unwrap();

        let command_buffer_infos = [vk::CommandBufferSubmitInfo::default()
            .command_buffer(encode_slot.encode_command_buffer)];
        let wait_semaphore_infos = [vk::SemaphoreSubmitInfo::default()
            .semaphore(encode_slot.transfer_semaphore)
            .stage_mask(vk::PipelineStageFlags2::VIDEO_ENCODE_KHR)];
        let submit_info = vk::SubmitInfo2::default()
            .command_buffer_infos(&command_buffer_infos)
            .wait_semaphore_infos(&wait_semaphore_infos);
        self.device
            .device()
            .queue_submit2(
                self.encode_queue,
                &[submit_info],
                encode_slot.completion_fence,
            )
            .unwrap();

        self.device
            .device()
            .queue_wait_idle(self.encode_queue)
            .unwrap();

        let mut bytes_written = [[0u64; 2]; 1];
        self.device
            .device()
            .get_query_pool_results(
                self.video_encode_feedback_query_pool,
                encode_slot.index,
                &mut bytes_written,
                vk::QueryResultFlags::TYPE_64 | vk::QueryResultFlags::WAIT,
            )
            .unwrap();

        println!("Bytes written: {:?}", bytes_written);

        let output = self
            .device
            .device()
            .map_memory(
                encode_slot.output_memory,
                0,
                1024 * 1024,
                vk::MemoryMapFlags::empty(),
            )
            .unwrap();

        {
            let output = std::slice::from_raw_parts(
                output.cast::<u8>(),
                bytes_written[0][1].try_into().unwrap(),
            );

            println!("H.264 Output: {:?}", &output[..32]);

            self.tmp_bitstream.extend(output);
        }

        self.device.device().unmap_memory(encode_slot.output_memory);

        self.active_ref_images.push_front(setup_ref_slot);
        self.in_flight.push_back(encode_slot);
    }

    unsafe fn upload_yuv_to_stage(&mut self, stage: &mut EncodeSlot, yuv_data: &[u8]) {
        let data_ptr = self
            .device
            .device()
            .map_memory(
                stage.input_staging_memory,
                0,
                yuv_data.len() as u64,
                vk::MemoryMapFlags::empty(),
            )
            .unwrap();

        println!("Staging pointer: {data_ptr:p}");
        std::ptr::copy_nonoverlapping(yuv_data.as_ptr(), data_ptr as *mut u8, yuv_data.len());
        self.device
            .device()
            .unmap_memory(stage.input_staging_memory);
    }
}

unsafe fn create_command_pool(
    device: &Device,
    encode_queue_family_index: u32,
    command_buffer_count: u32,
) -> (vk::CommandPool, Vec<vk::CommandBuffer>) {
    let command_pool_create_info = vk::CommandPoolCreateInfo::default()
        .queue_family_index(encode_queue_family_index)
        .flags(vk::CommandPoolCreateFlags::RESET_COMMAND_BUFFER);
    let command_pool = device
        .device()
        .create_command_pool(&command_pool_create_info, None)
        .unwrap();

    let command_buffer_create_info = vk::CommandBufferAllocateInfo::default()
        .command_buffer_count(command_buffer_count)
        .command_pool(command_pool)
        .level(vk::CommandBufferLevel::PRIMARY);

    let command_buffers = device
        .device()
        .allocate_command_buffers(&command_buffer_create_info)
        .unwrap();

    (command_pool, command_buffers)
}

unsafe fn create_image_view(
    device: &Device,
    input_image: vk::Image,
    aspect_mask: vk::ImageAspectFlags,
    array_layer: u32,
) -> vk::ImageView {
    let image_view_create_info = vk::ImageViewCreateInfo::default()
        .image(input_image)
        .view_type(vk::ImageViewType::TYPE_2D)
        .format(vk::Format::G8_B8R8_2PLANE_420_UNORM)
        .components(vk::ComponentMapping::default())
        .subresource_range(vk::ImageSubresourceRange {
            aspect_mask,
            base_mip_level: 0,
            level_count: 1,
            base_array_layer: array_layer,
            layer_count: 1,
        });

    device
        .device()
        .create_image_view(&image_view_create_info, None)
        .unwrap()
}

#[allow(clippy::too_many_arguments)]
unsafe fn transition_image_layout_raw(
    device: &Device,
    command_buffer: vk::CommandBuffer,

    input_image: vk::Image,

    old_layout: vk::ImageLayout,
    new_layout: vk::ImageLayout,

    src_queue_family_index: u32,
    dst_queue_family_index: u32,

    src_stage_mask: vk::PipelineStageFlags2,
    src_access_mask: vk::AccessFlags2,

    dst_stage_mask: vk::PipelineStageFlags2,
    dst_access_mask: vk::AccessFlags2,
) {
    let barrier = vk::ImageMemoryBarrier2::default()
        .image(input_image)
        .old_layout(old_layout)
        .new_layout(new_layout)
        .src_queue_family_index(src_queue_family_index)
        .dst_queue_family_index(dst_queue_family_index)
        .src_stage_mask(src_stage_mask)
        .src_access_mask(src_access_mask)
        .dst_stage_mask(dst_stage_mask)
        .dst_access_mask(dst_access_mask)
        .subresource_range(vk::ImageSubresourceRange {
            aspect_mask: vk::ImageAspectFlags::COLOR,
            base_mip_level: 0,
            level_count: 1,
            base_array_layer: 0,
            layer_count: 1,
        });

    let barriers = [barrier];
    let dependency_info = vk::DependencyInfoKHR::default().image_memory_barriers(&barriers);

    device
        .device()
        .cmd_pipeline_barrier2(command_buffer, &dependency_info);
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
            find_memory_type(
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
            find_memory_type(
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

unsafe fn create_ref_image(
    physical_device_memory_properties: &vk::PhysicalDeviceMemoryProperties,
    device: &Device,
    video_profile_info: vk::VideoProfileInfoKHR<'_>,
    num_dpb_entries: u32,
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
        .array_layers(num_dpb_entries)
        .tiling(vk::ImageTiling::OPTIMAL)
        .sharing_mode(vk::SharingMode::EXCLUSIVE)
        .initial_layout(vk::ImageLayout::UNDEFINED)
        .samples(vk::SampleCountFlags::TYPE_1)
        .usage(vk::ImageUsageFlags::VIDEO_ENCODE_DPB_KHR)
        .push(&mut video_profile_list_info);

    let image = device
        .device()
        .create_image(&input_image_info, None)
        .unwrap();
    let memory_requirements = device.device().get_image_memory_requirements(image);

    let alloc_info = vk::MemoryAllocateInfo::default()
        .allocation_size(memory_requirements.size)
        .memory_type_index(
            find_memory_type(
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
            find_memory_type(
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

unsafe fn create_video_session_parameters(
    device: &Device,
    video_session: vk::VideoSessionKHR,
) -> (vk::VideoSessionParametersKHR, Vec<u8>) {
    let mut seq_params: vk::native::StdVideoH264SequenceParameterSet = zeroed();
    seq_params.profile_idc = vk::native::StdVideoH264ProfileIdc_STD_VIDEO_H264_PROFILE_IDC_HIGH;
    seq_params.level_idc = vk::native::StdVideoH264LevelIdc_STD_VIDEO_H264_LEVEL_IDC_4_2;
    seq_params.chroma_format_idc =
        vk::native::StdVideoH264ChromaFormatIdc_STD_VIDEO_H264_CHROMA_FORMAT_IDC_420;

    seq_params.log2_max_frame_num_minus4 = 16 - 4;
    seq_params.log2_max_pic_order_cnt_lsb_minus4 = 16 - 4; // TODO: calculate
    seq_params.max_num_ref_frames = 2; // TODO: configure
    seq_params.pic_width_in_mbs_minus1 = (macro_block_align(1920) / 16) - 1;
    seq_params.pic_height_in_map_units_minus1 = (macro_block_align(1080) / 16) - 1;
    seq_params.flags.set_frame_mbs_only_flag(1);
    seq_params.flags.set_direct_8x8_inference_flag(1);
    seq_params.flags.set_frame_cropping_flag(1);
    seq_params.flags.set_vui_parameters_present_flag(0);

    seq_params.frame_crop_right_offset = 8;

    let mut pic_params: vk::native::StdVideoH264PictureParameterSet = zeroed();
    // pic_params.weighted_bipred_idc =
    //     vk::native::StdVideoH264WeightedBipredIdc_STD_VIDEO_H264_WEIGHTED_BIPRED_IDC_INVALID;
    pic_params
        .flags
        .set_deblocking_filter_control_present_flag(1);
    pic_params.flags.set_entropy_coding_mode_flag(0);

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
        .video_session(video_session)
        .push(&mut video_encode_h264_session_parameters_create_info);

    let video_session_parameters = device
        .video_queue_device()
        .create_video_session_parameters(&video_session_parameters_create_info, None)
        .unwrap();

    // Get the encoded parameters
    let mut h264_get_encoded_params = vk::VideoEncodeH264SessionParametersGetInfoKHR::default()
        .write_std_sps(true)
        .write_std_pps(true);
    let get_encoded_params = vk::VideoEncodeSessionParametersGetInfoKHR::default()
        .video_session_parameters(video_session_parameters)
        .push(&mut h264_get_encoded_params);
    let len = device
        .video_encode_queue_device()
        .get_encoded_video_session_parameters_len(&get_encoded_params, None)
        .unwrap();
    let mut buf = vec![MaybeUninit::new(0); len];
    device
        .video_encode_queue_device()
        .get_encoded_video_session_parameters(&get_encoded_params, None, &mut buf)
        .unwrap();
    let encoded_video_session_parameters = transmute::<Vec<MaybeUninit<u8>>, Vec<u8>>(buf);

    println!("SPS/PPS: {encoded_video_session_parameters:?}");

    (video_session_parameters, encoded_video_session_parameters)
}

unsafe fn create_video_session(
    device: &Device,
    video_profile_info: vk::VideoProfileInfoKHR<'_>,
    physical_device_memory_properties: &vk::PhysicalDeviceMemoryProperties,
    encode_queue_family_index: u32,
    std_header_version: &vk::ExtensionProperties,
    max_active_reference_pictures: u32,
    max_dpb_slots: u32,
) -> vk::VideoSessionKHR {
    let create_info = vk::VideoSessionCreateInfoKHR::default()
        .max_coded_extent(vk::Extent2D {
            width: 1920,
            height: 1080,
        })
        .queue_family_index(encode_queue_family_index)
        .max_active_reference_pictures(max_active_reference_pictures)
        .max_dpb_slots(max_dpb_slots)
        .picture_format(vk::Format::G8_B8R8_2PLANE_420_UNORM)
        .reference_picture_format(vk::Format::G8_B8R8_2PLANE_420_UNORM)
        .video_profile(&video_profile_info)
        .std_header_version(std_header_version);

    let video_session = device
        .video_queue_device()
        .create_video_session(&create_info, None)
        .unwrap();

    let len = device
        .video_queue_device()
        .get_video_session_memory_requirements_len(video_session)
        .unwrap();

    let mut video_session_memory_requirements =
        vec![vk::VideoSessionMemoryRequirementsKHR::default(); len];

    device
        .video_queue_device()
        .get_video_session_memory_requirements(
            video_session,
            &mut video_session_memory_requirements,
        )
        .unwrap();

    let bind_session_memory_infos: Vec<_> = video_session_memory_requirements
        .iter()
        .map(|video_session_memory_requirement| {
            let memory_type_index = find_memory_type(
                video_session_memory_requirement
                    .memory_requirements
                    .memory_type_bits,
                vk::MemoryPropertyFlags::empty(),
                physical_device_memory_properties,
            )
            .unwrap();

            let allocate_info = vk::MemoryAllocateInfo::default()
                .memory_type_index(memory_type_index)
                .allocation_size(video_session_memory_requirement.memory_requirements.size);

            // TODO: leaking memory big
            let memory = device
                .device()
                .allocate_memory(&allocate_info, None)
                .unwrap();

            vk::BindVideoSessionMemoryInfoKHR::default()
                .memory(memory)
                .memory_bind_index(video_session_memory_requirement.memory_bind_index)
                .memory_size(video_session_memory_requirement.memory_requirements.size)
        })
        .collect();

    device
        .video_queue_device()
        .bind_video_session_memory(video_session, &bind_session_memory_infos)
        .unwrap();

    video_session
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

fn find_memory_type(
    memory_type_bits: u32,
    properties: vk::MemoryPropertyFlags,
    mem_properties: &vk::PhysicalDeviceMemoryProperties,
) -> Option<u32> {
    for (i, memory_type) in mem_properties.memory_types.iter().enumerate() {
        let type_supported = (memory_type_bits & (1 << i)) != 0;
        let has_properties = memory_type.property_flags.contains(properties);
        if type_supported && has_properties {
            return Some(i as u32);
        }
    }
    None
}

fn macro_block_align(v: u32) -> u32 {
    (v + 0xF) & !0xF
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

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::{Level, encoder::FramePattern};
    use ezk_image::resize::{FilterType, ResizeAlg};
    use ezk_image::{
        ColorInfo, ColorPrimaries, ColorSpace, ColorTransfer, ImageRef, PixelFormat, YuvColorInfo,
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
                qp: Some((20, 28)),
                frame_pattern: FramePattern {
                    intra_idr_period: 120,
                    intra_period: 120,
                    ip_period: 1,
                },
                bitrate: Some(6_000_000),
                max_bitrate: Some(6_000_000),
                max_slice_len: None,
            })
            .unwrap();

            if scap::has_permission() {
                scap::request_permission();
            }

            let mut resizer =
                ezk_image::resize::Resizer::new(ResizeAlg::Convolution(FilterType::Bilinear));

            let mut capturer = scap::capturer::Capturer::build(scap::capturer::Options {
                fps: 30,
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

            let mut i = 0;
            let mut last_frame = Instant::now();
            while let Ok(frame) = capturer.get_next_frame() {
                let now = Instant::now();
                println!("Time since last frame: {:?}", now - last_frame);
                last_frame = now;
                i += 1;
                if i > 1000 {
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

                let nv12 = match nv12.buffer() {
                    ezk_image::BufferKind::Whole(buf) => buf,
                    ezk_image::BufferKind::Split(items) => unreachable!(),
                };

                encoder.encode_frame(nv12);

                // while let Some(buf) = encoder.poll_result() {
                //     println!("buf: {:?}", &buf[..8]);
                //     file.write_all(&buf).unwrap();
                // }
            }

            std::fs::write("vk.h264", &encoder.tmp_bitstream).unwrap();
            std::mem::forget(encoder);
        }
    }
}
