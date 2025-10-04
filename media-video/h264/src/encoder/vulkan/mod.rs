use crate::{
    Level, Profile,
    encoder::{
        H264EncoderConfig, H264FrameRate, H264FrameType, H264RateControlConfig,
        util::{FrameEncodeInfo, H264EncoderState, macro_block_align},
    },
};
use std::{
    cmp,
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
        vk::{self, Handle},
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
    video_session_needs_control: bool,
    video_session_is_uninitialized: bool,

    rate_control: Box<RateControl>,

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
    pic_order_cnt: Option<u16>,
    image_view: ImageView,
    h264_reference_info: vk::native::StdVideoEncodeH264ReferenceInfo,
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

        this.info.virtual_buffer_size_in_ms = 100;

        this.layer.p_next = (&raw mut this.h264_layer).cast();
        this.info.p_next = (&raw mut this.h264_info).cast();

        this.info.p_layers = &raw const this.layer;
        this.info.layer_count = 1;

        this
    }

    fn update_from_config(&mut self, config: &H264EncoderConfig) {
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

impl VkH264Encoder {
    #[allow(unsafe_op_in_unsafe_fn, clippy::missing_safety_doc)]
    pub unsafe fn new(config: H264EncoderConfig) -> Result<Self, Box<dyn Error>> {
        let entry = unsafe { Entry::load().unwrap() };

        let instance = Instance::load(&entry).unwrap();

        let devices = dbg!(instance.instance().enumerate_physical_devices().unwrap());

        let physical_device = devices[0];

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
            .push_next(&mut sync2_features_enable);

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
            .push_next(&mut h264_profile_info);

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
            cmp::max(
                max_l0_p_ref_images,
                max_l0_b_ref_images + max_l1_b_ref_images,
            ) as u8,
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
                    .push_next(&mut video_profile_list_info);

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
                    pic_order_cnt: None,
                })
                .rev()
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
            video_session_needs_control: true,
            video_session_is_uninitialized: true,
            rate_control: RateControl::default(),
            available_encode_slots,
            in_flight: VecDeque::new(),
            max_l0_p_ref_images,
            max_l0_b_ref_images,
            max_l1_b_ref_images,
            available_ref_images,
            dpb_in_correct_layout: false,
            active_ref_images: VecDeque::new(),
            backlogged_b_frames: Vec::new(),
            output: VecDeque::new(),
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
                .extend(self.active_ref_images.drain(..).map(|dpb_slot| DpbSlot {
                    pic_order_cnt: None,
                    ..dpb_slot
                }));
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
            setup_reference.pic_order_cnt = Some(frame_info.pic_order_cnt_lsb);

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

        let l0 = self
            .active_ref_images
            .iter()
            .filter(|dpb_slot| dpb_slot.pic_order_cnt.unwrap() < frame_info.pic_order_cnt_lsb);
        let l1 = self
            .active_ref_images
            .iter()
            .rev()
            .filter(|dpb_slot| dpb_slot.pic_order_cnt.unwrap() > frame_info.pic_order_cnt_lsb);

        let (l0, l1) = match frame_info.frame_type {
            H264FrameType::P => (l0.take(self.max_l0_p_ref_images as usize).collect(), vec![]),
            H264FrameType::B => (
                l0.take(self.max_l0_b_ref_images as usize).collect(),
                l1.take(self.max_l1_b_ref_images as usize).collect(),
            ),
            H264FrameType::I | H264FrameType::Idr => (vec![], vec![]),
        };

        for dpb_slot in l0.iter().chain(l1.iter()).chain(Some(&&*setup_reference)) {
            dpb_slot.image_view.image().cmd_memory_barrier2(
                encode_slot.encode_command_buffer.command_buffer(),
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

        let setup_ref_image_resource_info = vk::VideoPictureResourceInfoKHR::default()
            .image_view_binding(setup_reference.image_view.image_view())
            .coded_extent(vk::Extent2D {
                width: self.width,
                height: self.height,
            });

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
            PicOrderCnt: frame_info.pic_order_cnt_lsb.into(),
            long_term_pic_num: 0,
            long_term_frame_idx: 0,
            temporal_id: 0,
        };

        let mut setup_ref_image_h264_dpb_slot_info = vk::VideoEncodeH264DpbSlotInfoKHR::default()
            .std_reference_info(&setup_reference.h264_reference_info);

        let setup_ref_image_slot_info = vk::VideoReferenceSlotInfoKHR::default()
            .picture_resource(&setup_ref_image_resource_info)
            .slot_index(setup_reference.slot_index as i32)
            .push_next(&mut setup_ref_image_h264_dpb_slot_info);

        // Prepare active reference images stuff
        let mut active_ref_image_resource_infos: Vec<_> = l0
            .iter()
            .chain(l1.iter())
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
                    .push_next(h264_dpb_slot)
            })
            .collect();

        // Reset query for this encode
        self.video_feedback_query_pool.cmd_reset_query(
            encode_slot.encode_command_buffer.command_buffer(),
            encode_slot.index,
        );

        // Build the reference slots list for the begin video coding command
        let mut use_reference_slots = active_ref_image_slot_infos.clone();
        let mut use_setup_ref_image_slot_info = setup_ref_image_slot_info;
        // TODO: marking setup slot as not active, validation layers are not complaining but not sure if its correct
        use_setup_ref_image_slot_info.slot_index = -1;
        use_reference_slots.push(use_setup_ref_image_slot_info);

        let mut begin_info = vk::VideoBeginCodingInfoKHR::default()
            .video_session(self.video_session.video_session())
            .video_session_parameters(self.video_session_parameters.video_session_parameters())
            .reference_slots(&use_reference_slots);

        if !self.video_session_is_uninitialized {
            begin_info.p_next = (&raw const self.rate_control.info).cast();
        }

        // Issue the begin video coding command
        let cmd_begin_video_coding = self
            .device
            .video_queue_device()
            .fp()
            .cmd_begin_video_coding_khr;
        (cmd_begin_video_coding)(
            encode_slot.encode_command_buffer.command_buffer(),
            &raw const begin_info,
        );

        if self.video_session_needs_control {
            // Update the rate control configs after begin_video_coding, so the rate control passed reflects the current
            // state of the video session.
            self.rate_control.update_from_config(&self.config);

            self.control_video_coding(encode_slot, self.video_session_is_uninitialized);

            self.video_session_is_uninitialized = false;
            self.video_session_needs_control = false;
        }

        let src_picture_resource_plane0 = vk::VideoPictureResourceInfoKHR::default()
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

        let mut l0_iter = l0.iter().map(|dpb_slot| dpb_slot.slot_index as u8);
        ref_lists
            .RefPicList0
            .fill_with(|| l0_iter.next().unwrap_or(0xFF));

        let mut l1_iter = l1.iter().map(|dpb_slot| dpb_slot.slot_index as u8);
        ref_lists
            .RefPicList1
            .fill_with(|| l1_iter.next().unwrap_or(0xFF));

        ref_lists.num_ref_idx_l0_active_minus1 = l0.len().saturating_sub(1) as u8;
        ref_lists.num_ref_idx_l1_active_minus1 = l1.len().saturating_sub(1) as u8;

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
            PicOrderCnt: frame_info.pic_order_cnt_lsb.into(),
            temporal_id: 0,
            reserved1: [0; 3],
            pRefLists: &raw const ref_lists,
        };

        let mut h264_encode_info = vk::VideoEncodeH264PictureInfoKHR::default()
            .generate_prefix_nalu(false)
            .nalu_slice_entries(&nalu_slices)
            .std_picture_info(&h264_picture_info);

        let encode_info = vk::VideoEncodeInfoKHR::default()
            .src_picture_resource(src_picture_resource_plane0)
            .dst_buffer(encode_slot.output_buffer.buffer())
            .dst_buffer_range(1024 * 1024) // TODO: actually use the value here of the buffer
            .reference_slots(&active_ref_image_slot_infos)
            .flags(vk::VideoEncodeFlagsKHR::empty())
            .setup_reference_slot(&setup_ref_image_slot_info)
            .push_next(&mut h264_encode_info);

        self.video_feedback_query_pool.cmd_begin_query(
            encode_slot.encode_command_buffer.command_buffer(),
            encode_slot.index,
        );

        let cmd_encode_video = self
            .device
            .video_encode_queue_device()
            .fp()
            .cmd_encode_video_khr;
        (cmd_encode_video)(
            encode_slot.encode_command_buffer.command_buffer(),
            &raw const encode_info,
        );

        self.video_feedback_query_pool.cmd_end_query(
            encode_slot.encode_command_buffer.command_buffer(),
            encode_slot.index,
        );

        let end_video_coding_info = vk::VideoEndCodingInfoKHR::default();
        let cmd_end_video_coding = self
            .device
            .video_queue_device()
            .fp()
            .cmd_end_video_coding_khr;
        cmd_end_video_coding(
            encode_slot.encode_command_buffer.command_buffer(),
            &raw const end_video_coding_info,
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

    unsafe fn control_video_coding(&self, encode_slot: &mut EncodeSlot, reset: bool) {
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
            encode_slot.encode_command_buffer.command_buffer(),
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
        .push_next(&mut video_profile_list_info);

    Image::create(device, &create_info).unwrap()
}

#[allow(clippy::too_many_arguments)]
unsafe fn create_video_session_parameters(
    state: &H264EncoderState,
    video_session: &VideoSession,
    width: u32,
    height: u32,
    max_num_ref_frames: u8,
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
        .push_next(&mut video_encode_h264_session_parameters_create_info);

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
        .push_next(&mut video_profile_list_info);

    let get_physical_device_video_format_properties = instance
        .video_queue_instance()
        .fp()
        .get_physical_device_video_format_properties_khr;

    let mut len = 0;
    (get_physical_device_video_format_properties)(
        physical_device,
        &raw const physical_device_video_format_info,
        &raw mut len,
        null_mut(),
    )
    .result()
    .unwrap();

    let mut video_format_properties = vec![vk::VideoFormatPropertiesKHR::default(); len as usize];
    (get_physical_device_video_format_properties)(
        physical_device,
        &raw const physical_device_video_format_info,
        &raw mut len,
        video_format_properties.as_mut_ptr(),
    )
    .result()
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

    let get_physical_device_video_capabilities = instance
        .video_queue_instance()
        .fp()
        .get_physical_device_video_capabilities_khr;

    (get_physical_device_video_capabilities)(
        physical_device,
        &raw const video_profile_info,
        &raw mut caps,
    )
    .result()
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
                rate_control: H264RateControlConfig::ConstantBitRate { bitrate: 6_000_000 },
                usage_hint: H264EncodeUsageHint::Default,
                content_hint: H264EncodeContentHint::Default,
                tuning_hint: H264EncodeTuningHint::Default,
                max_slice_len: None,
            })
            .unwrap();

            let monitors = xcap::Monitor::all().unwrap();

            let monitor = &monitors[0];
            let (rec, receiver) = monitor.video_recorder().unwrap();
            rec.start().unwrap();

            let mut resizer =
                ezk_image::resize::Resizer::new(ResizeAlg::Convolution(FilterType::Bilinear));

            let mut bgrx_target = ezk_image::Image::blank(
                PixelFormat::RGBA,
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
            while i < 500 {
                i += 1;

                let image = receiver.recv().unwrap();

                let bgrx = image.raw;

                let bgrx_original = ezk_image::Image::from_buffer(
                    PixelFormat::RGBA,
                    bgrx,
                    None,
                    image.width as usize,
                    image.height as usize,
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
            }

            while let Some(buf) = encoder.wait_result() {
                file.write_all(&buf).unwrap();
            }
            std::mem::forget(encoder);
        }
    }
}
