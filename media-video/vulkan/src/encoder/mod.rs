use crate::{
    Buffer, CommandBuffer, Fence, ImageView, RecordingCommandBuffer, Semaphore,
    VideoFeedbackQueryPool, VideoSession, VideoSessionParameters, VulkanError,
    encoder::{
        codec::VulkanEncCodec,
        input::{Input, InputData, InputPixelFormat},
    },
    image::ImageMemoryBarrier,
};
use ash::vk;
use ezk_image::{ColorInfo, ColorSpace, ImageRef, PixelFormat, YuvColorInfo};
use smallvec::SmallVec;
use std::{collections::VecDeque, pin::Pin};

pub mod capabilities;
pub mod codec;
pub mod input;

#[derive(Debug, thiserror::Error)]
pub enum VulkanEncodeFrameError {
    #[error(
        "Input image is larger than the configured maximum size, got={got:?} maximum={maximum:?} "
    )]
    InputExtentTooLarge { got: [u32; 2], maximum: [u32; 2] },

    #[error("Invalid input type, expected: {expected}")]
    InvalidInputType { expected: &'static str },

    #[error(transparent)]
    Other(#[from] VulkanError),
}

// Configuration for [`VulkanEncoder`] set by a codec implementation
#[derive(Debug)]
pub struct VulkanEncoderImplConfig {
    /// Configuration provided by the user of a encoder
    pub user: VulkanEncoderConfig,

    /// Number of encode slots.
    ///
    /// Must be at least 1 or number of out of order frames + 1.
    ///
    /// E.g. H.264 uses B-Frames specified by an `ip_interval` where `num_encode_slots` must be at least `ip_interval + 1`
    pub num_encode_slots: u32,

    /// Maximum number of active reference kept by the encoder
    pub max_active_references: u32,

    /// Number of DPB slots
    pub num_dpb_slots: u32,
}

// Configuration for [`VulkanEncoder`] set by the user of a encoder
#[derive(Debug, Clone, Copy)]
pub struct VulkanEncoderConfig {
    /// Maximum resolution of the encoded video
    pub max_encode_resolution: vk::Extent2D,

    /// The initial resolution of the encoded video
    pub initial_encode_resolution: vk::Extent2D,

    /// Set the maximum input resolution. Input is always resized to fit the current encoder resolution.
    pub max_input_resolution: vk::Extent2D,

    /// Input is a a new vulkan image set for every frame, instead of using a staging buffer to copy image data from
    /// the host memory.
    pub input_as_vulkan_image: bool,

    /// Pixel format of the input, cannot be changed later.
    pub input_pixel_format: InputPixelFormat,

    /// Vulkan encoder usage flags, zero or more bits can be set
    pub usage_hints: vk::VideoEncodeUsageFlagsKHR,

    /// Vulkan encoder content flags, zero or more bits can be set
    pub content_hints: vk::VideoEncodeContentFlagsKHR,

    /// Vulkan tuning mode can be set to value
    pub tuning_mode: vk::VideoEncodeTuningModeKHR,
}

#[derive(Debug)]
pub struct VulkanEncoder<C: VulkanEncCodec> {
    max_input_extent: vk::Extent2D,
    max_encode_extent: vk::Extent2D,
    current_encode_extent: vk::Extent2D,

    output_buffer_size: u64,

    video_session: VideoSession,
    video_session_parameters: VideoSessionParameters,
    video_session_is_uninitialized: bool,

    video_feedback_query_pool: VideoFeedbackQueryPool,

    graphics_queue_family_index: u32,
    graphics_queue: vk::Queue,

    // Data required when there's a dedicated encode queue
    separate_queue_data: Option<VulkanEncoderSeparateQueueData>,

    // boxed so pointers in structures are stable
    current_rc: Option<Pin<Box<RateControlInfos<C>>>>,
    next_rc: Option<Pin<Box<RateControlInfos<C>>>>,

    encode_slots: Vec<VulkanEncodeSlot>,
    in_flight: VecDeque<VulkanEncodeSlot>,

    dpb_slots: Vec<DpbSlot<C>>,

    output: VecDeque<Vec<u8>>,
}

#[derive(Debug)]
struct VulkanEncoderSeparateQueueData {
    encode_queue_family_index: u32,
    encode_queue: vk::Queue,
}

#[derive(Debug)]
pub struct VulkanEncodeSlot {
    /// Index used for the video feedback query pool
    index: u32,

    emit_parameters: bool,

    input: input::Input,

    output_buffer: Buffer,

    command_buffer: CommandBuffer,

    // Data required when there's a dedicated encode queue
    separate_queue_data: Option<VulkanEncodeSlotSeparateQueueData>,

    completion_fence: Fence,
}

#[derive(Debug)]
struct VulkanEncodeSlotSeparateQueueData {
    semaphore: Semaphore,
    command_buffer: CommandBuffer,
}

#[derive(Debug)]
struct DpbSlot<C: VulkanEncCodec> {
    image_view: ImageView,
    std_reference_info: C::StdReferenceInfo,
}

impl<C: VulkanEncCodec> VulkanEncoder<C> {
    /// Maximum configured extent, cannot be changed without re-creating the encoder
    pub fn max_extent(&self) -> vk::Extent2D {
        self.max_encode_extent
    }

    /// The extent the encoder is currently configured for, input must match this exactly, to change the current extent
    /// see [`Self::update_current_extent`]
    pub fn current_extent(&self) -> vk::Extent2D {
        self.current_encode_extent
    }

    /// Set the new extent of the encoder and updates vulkan's VideoSessionParameters. The given `parameters` must
    /// match the given `extent`.
    ///
    /// # Panics
    ///
    /// If the given extent is larger than [`Self::max_extent`]
    pub fn update_current_extent(
        &mut self,
        extent: vk::Extent2D,
        mut parameters: C::ParametersAddInfo<'_>,
    ) -> Result<(), VulkanError> {
        assert!(extent.width <= self.max_encode_extent.width);
        assert!(extent.height <= self.max_encode_extent.height);

        self.current_encode_extent = extent;

        self.video_session_parameters.update(&mut parameters)?;

        Ok(())
    }

    /// Update the current rate control settings
    ///
    /// # Safety
    ///
    /// 1. [`RateControlInfos`] is self referential and all pointers must be valid until the whole thing is dropped
    /// 2. [`RateControlInfos`] must contain valid parameters for the session
    pub unsafe fn update_rc(&mut self, rate_control: Pin<Box<RateControlInfos<C>>>) {
        self.next_rc = Some(rate_control);
    }

    fn wait_encode_slot(&mut self, encode_slot: &mut VulkanEncodeSlot) -> Result<(), VulkanError> {
        encode_slot.completion_fence.wait(u64::MAX)?;
        encode_slot.completion_fence.reset()?;

        Ok(())
    }

    fn read_out_encode_slot(
        &mut self,
        encode_slot: &mut VulkanEncodeSlot,
    ) -> Result<(), VulkanError> {
        if encode_slot.emit_parameters {
            let parameters =
                C::get_encoded_video_session_parameters(&self.video_session_parameters);

            self.output.push_back(parameters);
        }

        unsafe {
            let bytes_written = self
                .video_feedback_query_pool
                .get_bytes_written(encode_slot.index)?;

            let mapped_buffer = encode_slot.output_buffer.map(bytes_written as usize)?;

            self.output.push_back(mapped_buffer.data().to_vec());
        }

        encode_slot.input.drop_borrowed_resources();

        Ok(())
    }

    /// Try to get an available encode slot for a new frame, if this ever returns `Ok(None)` the encoder was not properly
    /// configured for the use case
    /// (e.g. if the number of B-Frames used is larger than the number of available encode slots)
    pub fn pop_encode_slot(&mut self) -> Result<Option<VulkanEncodeSlot>, VulkanError> {
        if let Some(encode_slot) = self.encode_slots.pop() {
            return Ok(Some(encode_slot));
        }

        let Some(mut encode_slot) = self.in_flight.pop_front() else {
            return Ok(None);
        };

        self.wait_encode_slot(&mut encode_slot)?;
        self.read_out_encode_slot(&mut encode_slot)?;

        Ok(Some(encode_slot))
    }

    /// Poll for encoder results, returns `None` immediately if there's no in-flight encodings or all of them are still
    /// in progress.
    pub fn poll_result(&mut self) -> Result<Option<Vec<u8>>, VulkanError> {
        if let Some(output) = self.output.pop_front() {
            return Ok(Some(output));
        }

        if let Some(encode_slot) = self.in_flight.front_mut() {
            let completed = encode_slot.completion_fence.wait(0)?;
            if !completed {
                return Ok(None);
            }

            encode_slot.completion_fence.reset()?;

            let mut encode_slot = self
                .in_flight
                .pop_front()
                .expect("just peeked with front_mut");

            self.read_out_encode_slot(&mut encode_slot)?;
            self.encode_slots.push(encode_slot);
        }

        Ok(self.output.pop_front())
    }

    /// Blocks until an encoding slot has finished, returns `None` if no slots are in-flight.
    pub fn wait_result(&mut self) -> Result<Option<Vec<u8>>, VulkanError> {
        if let Some(output) = self.output.pop_front() {
            return Ok(Some(output));
        }

        if let Some(mut encode_slot) = self.in_flight.pop_front() {
            self.wait_encode_slot(&mut encode_slot)?;
            self.read_out_encode_slot(&mut encode_slot)?;
            self.encode_slots.push(encode_slot);
        }

        Ok(self.output.pop_front())
    }

    /// Set the input image of an encode slot
    pub fn set_input_of_encode_slot(
        &mut self,
        encode_slot: &mut VulkanEncodeSlot,
        input_data: InputData<'_>,
    ) -> Result<(), VulkanEncodeFrameError> {
        let width = input_data.extent().width;
        let height = input_data.extent().height;

        if width > self.max_input_extent.width || height > self.max_input_extent.height {
            return Err(VulkanEncodeFrameError::InputExtentTooLarge {
                got: [width, height],
                maximum: [self.max_input_extent.width, self.max_input_extent.height],
            });
        }

        match input_data {
            InputData::Image(image) => self.copy_image_to_encode_slot(encode_slot, image),
            InputData::VulkanImage(vulkan_image_input) => match &mut encode_slot.input {
                Input::ImportedRGBA { rgb_image, .. } => {
                    *rgb_image = Some(vulkan_image_input);
                    Ok(())
                }
                _ => Err(VulkanEncodeFrameError::InvalidInputType {
                    expected: "InputData::Image",
                }),
            },
        }
    }

    fn copy_image_to_encode_slot(
        &mut self,
        encode_slot: &mut VulkanEncodeSlot,
        image: &dyn ImageRef,
    ) -> Result<(), VulkanEncodeFrameError> {
        let (dst_format, staging_buffer) = match &mut encode_slot.input {
            Input::HostNV12 { staging_buffer, .. } => (PixelFormat::NV12, staging_buffer),
            Input::HostRGBA {
                staging_buffer,
                staging_extent,
                ..
            } => {
                *staging_extent = Some(vk::Extent2D {
                    width: image.width() as u32,
                    height: image.height() as u32,
                });

                (PixelFormat::RGBA, staging_buffer)
            }
            _ => {
                return Err(VulkanEncodeFrameError::InvalidInputType {
                    expected: "InputData::Image",
                });
            }
        };

        let mut mapped_buffer = staging_buffer.map(staging_buffer.capacity())?;

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
            dst_format,
            mapped_buffer.data_mut(),
            None,
            image.width(),
            image.height(),
            dst_color.into(),
        )
        .unwrap();

        ezk_image::convert_multi_thread(image, &mut dst).unwrap();

        drop(mapped_buffer);

        Ok(())
    }

    /// Submit an slot to be encoded
    pub fn submit_encode_slot(
        &mut self,
        mut encode_slot: VulkanEncodeSlot,
        reference_indices: SmallVec<[usize; 8]>,
        setup_reference: usize,
        setup_std_reference_info: C::StdReferenceInfo,
        picture_info: C::PictureInfo<'_>,
        emit_parameters: bool,
    ) -> Result<(), VulkanError> {
        encode_slot.emit_parameters = emit_parameters;

        log::trace!(
            "Submit encode slot: references: {reference_indices:?}, setup_reference: {setup_reference}, emit_parameters: {emit_parameters}"
        );

        unsafe {
            let mut recording = encode_slot
                .command_buffer
                .begin(&vk::CommandBufferBeginInfo::default())?;

            let encode_queue_family_index = self
                .separate_queue_data
                .as_ref()
                .map(|x| x.encode_queue_family_index)
                .unwrap_or(self.graphics_queue_family_index);

            encode_slot.input.prepare_input_image(
                self.video_session.device(),
                self.graphics_queue_family_index,
                encode_queue_family_index,
                &recording,
                self.current_encode_extent,
            )?;

            // When using a separate queue release the ownership and submit the first queue
            if let Some(slot_separate_queue_data) = &encode_slot.separate_queue_data {
                recording.end()?;

                let mut wait_semaphores = smallvec::smallvec![];
                let mut signal_semaphores = smallvec::smallvec![
                    vk::SemaphoreSubmitInfo::default()
                        .semaphore(slot_separate_queue_data.semaphore.handle())
                        .stage_mask(vk::PipelineStageFlags2::ALL_COMMANDS),
                ];

                let command_buffers = [vk::CommandBufferSubmitInfo::default()
                    .command_buffer(encode_slot.command_buffer.command_buffer())];

                encode_slot.input.submit_graphics_queue_add_semaphores(
                    &mut wait_semaphores,
                    &mut signal_semaphores,
                );

                let submit_info = vk::SubmitInfo2::default()
                    .command_buffer_infos(&command_buffers)
                    .wait_semaphore_infos(&wait_semaphores)
                    .signal_semaphore_infos(&signal_semaphores);

                self.video_session.device().ash().queue_submit2(
                    self.graphics_queue,
                    &[submit_info],
                    vk::Fence::null(),
                )?;

                // Begin recording the encode command buffer
                recording = slot_separate_queue_data
                    .command_buffer
                    .begin(&vk::CommandBufferBeginInfo::default())?;
            }

            self.record_encode_queue(
                &encode_slot,
                &recording,
                reference_indices,
                setup_reference,
                setup_std_reference_info,
                picture_info,
            );

            let command_buffer = recording.command_buffer();

            // Finish up everything
            recording.end()?;

            let command_buffer_infos =
                [vk::CommandBufferSubmitInfo::default().command_buffer(command_buffer)];

            let wait_semaphore_infos: SmallVec<[vk::SemaphoreSubmitInfo; 1]> =
                if let Some(slot_separate_queue_data) = &encode_slot.separate_queue_data {
                    smallvec::smallvec![
                        vk::SemaphoreSubmitInfo::default()
                            .semaphore(slot_separate_queue_data.semaphore.handle())
                            .stage_mask(vk::PipelineStageFlags2::ALL_COMMANDS),
                    ]
                } else {
                    smallvec::smallvec![]
                };

            let submit_info = vk::SubmitInfo2::default()
                .command_buffer_infos(&command_buffer_infos)
                .wait_semaphore_infos(&wait_semaphore_infos);

            self.video_session.device().ash().queue_submit2(
                self.separate_queue_data
                    .as_ref()
                    .map(|d| d.encode_queue)
                    .unwrap_or(self.graphics_queue),
                &[submit_info],
                encode_slot.completion_fence.fence(),
            )?;

            self.in_flight.push_back(encode_slot);
        }

        Ok(())
    }

    unsafe fn record_encode_queue(
        &mut self,
        encode_slot: &VulkanEncodeSlot,
        recording: &RecordingCommandBuffer<'_>,
        reference_indices: SmallVec<[usize; 8]>,
        setup_reference_index: usize,
        setup_std_reference_info: C::StdReferenceInfo,
        mut picture_info: C::PictureInfo<'_>,
    ) {
        let device = self.video_session.device();

        // Reset query for this encode
        self.video_feedback_query_pool
            .cmd_reset_query(recording.command_buffer(), encode_slot.index);

        let encode_queue_family_index = self
            .separate_queue_data
            .as_ref()
            .map(|x| x.encode_queue_family_index)
            .unwrap_or(self.graphics_queue_family_index);

        let input_image = encode_slot.input.acquire_input_image(
            self.graphics_queue_family_index,
            encode_queue_family_index,
            recording,
        );

        // Barrier the setup dpb slot
        self.dpb_slots[setup_reference_index].std_reference_info = setup_std_reference_info;
        let setup_reference = &self.dpb_slots[setup_reference_index];

        setup_reference.image_view.image().cmd_memory_barrier(
            recording,
            ImageMemoryBarrier::dst(
                vk::ImageLayout::VIDEO_ENCODE_DPB_KHR,
                vk::PipelineStageFlags2::VIDEO_ENCODE_KHR,
                vk::AccessFlags2::VIDEO_ENCODE_WRITE_KHR,
            ),
            setup_reference
                .image_view
                .subresource_range()
                .base_array_layer,
        );

        let setup_reference_picture_resource_info = vk::VideoPictureResourceInfoKHR::default()
            .image_view_binding(setup_reference.image_view.handle())
            .coded_extent(self.current_encode_extent);
        let mut setup_reference_dpb_slot_info =
            C::slot_info_from_std(&setup_reference.std_reference_info);
        let setup_reference_slot_info = vk::VideoReferenceSlotInfoKHR::default()
            .picture_resource(&setup_reference_picture_resource_info)
            .slot_index(setup_reference_index as i32)
            .push_next(&mut setup_reference_dpb_slot_info);

        // Barrier the active reference dpb slots
        for dpb_slot in &reference_indices {
            let dpb_slot = &self.dpb_slots[*dpb_slot];

            dpb_slot.image_view.image().cmd_memory_barrier(
                recording,
                ImageMemoryBarrier::dst(
                    vk::ImageLayout::VIDEO_ENCODE_DPB_KHR,
                    vk::PipelineStageFlags2::VIDEO_ENCODE_KHR,
                    vk::AccessFlags2::VIDEO_ENCODE_READ_KHR,
                ),
                setup_reference
                    .image_view
                    .subresource_range()
                    .base_array_layer,
            );
        }

        let mut reference_slots_resources: SmallVec<[_; 8]> = reference_indices
            .iter()
            .map(|index| {
                let slot = &self.dpb_slots[*index];

                let dpb_slot_info = C::slot_info_from_std(&slot.std_reference_info);

                let picture_resource_info = vk::VideoPictureResourceInfoKHR::default()
                    .image_view_binding(slot.image_view.handle())
                    .coded_extent(self.current_encode_extent);

                (*index, picture_resource_info, dpb_slot_info)
            })
            .collect();

        let mut reference_slots: SmallVec<[_; 8]> = reference_slots_resources
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
            "Begin reference_slots: {:?}",
            reference_slots
                .iter()
                .map(|slot| slot.slot_index)
                .collect::<SmallVec<[_; 8]>>()
        );

        let mut begin_info = vk::VideoBeginCodingInfoKHR::default()
            .video_session(self.video_session.video_session())
            .video_session_parameters(self.video_session_parameters.video_session_parameters())
            .reference_slots(&reference_slots);

        if let Some(rc) = &self.current_rc {
            begin_info.p_next = (&raw const rc.info).cast();
        }

        // Issue the begin video coding command
        let cmd_begin_video_coding = device
            .ash_video_queue_device()
            .fp()
            .cmd_begin_video_coding_khr;
        (cmd_begin_video_coding)(recording.command_buffer(), &raw const begin_info);

        if self.video_session_is_uninitialized || self.next_rc.is_some() {
            // Update the rate control configs after begin_video_coding, so the rate control passed reflects the current
            // state of the video session.
            self.current_rc = self.next_rc.take();

            self.control_video_coding(recording, self.video_session_is_uninitialized);

            self.video_session_is_uninitialized = false;
        }

        let src_picture_resource_info = vk::VideoPictureResourceInfoKHR::default()
            .image_view_binding(input_image.handle())
            .coded_offset(vk::Offset2D { x: 0, y: 0 })
            .coded_extent(self.current_encode_extent)
            .base_array_layer(0);

        // Do not include the setup reference in the vk::VideoEncodeInfoKHR::reference_slots
        let _setup_slot = reference_slots.pop();

        let encode_info = vk::VideoEncodeInfoKHR::default()
            .src_picture_resource(src_picture_resource_info)
            .dst_buffer(encode_slot.output_buffer.buffer())
            .dst_buffer_range(self.output_buffer_size)
            .reference_slots(&reference_slots)
            .flags(vk::VideoEncodeFlagsKHR::empty())
            .setup_reference_slot(&setup_reference_slot_info)
            .push_next(&mut picture_info);

        self.video_feedback_query_pool
            .cmd_begin_query(recording.command_buffer(), encode_slot.index);

        let cmd_encode_video = device
            .ash_video_encode_queue_device()
            .fp()
            .cmd_encode_video_khr;
        (cmd_encode_video)(recording.command_buffer(), &raw const encode_info);

        self.video_feedback_query_pool
            .cmd_end_query(recording.command_buffer(), encode_slot.index);

        let end_video_coding_info = vk::VideoEndCodingInfoKHR::default();
        let cmd_end_video_coding = device
            .ash_video_queue_device()
            .fp()
            .cmd_end_video_coding_khr;
        cmd_end_video_coding(recording.command_buffer(), &raw const end_video_coding_info);
    }

    unsafe fn control_video_coding(
        &self,
        command_buffer: &RecordingCommandBuffer<'_>,
        reset: bool,
    ) {
        let mut video_coding_control_info = vk::VideoCodingControlInfoKHR::default();

        if reset {
            video_coding_control_info.flags |= vk::VideoCodingControlFlagsKHR::RESET;
        };

        if let Some(rc) = &self.current_rc {
            video_coding_control_info.flags |= vk::VideoCodingControlFlagsKHR::ENCODE_RATE_CONTROL;
            video_coding_control_info.p_next = (&raw const rc.info).cast();
        }

        let cmd_control_video_coding = self
            .video_session
            .device()
            .ash_video_queue_device()
            .fp()
            .cmd_control_video_coding_khr;

        (cmd_control_video_coding)(
            command_buffer.command_buffer(),
            &raw const video_coding_control_info,
        );
    }
}

impl<C: VulkanEncCodec> Drop for VulkanEncoder<C> {
    fn drop(&mut self) {
        // Wait for all encode operations to complete
        while let Ok(Some(..)) = self.wait_result() {}
    }
}

/// Rate control parameters
///
/// See [`VulkanEncoder::update_rc`]
#[derive(Debug)]
pub struct RateControlInfos<C: VulkanEncCodec> {
    pub codec_layer: C::RateControlLayerInfo<'static>,
    pub layer: vk::VideoEncodeRateControlLayerInfoKHR<'static>,
    pub codec_info: C::RateControlInfo<'static>,
    pub info: vk::VideoEncodeRateControlInfoKHR<'static>,
}
