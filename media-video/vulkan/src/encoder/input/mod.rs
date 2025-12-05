use crate::{
    Buffer, Device, Image, ImageView, RecordingCommandBuffer, Semaphore, VulkanError,
    encoder::input::rgb_to_nv12::RgbToNV12Converter, image::ImageMemoryBarrier,
};
use ash::vk;
use ezk_image::ImageRef;
use smallvec::SmallVec;

mod rgb_to_nv12;
pub use rgb_to_nv12::Primaries;

#[derive(Debug, Clone, Copy)]
pub enum InputPixelFormat {
    /// 2 Plane YUV with 4:2:0 subsampling
    NV12,
    /// 1 Plane RGBA
    RGBA {
        /// Primaries to use when converting RGB to YUV for encoding
        primaries: Primaries,
    },
}

#[allow(missing_debug_implementations)]
pub enum InputData<'a> {
    /// Host memory image
    Image(&'a dyn ImageRef),

    /// Externally provided vulkan image view
    ///
    /// Must have usage SAMPLED and represent an RGB(A) image
    VulkanImage(VulkanImageInput),
}

#[derive(Debug)]
pub struct VulkanImageInput {
    pub view: ImageView,
    pub extent: vk::Extent2D,

    pub acquire: Option<InputSync>,
    pub release: Option<InputSync>,
}

#[derive(Debug, Clone)]
pub struct InputSync {
    pub semaphore: Semaphore,
    pub timeline_point: Option<u64>,
}

impl InputData<'_> {
    pub fn extent(&self) -> vk::Extent2D {
        match self {
            InputData::Image(image_ref) => vk::Extent2D {
                width: image_ref.width() as u32,
                height: image_ref.height() as u32,
            },
            InputData::VulkanImage(image) => image.extent,
        }
    }
}

/// Encoder input
///
/// NV12 (host-memory) -> staging-buffer -> encode-input-image
/// RGBA (host-memory) -> staging-buffer -> rgb-image -> convert -> encode-input-image
///
/// NV12 (device-memory) = encode-input-image
/// RGBA (device-memory) -> convert -> encode-input-image
#[derive(Debug)]
pub(super) enum Input {
    /// Input is NV12 copied from Host to staging buffer, staging buffer has image set when recording command buffer
    HostNV12 {
        staging_buffer: Buffer,
        nv12_image: ImageView,
        // TODO: nv12 scaler
    },
    /// Input is RGBA copied from Host to staging buffer, then converted to NV12
    HostRGBA {
        /// RGBA staging buffer
        staging_buffer: Buffer,
        /// Extent of the image inside the staging buffer
        staging_extent: Option<vk::Extent2D>,

        /// RGBA image created from the staging buffer
        rgb_image: ImageView,
        rgb_image_extent: vk::Extent2D,

        /// RGB -> YUV converter
        converter: RgbToNV12Converter,
        /// Final NV12 output image
        nv12_image: ImageView,
    },
    ImportedRGBA {
        /// Imported RGBA image
        rgb_image: Option<VulkanImageInput>,
        /// RGB -> YUV converter
        converter: RgbToNV12Converter,
        /// final output image
        nv12_image: ImageView,
    },
}

impl Input {
    pub(super) fn create(
        device: &Device,
        video_profile_info: vk::VideoProfileInfoKHR<'_>,
        input_as_vulkan_image: bool,
        pixel_format: InputPixelFormat,
        input_extent: vk::Extent2D,
        encode_extent: vk::Extent2D,
        num: u32,
    ) -> Result<Vec<Input>, VulkanError> {
        if input_as_vulkan_image {
            Self::new_from_vulkan_image(
                device,
                video_profile_info,
                pixel_format,
                input_extent,
                encode_extent,
                num,
            )
        } else {
            Self::new_from_host(
                device,
                video_profile_info,
                pixel_format,
                input_extent,
                encode_extent,
                num,
            )
        }
    }

    fn new_from_host(
        device: &Device,
        video_profile_info: vk::VideoProfileInfoKHR<'_>,
        pixel_format: InputPixelFormat,
        input_extent: vk::Extent2D,
        encode_extent: vk::Extent2D,
        num: u32,
    ) -> Result<Vec<Input>, VulkanError> {
        use InputPixelFormat::*;

        match pixel_format {
            NV12 => {
                let staging_buffer_size =
                    (input_extent.width as u64 * input_extent.height as u64 * 12) / 8;

                (0..num)
                    .map(|_| -> Result<Input, VulkanError> {
                        Ok(Input::HostNV12 {
                            staging_buffer: create_staging_buffer(device, staging_buffer_size)?,
                            nv12_image: create_nv12_image(
                                device,
                                video_profile_info,
                                encode_extent,
                            )?,
                        })
                    })
                    .collect()
            }
            RGBA { primaries } => {
                let staging_buffer_size =
                    input_extent.width as u64 * input_extent.height as u64 * 4;

                let mut converter: Vec<RgbToNV12Converter> =
                    RgbToNV12Converter::create(device, primaries, encode_extent, num)?;

                (0..num)
                    .map(|_| -> Result<Input, VulkanError> {
                        // Staging buffer containing the host image data
                        let staging_buffer = create_staging_buffer(device, staging_buffer_size)?;

                        // Staging buffer copy destination and if the resolution matches the encoder's: input to the RGB->Yuv converter
                        let rgb_image = create_rgba_image(
                            device,
                            input_extent,
                            vk::ImageUsageFlags::SAMPLED
                                | vk::ImageUsageFlags::TRANSFER_DST
                                | vk::ImageUsageFlags::TRANSFER_SRC,
                        )?;

                        // Destination of the RGB->YUV converter
                        let nv12_image =
                            create_nv12_image(device, video_profile_info, encode_extent)?;

                        Ok(Input::HostRGBA {
                            staging_buffer,
                            staging_extent: None,
                            rgb_image,
                            rgb_image_extent: input_extent,
                            converter: converter.pop().unwrap(),
                            nv12_image,
                        })
                    })
                    .collect()
            }
        }
    }

    fn new_from_vulkan_image(
        device: &Device,
        video_profile_info: vk::VideoProfileInfoKHR<'_>,
        pixel_format: InputPixelFormat,
        #[expect(unused_variables)] input_extent: vk::Extent2D,
        encode_extent: vk::Extent2D,
        num: u32,
    ) -> Result<Vec<Input>, VulkanError> {
        use InputPixelFormat::*;

        match pixel_format {
            NV12 => Err(VulkanError::InvalidArgument {
                message: "NV12 Vulkan Image Input to VulkanEncoder is currently not supported",
            }),
            RGBA { primaries } => {
                let mut converter: Vec<RgbToNV12Converter> =
                    RgbToNV12Converter::create(device, primaries, encode_extent, num)?;

                (0..num)
                    .map(|_| -> Result<Input, VulkanError> {
                        // Destination of the RGB->YUV converter
                        let nv12_image =
                            create_nv12_image(device, video_profile_info, encode_extent)?;

                        Ok(Input::ImportedRGBA {
                            rgb_image: None,
                            converter: converter.pop().unwrap(),
                            nv12_image,
                        })
                    })
                    .collect()
            }
        }
    }

    pub(super) fn submit_graphics_queue_add_semaphores(
        &mut self,
        wait_semaphores: &mut SmallVec<[vk::SemaphoreSubmitInfo; 2]>,
        signal_semaphores: &mut SmallVec<[vk::SemaphoreSubmitInfo; 2]>,
    ) {
        if let Input::ImportedRGBA {
            rgb_image: Some(rgb_image),
            ..
        } = &self
        {
            if let Some(InputSync {
                semaphore,
                timeline_point,
            }) = &rgb_image.acquire
            {
                let mut semaphore_info =
                    vk::SemaphoreSubmitInfo::default().semaphore(unsafe { semaphore.handle() });

                if let Some(timeline_point) = timeline_point {
                    semaphore_info = semaphore_info.value(*timeline_point);
                };

                wait_semaphores.push(semaphore_info);
            }

            if let Some(InputSync {
                semaphore,
                timeline_point,
            }) = &rgb_image.release
            {
                let mut semaphore_info =
                    vk::SemaphoreSubmitInfo::default().semaphore(unsafe { semaphore.handle() });

                if let Some(timeline_point) = timeline_point {
                    semaphore_info = semaphore_info.value(*timeline_point);
                };

                signal_semaphores.push(semaphore_info);
            }
        }
    }

    /// Destroy any references to external resources
    pub(super) fn drop_borrowed_resources(&mut self) {
        if let Input::ImportedRGBA { rgb_image, .. } = self {
            *rgb_image = None;
        }
    }

    /// Process input, depending on the input type and data given
    ///
    /// Copies image data from staging buffers, converts RGB to YUV etc..
    pub(super) unsafe fn prepare_input_image(
        &mut self,
        device: &Device,
        queue_family_index: u32,
        encode_queue_family_index: u32,
        command_buffer: &RecordingCommandBuffer<'_>,
        nv12_extent: vk::Extent2D,
    ) -> Result<(), VulkanError> {
        match self {
            Input::HostNV12 {
                staging_buffer,
                nv12_image,
            } => {
                nv12_image.image().cmd_memory_barrier(
                    command_buffer,
                    ImageMemoryBarrier::dst(
                        vk::ImageLayout::TRANSFER_DST_OPTIMAL,
                        vk::PipelineStageFlags2::TRANSFER,
                        vk::AccessFlags2::TRANSFER_WRITE,
                    )
                    .src(
                        vk::ImageLayout::UNDEFINED,
                        vk::PipelineStageFlags2::NONE,
                        vk::AccessFlags2::NONE,
                    ),
                    0,
                );

                copy_nv12_staging_buffer_to_image(
                    device,
                    command_buffer,
                    staging_buffer,
                    nv12_image.image(),
                    nv12_extent,
                );
                release_and_prepare_for_encode_queue(
                    queue_family_index,
                    encode_queue_family_index,
                    command_buffer,
                    nv12_image.image(),
                );
            }
            Input::HostRGBA {
                staging_buffer,
                staging_extent,
                rgb_image,
                rgb_image_extent,
                converter,
                nv12_image,
            } => {
                let rgb_image_content_extent = staging_extent.expect("staging_extent must be set");

                rgb_image.image().cmd_memory_barrier(
                    command_buffer,
                    ImageMemoryBarrier::dst(
                        vk::ImageLayout::TRANSFER_DST_OPTIMAL,
                        vk::PipelineStageFlags2::TRANSFER,
                        vk::AccessFlags2::TRANSFER_WRITE,
                    )
                    .src(
                        vk::ImageLayout::UNDEFINED,
                        vk::PipelineStageFlags2::BLIT,
                        vk::AccessFlags2::TRANSFER_READ,
                    ),
                    0,
                );

                copy_rgba_staging_buffer_to_image(
                    device,
                    command_buffer,
                    staging_buffer,
                    rgb_image.image(),
                    rgb_image_content_extent,
                );

                converter.record_rgba_to_nv12(
                    command_buffer,
                    *rgb_image_extent,
                    rgb_image_content_extent,
                    nv12_extent,
                    rgb_image,
                    nv12_image.image(),
                )?;
                release_and_prepare_for_encode_queue(
                    queue_family_index,
                    encode_queue_family_index,
                    command_buffer,
                    nv12_image.image(),
                );
            }
            Input::ImportedRGBA {
                rgb_image,
                converter,
                nv12_image,
            } => {
                let rgb_image = rgb_image
                    .as_ref()
                    .expect("device rgba-image view not set on submitted encode slot");

                converter.record_rgba_to_nv12(
                    command_buffer,
                    rgb_image.extent,
                    rgb_image.extent,
                    nv12_extent,
                    &rgb_image.view,
                    nv12_image.image(),
                )?;
                release_and_prepare_for_encode_queue(
                    queue_family_index,
                    encode_queue_family_index,
                    command_buffer,
                    nv12_image.image(),
                );
            }
        }

        Ok(())
    }

    pub(super) unsafe fn acquire_input_image(
        &self,
        graphics_queue_family_index: u32,
        encode_queue_family_index: u32,
        command_buffer: &RecordingCommandBuffer<'_>,
    ) -> &ImageView {
        let nv12_image = match self {
            Input::HostNV12 { nv12_image, .. } => nv12_image,
            Input::HostRGBA { nv12_image, .. } => nv12_image,
            Input::ImportedRGBA { nv12_image, .. } => nv12_image,
        };

        nv12_image.image().cmd_memory_barrier(
            command_buffer,
            ImageMemoryBarrier::dst(
                vk::ImageLayout::VIDEO_ENCODE_SRC_KHR,
                vk::PipelineStageFlags2::VIDEO_ENCODE_KHR,
                vk::AccessFlags2::VIDEO_ENCODE_READ_KHR,
            )
            .queue_family_indices(graphics_queue_family_index, encode_queue_family_index),
            0,
        );

        nv12_image
    }
}

fn create_staging_buffer(device: &Device, size: u64) -> Result<Buffer, VulkanError> {
    let create_info = vk::BufferCreateInfo::default()
        .size(size)
        .usage(vk::BufferUsageFlags::TRANSFER_SRC)
        .sharing_mode(vk::SharingMode::EXCLUSIVE);

    unsafe { Buffer::create(device, &create_info) }
}

fn create_nv12_image(
    device: &Device,
    video_profile_info: vk::VideoProfileInfoKHR<'_>,
    extent: vk::Extent2D,
) -> Result<ImageView, VulkanError> {
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

    let image = unsafe { Image::create(device, &create_info)? };

    let create_info = vk::ImageViewCreateInfo::default()
        .image(unsafe { image.handle() })
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

    unsafe { ImageView::create(&image, &create_info) }
}

fn create_rgba_image(
    device: &Device,
    extent: vk::Extent2D,
    usage: vk::ImageUsageFlags,
) -> Result<ImageView, VulkanError> {
    let create_info = vk::ImageCreateInfo::default()
        .image_type(vk::ImageType::TYPE_2D)
        .format(vk::Format::R8G8B8A8_UNORM)
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
        .usage(usage);

    let image = unsafe { Image::create(device, &create_info)? };

    let create_info = vk::ImageViewCreateInfo::default()
        .image(unsafe { image.handle() })
        .view_type(vk::ImageViewType::TYPE_2D)
        .format(vk::Format::R8G8B8A8_UNORM)
        .subresource_range(vk::ImageSubresourceRange {
            aspect_mask: vk::ImageAspectFlags::COLOR,
            base_mip_level: 0,
            level_count: 1,
            base_array_layer: 0,
            layer_count: 1,
        });

    unsafe { ImageView::create(&image, &create_info) }
}

unsafe fn copy_nv12_staging_buffer_to_image(
    device: &Device,
    recording: &RecordingCommandBuffer<'_>,
    staging_buffer: &Buffer,
    image: &Image,
    extent: vk::Extent2D,
) {
    device.ash().cmd_copy_buffer_to_image(
        recording.command_buffer(),
        staging_buffer.buffer(),
        image.handle(),
        vk::ImageLayout::TRANSFER_DST_OPTIMAL,
        &[
            // Plane 0
            vk::BufferImageCopy::default()
                .image_subresource(
                    vk::ImageSubresourceLayers::default()
                        .aspect_mask(vk::ImageAspectFlags::PLANE_0)
                        .layer_count(1),
                )
                .image_extent(vk::Extent3D {
                    width: extent.width,
                    height: extent.height,
                    depth: 1,
                }),
            // Plane 1
            vk::BufferImageCopy::default()
                .buffer_offset(extent.width as vk::DeviceSize * extent.height as vk::DeviceSize)
                .image_subresource(
                    vk::ImageSubresourceLayers::default()
                        .aspect_mask(vk::ImageAspectFlags::PLANE_1)
                        .layer_count(1),
                )
                .image_extent(vk::Extent3D {
                    width: extent.width / 2,
                    height: extent.height / 2,
                    depth: 1,
                }),
        ],
    );
}

unsafe fn copy_rgba_staging_buffer_to_image(
    device: &Device,
    command_buffer: &RecordingCommandBuffer<'_>,
    staging_buffer: &Buffer,
    image: &Image,
    extent: vk::Extent2D,
) {
    device.ash().cmd_copy_buffer_to_image(
        command_buffer.command_buffer(),
        staging_buffer.buffer(),
        image.handle(),
        vk::ImageLayout::TRANSFER_DST_OPTIMAL,
        &[vk::BufferImageCopy {
            buffer_offset: 0,
            buffer_row_length: extent.width,
            buffer_image_height: extent.height,
            image_subresource: vk::ImageSubresourceLayers {
                aspect_mask: vk::ImageAspectFlags::COLOR,
                mip_level: 0,
                base_array_layer: 0,
                layer_count: 1,
            },
            image_offset: vk::Offset3D::default(),
            image_extent: vk::Extent3D {
                width: extent.width,
                height: extent.height,
                depth: 1,
            },
        }],
    );
}

unsafe fn release_and_prepare_for_encode_queue(
    queue_family_index: u32,
    encode_queue_family_index: u32,
    command_buffer: &RecordingCommandBuffer<'_>,
    nv12: &Image,
) {
    nv12.cmd_memory_barrier(
        command_buffer,
        ImageMemoryBarrier::dst(
            vk::ImageLayout::VIDEO_ENCODE_SRC_KHR,
            vk::PipelineStageFlags2::NONE,
            vk::AccessFlags2::NONE,
        )
        .queue_family_indices(queue_family_index, encode_queue_family_index),
        0,
    );
}
