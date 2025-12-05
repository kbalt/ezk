use crate::{
    Buffer, DescriptorSet, DescriptorSetLayout, Device, Image, ImageView, Pipeline, PipelineLayout,
    RecordingCommandBuffer, Sampler, ShaderModule, VulkanError, image::ImageMemoryBarrier,
};
use ash::vk::{self};

use std::{
    slice,
    sync::{Arc, OnceLock},
};

static SHADER: &str = include_str!("rgb_to_nv12.wgsl");
static COMPILED: OnceLock<Vec<u32>> = OnceLock::new();

#[derive(Debug, Clone, Copy)]
pub enum Primaries {
    BT601,
    BT709,
    BT2020,
}

impl Primaries {
    fn primaries(&self) -> [f32; 3] {
        match self {
            Primaries::BT601 => [0.299, 0.587, 0.114],
            Primaries::BT709 => [0.2126, 0.7152, 0.0722],
            Primaries::BT2020 => [0.2627, 0.6780, 0.0593],
        }
    }
}

/// RGB to YUV converter using a compute shader
///
/// Since some drivers don't support binding Vulkan YUV images to compute shaders it uses intermediate
/// R8_UNORM & R8G8_UNORM images for the YUV planes
#[derive(Debug)]
pub(crate) struct RgbToNV12Converter {
    device: Device,

    compute_pipeline: Pipeline,
    descriptor_set: DescriptorSet,

    rgb_sampler: Sampler,
    intermediate_y: ImageView,
    intermediate_uv: ImageView,

    primaries_uniform: Arc<Buffer<[f32; 3]>>,
    scale_uniform: Buffer<[f32; 2]>,
    current_scale: [f32; 2],
}

impl RgbToNV12Converter {
    pub(super) fn create(
        device: &Device,
        primaries: Primaries,
        max_extent: vk::Extent2D,
        num: u32,
    ) -> Result<Vec<RgbToNV12Converter>, VulkanError> {
        let spv = COMPILED.get_or_init(|| ShaderModule::compile_wgsl_to_spv(SHADER));

        let compute_shader_module = ShaderModule::from_spv(device, spv)?;

        let bindings = [
            // Input RGB image
            vk::DescriptorSetLayoutBinding::default()
                .binding(0)
                .descriptor_type(vk::DescriptorType::SAMPLED_IMAGE)
                .descriptor_count(1)
                .stage_flags(vk::ShaderStageFlags::COMPUTE),
            // Input RGB image sampler
            vk::DescriptorSetLayoutBinding::default()
                .binding(1)
                .descriptor_type(vk::DescriptorType::SAMPLER)
                .descriptor_count(1)
                .stage_flags(vk::ShaderStageFlags::COMPUTE),
            // Output Y plane
            vk::DescriptorSetLayoutBinding::default()
                .binding(2)
                .descriptor_type(vk::DescriptorType::STORAGE_IMAGE)
                .descriptor_count(1)
                .stage_flags(vk::ShaderStageFlags::COMPUTE),
            // Output UV plane
            vk::DescriptorSetLayoutBinding::default()
                .binding(3)
                .descriptor_type(vk::DescriptorType::STORAGE_IMAGE)
                .descriptor_count(1)
                .stage_flags(vk::ShaderStageFlags::COMPUTE),
            // Primaries
            vk::DescriptorSetLayoutBinding::default()
                .binding(4)
                .descriptor_type(vk::DescriptorType::UNIFORM_BUFFER)
                .descriptor_count(1)
                .stage_flags(vk::ShaderStageFlags::COMPUTE),
            // Scale
            vk::DescriptorSetLayoutBinding::default()
                .binding(5)
                .descriptor_type(vk::DescriptorType::UNIFORM_BUFFER)
                .descriptor_count(1)
                .stage_flags(vk::ShaderStageFlags::COMPUTE),
        ];

        let descriptor_set_layout = DescriptorSetLayout::create(device, &bindings)?;
        let pipeline_layout = PipelineLayout::create(device, &descriptor_set_layout)?;

        let mut compute_pipelines = Pipeline::create(
            device,
            pipeline_layout,
            compute_shader_module,
            vk::ShaderStageFlags::COMPUTE,
            c"main",
            num,
        )?;

        let pool_sizes = [
            vk::DescriptorPoolSize {
                ty: vk::DescriptorType::SAMPLED_IMAGE,
                descriptor_count: num, // 1 sampled image binding
            },
            vk::DescriptorPoolSize {
                ty: vk::DescriptorType::SAMPLER,
                descriptor_count: num, // 1 sampler binding
            },
            vk::DescriptorPoolSize {
                ty: vk::DescriptorType::STORAGE_IMAGE,
                descriptor_count: 2 * num, // 2 image storage bindings
            },
            vk::DescriptorPoolSize {
                ty: vk::DescriptorType::UNIFORM_BUFFER,
                descriptor_count: num * 2, // 2 uniform buffer bindings
            },
        ];

        let mut descriptor_sets =
            DescriptorSet::create(device, &pool_sizes, &descriptor_set_layout, num)?;

        let primaries_uniform = unsafe {
            let primaries = primaries.primaries();

            let create_info = vk::BufferCreateInfo::default()
                .size(size_of_val(&primaries) as vk::DeviceSize)
                .usage(vk::BufferUsageFlags::UNIFORM_BUFFER);

            let mut buffer = Buffer::<[f32; 3]>::create(device, &create_info)?;

            let mut data = buffer.map(1)?;
            data.data_mut()[0] = primaries;
            drop(data);

            Arc::new(buffer)
        };

        let mut converter = Vec::with_capacity(num as usize);

        for _ in 0..num {
            let intermediate_y = unsafe {
                let intermediate_y = {
                    let create_info = vk::ImageCreateInfo::default()
                        .image_type(vk::ImageType::TYPE_2D)
                        .format(vk::Format::R8_UNORM)
                        .extent(vk::Extent3D {
                            width: max_extent.width,
                            height: max_extent.height,
                            depth: 1,
                        })
                        .mip_levels(1)
                        .array_layers(1)
                        .sharing_mode(vk::SharingMode::EXCLUSIVE)
                        .tiling(vk::ImageTiling::OPTIMAL)
                        .samples(vk::SampleCountFlags::TYPE_1)
                        .usage(vk::ImageUsageFlags::TRANSFER_SRC | vk::ImageUsageFlags::STORAGE)
                        .initial_layout(vk::ImageLayout::UNDEFINED);

                    Image::create(device, &create_info)
                }?;

                let create_info = vk::ImageViewCreateInfo::default()
                    .image(intermediate_y.handle())
                    .format(vk::Format::R8_UNORM)
                    .view_type(vk::ImageViewType::TYPE_2D)
                    .subresource_range(vk::ImageSubresourceRange {
                        aspect_mask: vk::ImageAspectFlags::COLOR,
                        base_mip_level: 0,
                        level_count: 1,
                        base_array_layer: 0,
                        layer_count: 1,
                    });

                ImageView::create(&intermediate_y, &create_info)?
            };

            let intermediate_uv = unsafe {
                let intermediate_uv = {
                    let initial_layout = vk::ImageCreateInfo::default()
                        .image_type(vk::ImageType::TYPE_2D)
                        .format(vk::Format::R8G8_UNORM)
                        .extent(vk::Extent3D {
                            width: max_extent.width / 2,
                            height: max_extent.height / 2,
                            depth: 1,
                        })
                        .mip_levels(1)
                        .array_layers(1)
                        .sharing_mode(vk::SharingMode::EXCLUSIVE)
                        .tiling(vk::ImageTiling::OPTIMAL)
                        .samples(vk::SampleCountFlags::TYPE_1)
                        .usage(vk::ImageUsageFlags::TRANSFER_SRC | vk::ImageUsageFlags::STORAGE)
                        .initial_layout(vk::ImageLayout::UNDEFINED);

                    Image::create(device, &initial_layout)
                }?;

                let create_info = vk::ImageViewCreateInfo::default()
                    .image(intermediate_uv.handle())
                    .format(vk::Format::R8G8_UNORM)
                    .view_type(vk::ImageViewType::TYPE_2D)
                    .subresource_range(vk::ImageSubresourceRange {
                        aspect_mask: vk::ImageAspectFlags::COLOR,
                        base_mip_level: 0,
                        level_count: 1,
                        base_array_layer: 0,
                        layer_count: 1,
                    });

                ImageView::create(&intermediate_uv, &create_info)?
            };

            let rgb_sampler = unsafe {
                let sampler_create_info = vk::SamplerCreateInfo::default()
                    .mag_filter(vk::Filter::LINEAR)
                    .min_filter(vk::Filter::LINEAR)
                    .address_mode_u(vk::SamplerAddressMode::CLAMP_TO_EDGE)
                    .address_mode_v(vk::SamplerAddressMode::CLAMP_TO_EDGE)
                    .address_mode_w(vk::SamplerAddressMode::CLAMP_TO_EDGE)
                    .mipmap_mode(vk::SamplerMipmapMode::LINEAR);

                Sampler::create(device, &sampler_create_info)?
            };

            let (scale_uniform, current_scale) = unsafe {
                let scale = [1.0f32; 2];

                let create_info = vk::BufferCreateInfo::default()
                    .size(size_of_val(&scale) as vk::DeviceSize)
                    .usage(vk::BufferUsageFlags::UNIFORM_BUFFER);

                let mut buffer = Buffer::<[f32; 2]>::create(device, &create_info)?;

                let mut data = buffer.map(1)?;
                data.data_mut()[0] = scale;
                drop(data);

                (buffer, scale)
            };

            converter.push(RgbToNV12Converter {
                device: device.clone(),
                compute_pipeline: compute_pipelines.pop().unwrap(),
                descriptor_set: descriptor_sets.pop().unwrap(),
                rgb_sampler,
                intermediate_y,
                intermediate_uv,
                primaries_uniform: primaries_uniform.clone(),
                scale_uniform,
                current_scale,
            });
        }

        Ok(converter)
    }

    /// Convert `input_rgb` into `output_nv12`
    pub(super) unsafe fn record_rgba_to_nv12(
        &mut self,
        command_buffer: &RecordingCommandBuffer<'_>,
        rgb_image_extent: vk::Extent2D,
        rgb_image_content_extent: vk::Extent2D,
        nv12_extent: vk::Extent2D,
        input_rgb: &ImageView,
        output_nv12: &Image,
    ) -> Result<(), VulkanError> {
        input_rgb.image().cmd_memory_barrier(
            command_buffer,
            ImageMemoryBarrier::dst(
                vk::ImageLayout::SHADER_READ_ONLY_OPTIMAL,
                vk::PipelineStageFlags2::COMPUTE_SHADER,
                vk::AccessFlags2::SHADER_SAMPLED_READ,
            ),
            0,
        );

        output_nv12.cmd_memory_barrier(
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

        self.intermediate_y.image().cmd_memory_barrier(
            command_buffer,
            ImageMemoryBarrier::dst(
                vk::ImageLayout::GENERAL,
                vk::PipelineStageFlags2::COMPUTE_SHADER,
                vk::AccessFlags2::SHADER_STORAGE_WRITE,
            ),
            0,
        );

        self.intermediate_uv.image().cmd_memory_barrier(
            command_buffer,
            ImageMemoryBarrier::dst(
                vk::ImageLayout::GENERAL,
                vk::PipelineStageFlags2::COMPUTE_SHADER,
                vk::AccessFlags2::SHADER_STORAGE_WRITE,
            ),
            0,
        );

        self.record_compute_shader(
            command_buffer,
            rgb_image_extent,
            rgb_image_content_extent,
            nv12_extent,
            input_rgb,
        )?;

        self.intermediate_y.image().cmd_memory_barrier(
            command_buffer,
            ImageMemoryBarrier::dst(
                vk::ImageLayout::TRANSFER_SRC_OPTIMAL,
                vk::PipelineStageFlags2::TRANSFER,
                vk::AccessFlags2::TRANSFER_READ,
            ),
            0,
        );

        self.intermediate_uv.image().cmd_memory_barrier(
            command_buffer,
            ImageMemoryBarrier::dst(
                vk::ImageLayout::TRANSFER_SRC_OPTIMAL,
                vk::PipelineStageFlags2::TRANSFER,
                vk::AccessFlags2::TRANSFER_READ,
            ),
            0,
        );

        self.device.ash().cmd_copy_image(
            command_buffer.command_buffer(),
            self.intermediate_y.image().handle(),
            vk::ImageLayout::TRANSFER_SRC_OPTIMAL,
            output_nv12.handle(),
            vk::ImageLayout::TRANSFER_DST_OPTIMAL,
            &[vk::ImageCopy {
                src_subresource: vk::ImageSubresourceLayers {
                    aspect_mask: vk::ImageAspectFlags::COLOR,
                    mip_level: 0,
                    base_array_layer: 0,
                    layer_count: 1,
                },
                src_offset: Default::default(),
                dst_subresource: vk::ImageSubresourceLayers {
                    aspect_mask: vk::ImageAspectFlags::PLANE_0,
                    mip_level: 0,
                    base_array_layer: 0,
                    layer_count: 1,
                },
                dst_offset: Default::default(),
                extent: vk::Extent3D {
                    width: nv12_extent.width,
                    height: nv12_extent.height,
                    depth: 1,
                },
            }],
        );

        self.device.ash().cmd_copy_image(
            command_buffer.command_buffer(),
            self.intermediate_uv.image().handle(),
            vk::ImageLayout::TRANSFER_SRC_OPTIMAL,
            output_nv12.handle(),
            vk::ImageLayout::TRANSFER_DST_OPTIMAL,
            &[vk::ImageCopy {
                src_subresource: vk::ImageSubresourceLayers {
                    aspect_mask: vk::ImageAspectFlags::COLOR,
                    mip_level: 0,
                    base_array_layer: 0,
                    layer_count: 1,
                },
                src_offset: Default::default(),
                dst_subresource: vk::ImageSubresourceLayers {
                    aspect_mask: vk::ImageAspectFlags::PLANE_1,
                    mip_level: 0,
                    base_array_layer: 0,
                    layer_count: 1,
                },
                dst_offset: Default::default(),
                extent: vk::Extent3D {
                    width: nv12_extent.width / 2,
                    height: nv12_extent.height / 2,
                    depth: 1,
                },
            }],
        );

        Ok(())
    }

    unsafe fn record_compute_shader(
        &mut self,
        recording: &RecordingCommandBuffer<'_>,
        rgb_image_extent: vk::Extent2D,
        rgb_image_content_extent: vk::Extent2D,
        nv12_extent: vk::Extent2D,
        input_rgb: &ImageView,
    ) -> Result<(), VulkanError> {
        let scale = [
            (1.0 / nv12_extent.width as f32) * rgb_image_content_extent.width as f32
                / rgb_image_extent.width as f32,
            (1.0 / nv12_extent.height as f32) * rgb_image_content_extent.height as f32
                / rgb_image_extent.height as f32,
        ];

        if self.current_scale != scale {
            self.current_scale = scale;
            let mut mapped = self.scale_uniform.map(1)?;
            mapped.data_mut()[0] = scale;
        }

        // Update descriptor set
        let image_infos = [
            vk::DescriptorImageInfo::default()
                .image_view(unsafe { input_rgb.handle() })
                .image_layout(vk::ImageLayout::SHADER_READ_ONLY_OPTIMAL),
            vk::DescriptorImageInfo::default().sampler(self.rgb_sampler.sampler()),
            vk::DescriptorImageInfo::default()
                .image_view(unsafe { self.intermediate_y.handle() })
                .image_layout(vk::ImageLayout::GENERAL),
            vk::DescriptorImageInfo::default()
                .image_view(unsafe { self.intermediate_uv.handle() })
                .image_layout(vk::ImageLayout::GENERAL),
        ];

        let primaries_buffer_info = vk::DescriptorBufferInfo::default()
            .buffer(unsafe { self.primaries_uniform.buffer() })
            .offset(0)
            .range(size_of::<[f32; 3]>() as u64);

        let scale_buffer_info = vk::DescriptorBufferInfo::default()
            .buffer(unsafe { self.scale_uniform.buffer() })
            .offset(0)
            .range(size_of::<[f32; 2]>() as u64);

        let descriptor_writes = [
            vk::WriteDescriptorSet::default()
                .dst_set(unsafe { self.descriptor_set.handle() })
                .dst_binding(0)
                .descriptor_type(vk::DescriptorType::SAMPLED_IMAGE)
                .image_info(slice::from_ref(&image_infos[0])),
            vk::WriteDescriptorSet::default()
                .dst_set(unsafe { self.descriptor_set.handle() })
                .dst_binding(1)
                .descriptor_type(vk::DescriptorType::SAMPLER)
                .image_info(slice::from_ref(&image_infos[1])),
            vk::WriteDescriptorSet::default()
                .dst_set(unsafe { self.descriptor_set.handle() })
                .dst_binding(2)
                .descriptor_type(vk::DescriptorType::STORAGE_IMAGE)
                .image_info(slice::from_ref(&image_infos[2])),
            vk::WriteDescriptorSet::default()
                .dst_set(unsafe { self.descriptor_set.handle() })
                .dst_binding(3)
                .descriptor_type(vk::DescriptorType::STORAGE_IMAGE)
                .image_info(slice::from_ref(&image_infos[3])),
            vk::WriteDescriptorSet::default()
                .dst_set(unsafe { self.descriptor_set.handle() })
                .dst_binding(4)
                .descriptor_type(vk::DescriptorType::UNIFORM_BUFFER)
                .buffer_info(slice::from_ref(&primaries_buffer_info)),
            vk::WriteDescriptorSet::default()
                .dst_set(unsafe { self.descriptor_set.handle() })
                .dst_binding(5)
                .descriptor_type(vk::DescriptorType::UNIFORM_BUFFER)
                .buffer_info(slice::from_ref(&scale_buffer_info)),
        ];

        self.device
            .ash()
            .update_descriptor_sets(&descriptor_writes, &[]);

        // Bind pipeline and dispatch
        self.device.ash().cmd_bind_pipeline(
            recording.command_buffer(),
            vk::PipelineBindPoint::COMPUTE,
            self.compute_pipeline.pipeline(),
        );

        self.device.ash().cmd_bind_descriptor_sets(
            recording.command_buffer(),
            vk::PipelineBindPoint::COMPUTE,
            self.compute_pipeline.pipeline_layout(),
            0,
            &[self.descriptor_set.handle()],
            &[],
        );

        self.device.ash().cmd_dispatch(
            recording.command_buffer(),
            nv12_extent.width.div_ceil(16),
            nv12_extent.height.div_ceil(16),
            1,
        );

        Ok(())
    }
}
