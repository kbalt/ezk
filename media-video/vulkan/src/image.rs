use crate::{Device, RecordingCommandBuffer, VulkanError};
use ash::vk;
use smallvec::SmallVec;
use std::{
    os::fd::{AsRawFd, OwnedFd},
    sync::{Arc, Mutex},
};

#[derive(Debug, Clone)]
pub struct Image {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    device: Device,
    image: vk::Image,
    memory: vk::DeviceMemory,
    extent: vk::Extent3D,

    state: Mutex<SmallVec<[State; 1]>>,
}

#[derive(Debug, Clone)]
struct State {
    current_layout: vk::ImageLayout,
    last_access: vk::AccessFlags2,
    last_stage: vk::PipelineStageFlags2,
}

impl Image {
    pub(crate) unsafe fn create(
        device: &Device,
        create_info: &vk::ImageCreateInfo<'_>,
    ) -> Result<Self, VulkanError> {
        let image = device.ash().create_image(create_info, None)?;
        let memory_requirements = device.ash().get_image_memory_requirements(image);

        let alloc_info = vk::MemoryAllocateInfo::default()
            .allocation_size(memory_requirements.size)
            .memory_type_index(device.find_memory_type(
                memory_requirements.memory_type_bits,
                vk::MemoryPropertyFlags::DEVICE_LOCAL,
            )?);

        let memory = device.ash().allocate_memory(&alloc_info, None)?;
        device.ash().bind_image_memory(image, memory, 0)?;

        Ok(Self {
            inner: Arc::new(Inner {
                device: device.clone(),
                image,
                memory,
                extent: create_info.extent,
                state: Mutex::new(smallvec::smallvec![
                    State {
                        current_layout: create_info.initial_layout,
                        last_access: vk::AccessFlags2::NONE,
                        last_stage: vk::PipelineStageFlags2::TOP_OF_PIPE,
                    };
                    create_info.array_layers as usize
                ]),
            }),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn import_dma_fd_rgba(
        device: &Device,
        fd: OwnedFd,
        width: u32,
        height: u32,
        offset: vk::DeviceSize,
        stride: vk::DeviceSize,
        modifier: u64,
        usage: vk::ImageUsageFlags,
    ) -> Result<Image, VulkanError> {
        Image::import_dma_fd(
            device,
            fd,
            width,
            height,
            &[offset],
            &[stride],
            modifier,
            vk::Format::R8G8B8A8_UNORM,
            usage,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) unsafe fn import_dma_fd(
        device: &Device,
        fd: OwnedFd,
        width: u32,
        height: u32,
        offset: &[vk::DeviceSize],
        stride: &[vk::DeviceSize],
        modifier: u64,
        format: vk::Format,
        usage: vk::ImageUsageFlags,
    ) -> Result<Image, VulkanError> {
        assert_eq!(offset.len(), stride.len());

        // Define the plane layout of the image inside the dma buffer
        let plane_layouts: SmallVec<[vk::SubresourceLayout; 3]> = offset
            .iter()
            .zip(stride)
            .map(|(offset, stride)| {
                vk::SubresourceLayout::default()
                    .offset(*offset)
                    .row_pitch(*stride)
            })
            .collect();

        let mut drm_modifier_info = vk::ImageDrmFormatModifierExplicitCreateInfoEXT::default()
            .drm_format_modifier(modifier)
            .plane_layouts(&plane_layouts);

        // Set the DMA_BUF_EXT handle for image creation
        let mut external_memory_image_info = vk::ExternalMemoryImageCreateInfo::default()
            .handle_types(vk::ExternalMemoryHandleTypeFlags::DMA_BUF_EXT);

        let extent = vk::Extent3D {
            width,
            height,
            depth: 1,
        };

        let image_create_info = vk::ImageCreateInfo::default()
            .image_type(vk::ImageType::TYPE_2D)
            .format(format)
            .extent(extent)
            .mip_levels(1)
            .array_layers(1)
            .samples(vk::SampleCountFlags::TYPE_1)
            .tiling(vk::ImageTiling::DRM_FORMAT_MODIFIER_EXT)
            .usage(usage)
            .sharing_mode(vk::SharingMode::EXCLUSIVE)
            .initial_layout(vk::ImageLayout::UNDEFINED)
            .push_next(&mut external_memory_image_info)
            .push_next(&mut drm_modifier_info);

        // Create the image
        let image = unsafe { device.ash().create_image(&image_create_info, None)? };

        // Bind external dma buf memory to the image
        let memory_requirements = unsafe { device.ash().get_image_memory_requirements(image) };

        let memory_type_index = device.find_memory_type(
            memory_requirements.memory_type_bits,
            vk::MemoryPropertyFlags::empty(),
        )?;

        let mut dedicated = vk::MemoryDedicatedAllocateInfo::default().image(image);
        let mut import_fd_info = vk::ImportMemoryFdInfoKHR::default()
            .handle_type(vk::ExternalMemoryHandleTypeFlags::DMA_BUF_EXT)
            .fd(fd.as_raw_fd());

        let allocate_info = vk::MemoryAllocateInfo::default()
            .allocation_size(memory_requirements.size)
            .memory_type_index(memory_type_index)
            .push_next(&mut import_fd_info)
            .push_next(&mut dedicated);

        // Create vulkan memory using the dma buf fd
        let memory = unsafe { device.ash().allocate_memory(&allocate_info, None)? };

        // Finally bind the image memory, when this call succeeds the fd ownership is transferred to vulkan
        let bind_result = unsafe { device.ash().bind_image_memory(image, memory, 0) };

        match bind_result {
            Ok(()) => std::mem::forget(fd),
            Err(e) => {
                device.ash().destroy_image(image, None);
                return Err(e.into());
            }
        }

        Ok(Self {
            inner: Arc::new(Inner {
                device: device.clone(),
                image,
                memory,
                extent,
                state: Mutex::new(smallvec::smallvec![State {
                    current_layout: vk::ImageLayout::UNDEFINED,
                    last_access: vk::AccessFlags2::NONE,
                    last_stage: vk::PipelineStageFlags2::NONE,
                }]),
            }),
        })
    }

    pub(crate) fn device(&self) -> &Device {
        &self.inner.device
    }

    pub unsafe fn handle(&self) -> vk::Image {
        self.inner.image
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn cmd_memory_barrier(
        &self,
        command_buffer: &RecordingCommandBuffer<'_>,
        info: ImageMemoryBarrier,
        base_array_layer: u32,
    ) {
        let mut state = self.inner.state.lock().unwrap();
        let state = &mut state[base_array_layer as usize];

        let (old_layout, src_stage_mask, src_access_mask) = match info.src {
            Some(src) => src,
            None => (state.current_layout, state.last_stage, state.last_access),
        };

        let (new_layout, dst_stage_mask, dst_access_mask) = info.dst;

        let barrier = vk::ImageMemoryBarrier2::default()
            .image(unsafe { self.handle() })
            .old_layout(old_layout)
            .new_layout(new_layout)
            .src_queue_family_index(info.src_queue_family_index)
            .dst_queue_family_index(info.dst_queue_family_index)
            .src_stage_mask(src_stage_mask)
            .src_access_mask(src_access_mask)
            .dst_stage_mask(dst_stage_mask)
            .dst_access_mask(dst_access_mask)
            .subresource_range(vk::ImageSubresourceRange {
                aspect_mask: vk::ImageAspectFlags::COLOR,
                base_mip_level: 0,
                level_count: 1,
                base_array_layer,
                layer_count: 1,
            });

        state.current_layout = new_layout;
        state.last_stage = dst_stage_mask;
        state.last_access = dst_access_mask;

        let barriers = [barrier];
        let dependency_info = vk::DependencyInfoKHR::default().image_memory_barriers(&barriers);

        unsafe {
            self.inner
                .device
                .ash()
                .cmd_pipeline_barrier2(command_buffer.command_buffer(), &dependency_info)
        };
    }

    pub unsafe fn to_wgpu_texture_hardcoded_rgba8(&self, device: &wgpu::Device) -> wgpu::Texture {
        // TODO: most of this is wrong and hardcoded

        let this = self.clone();

        let size = wgpu::Extent3d {
            width: self.inner.extent.width,
            height: self.inner.extent.height,
            depth_or_array_layers: self.inner.extent.depth,
        };

        let hal_texture = device
            .as_hal::<wgpu::hal::vulkan::Api>()
            .unwrap()
            .texture_from_raw(
                self.inner.image,
                &wgpu::hal::TextureDescriptor {
                    label: None,
                    size,
                    mip_level_count: 1,
                    sample_count: 1,
                    dimension: wgpu::TextureDimension::D2,
                    format: wgpu::TextureFormat::Rgba8Unorm,
                    usage: wgpu::TextureUses::UNKNOWN,
                    memory_flags: wgpu::hal::MemoryFlags::empty(),
                    view_formats: vec![wgpu::TextureFormat::Rgba8Unorm],
                },
                Some(Box::new(|| drop(this))),
            );

        device.create_texture_from_hal::<wgpu::hal::vulkan::Api>(
            hal_texture,
            &wgpu::TextureDescriptor {
                label: None,
                size,
                mip_level_count: 1,
                sample_count: 1,
                dimension: wgpu::TextureDimension::D2,
                format: wgpu::TextureFormat::Rgba8Unorm,
                // TODO: this is wrong!
                usage: wgpu::TextureUsages::TEXTURE_BINDING
                    | wgpu::TextureUsages::RENDER_ATTACHMENT,
                view_formats: &[wgpu::TextureFormat::Rgba8Unorm],
            },
        )
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        unsafe {
            self.device.ash().destroy_image(self.image, None);
            self.device.ash().free_memory(self.memory, None);
        }
    }
}

#[derive(Debug)]
pub(crate) struct ImageMemoryBarrier {
    dst: (vk::ImageLayout, vk::PipelineStageFlags2, vk::AccessFlags2),
    src: Option<(vk::ImageLayout, vk::PipelineStageFlags2, vk::AccessFlags2)>,

    src_queue_family_index: u32,
    dst_queue_family_index: u32,
}

impl ImageMemoryBarrier {
    pub(crate) fn dst(
        new_layout: vk::ImageLayout,
        dst_stage_mask: vk::PipelineStageFlags2,
        dst_access_flags: vk::AccessFlags2,
    ) -> Self {
        ImageMemoryBarrier {
            dst: (new_layout, dst_stage_mask, dst_access_flags),
            src: None,
            src_queue_family_index: vk::QUEUE_FAMILY_IGNORED,
            dst_queue_family_index: vk::QUEUE_FAMILY_IGNORED,
        }
    }

    pub(crate) fn src(
        mut self,
        old_layout: vk::ImageLayout,
        src_stage_mask: vk::PipelineStageFlags2,
        src_access_flags: vk::AccessFlags2,
    ) -> Self {
        self.src = Some((old_layout, src_stage_mask, src_access_flags));
        self
    }

    pub(crate) fn queue_family_indices(
        mut self,
        src_queue_family_index: u32,
        dst_queue_family_index: u32,
    ) -> Self {
        self.src_queue_family_index = src_queue_family_index;
        self.dst_queue_family_index = dst_queue_family_index;
        self
    }
}
