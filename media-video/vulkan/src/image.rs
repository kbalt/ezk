use crate::{Device, RecordingCommandBuffer, VulkanError, device::find_memory_type_stable};
use ash::vk::{self, Handle, TaggedStructure};
use smallvec::{SmallVec, smallvec};
use std::{
    os::fd::{AsRawFd, FromRawFd, OwnedFd},
    sync::{Arc, Mutex},
};
use wgpu::hal::vulkan::TextureMemory;

#[derive(Debug, Clone)]
pub struct Image {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    device: Device,
    image: vk::Image,
    memory: SmallVec<[vk::DeviceMemory; 1]>,
    extent: vk::Extent3D,
    usage: vk::ImageUsageFlags,
    foreign: bool,

    state: Mutex<SmallVec<[State; 1]>>,
}

#[derive(Debug, Clone)]
struct State {
    current_layout: vk::ImageLayout,
    last_access: vk::AccessFlags2,
    last_stage: vk::PipelineStageFlags2,
}

#[derive(Debug)]
pub struct DrmPlane {
    pub fd: OwnedFd,
    pub offset: usize,
    pub stride: usize,
}

impl Image {
    pub unsafe fn create(
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
                memory: smallvec![memory],
                extent: create_info.extent,
                usage: create_info.usage,
                foreign: false,
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

    pub unsafe fn create_dma_exportable(
        device: &Device,
        create_info: vk::ImageCreateInfo<'_>,
    ) -> Result<Self, VulkanError> {
        let image = {
            let mut external_memory_image_info = vk::ExternalMemoryImageCreateInfo::default()
                .handle_types(vk::ExternalMemoryHandleTypeFlags::DMA_BUF_EXT);

            device
                .ash()
                .create_image(&create_info.push(&mut external_memory_image_info), None)?
        };

        let mut dedicated_memory_requirements = vk::MemoryDedicatedRequirements::default();
        let mut memory_requirements2 =
            vk::MemoryRequirements2::default().push(&mut dedicated_memory_requirements);
        device.ash().get_image_memory_requirements2(
            &vk::ImageMemoryRequirementsInfo2::default().image(image),
            &mut memory_requirements2,
        );
        let memory_requirements = memory_requirements2.memory_requirements;

        let mut export_info = vk::ExportMemoryAllocateInfo::default()
            .handle_types(vk::ExternalMemoryHandleTypeFlags::DMA_BUF_EXT);
        let mut dedicated_info = vk::MemoryDedicatedAllocateInfo::default().image(image);

        let mut alloc_info = vk::MemoryAllocateInfo::default()
            .allocation_size(memory_requirements.size)
            .memory_type_index(device.find_memory_type(
                memory_requirements.memory_type_bits,
                vk::MemoryPropertyFlags::DEVICE_LOCAL,
            )?)
            .push(&mut export_info);

        if dedicated_memory_requirements.requires_dedicated_allocation == vk::TRUE {
            alloc_info = alloc_info.push(&mut dedicated_info);
        }

        let memory = device.ash().allocate_memory(&alloc_info, None)?;
        device.ash().bind_image_memory(image, memory, 0)?;

        Ok(Self {
            inner: Arc::new(Inner {
                device: device.clone(),
                image,
                memory: smallvec![memory],
                extent: create_info.extent,
                usage: create_info.usage,
                foreign: false,
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
    pub unsafe fn import_dma_fd(
        device: &Device,
        width: u32,
        height: u32,
        mut planes: SmallVec<[DrmPlane; 4]>,
        modifier: u64,
        format: vk::Format,
        usage: vk::ImageUsageFlags,
    ) -> Result<Image, VulkanError> {
        // Define the plane layout of the image inside the dma buffer
        let plane_layouts: SmallVec<[vk::SubresourceLayout; 4]> = planes
            .iter()
            .map(|plane| {
                vk::SubresourceLayout::default()
                    .offset(plane.offset as vk::DeviceSize)
                    .row_pitch(plane.stride as vk::DeviceSize)
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
            .flags(vk::ImageCreateFlags::empty())
            .image_type(vk::ImageType::TYPE_2D)
            .format(format)
            .extent(extent)
            .mip_levels(1)
            .array_layers(1)
            .samples(vk::SampleCountFlags::TYPE_1)
            .tiling(vk::ImageTiling::DRM_FORMAT_MODIFIER_EXT)
            .usage(usage)
            .initial_layout(vk::ImageLayout::UNDEFINED)
            .push(&mut external_memory_image_info)
            .push(&mut drm_modifier_info);

        // Create the image
        let image = unsafe { device.ash().create_image(&image_create_info, None)? };

        let memory_requirements_info = vk::ImageMemoryRequirementsInfo2::default().image(image);

        let mut memory_requirements = vk::MemoryRequirements2::default();

        // Bind external dma buf memory to the image
        unsafe {
            device
                .ash()
                .get_image_memory_requirements2(&memory_requirements_info, &mut memory_requirements)
        };

        let mut memory_requirements = memory_requirements.memory_requirements;

        let mut memory_fd_properties = vk::MemoryFdPropertiesKHR::default();
        ash::khr::external_memory_fd::Device::load(device.instance().ash(), device.ash())
            .get_memory_fd_properties(
                vk::ExternalMemoryHandleTypeFlags::DMA_BUF_EXT,
                planes[0].fd.as_raw_fd(),
                &mut memory_fd_properties,
            )?;

        memory_requirements.memory_type_bits &= memory_fd_properties.memory_type_bits;

        let memory_type_index = device
            .find_memory_type(
                memory_requirements.memory_type_bits,
                vk::MemoryPropertyFlags::DEVICE_LOCAL,
            )
            .or_else(|_e| {
                device.find_memory_type(
                    memory_requirements.memory_type_bits,
                    vk::MemoryPropertyFlags::empty(),
                )
            })?;

        let mut dedicated = vk::MemoryDedicatedAllocateInfo::default().image(image);

        let mut import_fd_info = vk::ImportMemoryFdInfoKHR::default()
            .handle_type(vk::ExternalMemoryHandleTypeFlags::DMA_BUF_EXT)
            .fd(planes[0].fd.as_raw_fd());

        let allocate_info = vk::MemoryAllocateInfo::default()
            .allocation_size(memory_requirements.size)
            .memory_type_index(memory_type_index)
            .push(&mut import_fd_info)
            .push(&mut dedicated);

        // Create vulkan memory using the dma buf fd
        let memory = unsafe { device.ash().allocate_memory(&allocate_info, None)? };

        // Finally bind the image memory, when this call succeeds the fd ownership is transferred to vulkan
        let bind_result = unsafe { device.ash().bind_image_memory(image, memory, 0) };

        match bind_result {
            Ok(()) => {
                std::mem::forget(planes.remove(0));
            }
            Err(e) => {
                device.ash().destroy_image(image, None);
                device.ash().free_memory(memory, None);

                return Err(e.into());
            }
        }

        Ok(Self {
            inner: Arc::new(Inner {
                device: device.clone(),
                image,
                memory: smallvec![memory],
                extent,
                usage,
                foreign: true,
                state: Mutex::new(smallvec::smallvec![State {
                    current_layout: vk::ImageLayout::UNDEFINED,
                    last_access: vk::AccessFlags2::NONE,
                    last_stage: vk::PipelineStageFlags2::NONE,
                }]),
            }),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn import_planar_dma_fd(
        device: &Device,
        width: u32,
        height: u32,
        planes: SmallVec<[DrmPlane; 4]>,
        modifier: u64,
        format: vk::Format,
        usage: vk::ImageUsageFlags,
    ) -> Result<Image, VulkanError> {
        // Define the plane layout of the image inside the dma buffer
        let plane_layouts: SmallVec<[vk::SubresourceLayout; 4]> = planes
            .iter()
            .map(|plane| {
                vk::SubresourceLayout::default()
                    .offset(plane.offset as vk::DeviceSize)
                    .row_pitch(plane.stride as vk::DeviceSize)
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
            .flags(vk::ImageCreateFlags::DISJOINT)
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
            .push(&mut external_memory_image_info)
            .push(&mut drm_modifier_info);

        // Create the image
        let image = unsafe { device.ash().create_image(&image_create_info, None)? };

        let mut allocated_memory = smallvec![];
        let mut plane_bind_infos: SmallVec<[vk::BindImagePlaneMemoryInfo; 4]> = smallvec![];
        let mut bind_infos: SmallVec<[vk::BindImageMemoryInfo; 4]> = smallvec![];

        for (i, plane) in planes.iter().enumerate() {
            let plane_aspect = match i {
                0 => vk::ImageAspectFlags::MEMORY_PLANE_0_EXT,
                1 => vk::ImageAspectFlags::MEMORY_PLANE_1_EXT,
                2 => vk::ImageAspectFlags::MEMORY_PLANE_2_EXT,
                3 => vk::ImageAspectFlags::MEMORY_PLANE_3_EXT,
                _ => {
                    return Err(VulkanError::InvalidArgument {
                        message: "too many planes",
                    });
                }
            };

            let mut plane_memory_requirements =
                vk::ImagePlaneMemoryRequirementsInfo::default().plane_aspect(plane_aspect);

            let memory_requirements_info = vk::ImageMemoryRequirementsInfo2::default()
                .image(image)
                .push(&mut plane_memory_requirements);

            let mut memory_requirements = vk::MemoryRequirements2::default();

            // Bind external dma buf memory to the image
            unsafe {
                device.ash().get_image_memory_requirements2(
                    &memory_requirements_info,
                    &mut memory_requirements,
                )
            };

            let memory_requirements = memory_requirements.memory_requirements;

            let memory_type_index = device
                .find_memory_type(
                    memory_requirements.memory_type_bits,
                    vk::MemoryPropertyFlags::DEVICE_LOCAL,
                )
                .or_else(|_e| {
                    device.find_memory_type(
                        memory_requirements.memory_type_bits,
                        vk::MemoryPropertyFlags::empty(),
                    )
                })?;

            let mut dedicated = vk::MemoryDedicatedAllocateInfo::default().image(image);

            let mut import_fd_info = vk::ImportMemoryFdInfoKHR::default()
                .handle_type(vk::ExternalMemoryHandleTypeFlags::DMA_BUF_EXT)
                .fd(plane.fd.as_raw_fd());

            let allocate_info = vk::MemoryAllocateInfo::default()
                .allocation_size(memory_requirements.size)
                .memory_type_index(memory_type_index)
                .push(&mut import_fd_info)
                .push(&mut dedicated);

            // Create vulkan memory using the dma buf fd
            let memory = unsafe { device.ash().allocate_memory(&allocate_info, None)? };

            allocated_memory.push(memory);
            plane_bind_infos
                .push(vk::BindImagePlaneMemoryInfo::default().plane_aspect(plane_aspect));

            bind_infos.push(
                vk::BindImageMemoryInfo::default()
                    .image(image)
                    .memory(memory),
            );
        }

        let bind_infos: SmallVec<[_; 4]> = plane_bind_infos
            .iter_mut()
            .zip(allocated_memory.iter())
            .map(|(plane, memory)| {
                vk::BindImageMemoryInfo::default()
                    .image(image)
                    .memory(*memory)
                    .push(plane)
            })
            .collect();

        // Finally bind the image memory, when this call succeeds the fd ownership is transferred to vulkan
        let bind_result = unsafe { device.ash().bind_image_memory2(&bind_infos) };

        match bind_result {
            Ok(()) => {
                for plane in planes {
                    std::mem::forget(plane.fd);
                }
            }
            Err(e) => {
                device.ash().destroy_image(image, None);

                for memory in allocated_memory {
                    device.ash().free_memory(memory, None);
                }

                return Err(e.into());
            }
        }

        Ok(Self {
            inner: Arc::new(Inner {
                device: device.clone(),
                image,
                memory: allocated_memory,
                extent,
                usage,
                foreign: true,
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

    pub fn is_foreign(&self) -> bool {
        self.inner.foreign
    }

    #[allow(clippy::too_many_arguments)]
    pub fn cmd_memory_barrier(
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
                .cmd_pipeline_barrier2(command_buffer.command_buffer(), &dependency_info);
        }
    }

    /// Import this image into a separate wgpu instance backed by a **different** Vulkan
    /// device/instance than the one this [`Image`] was created on.
    ///
    /// The cross-device transfer is done using Linux DMA-BUF, its memory is
    /// exported as a DMA-BUF fd from the source Vulkan device and then imported into the target wgpu Vulkan device.
    ///
    /// The returned [`wgpu::Texture`] owns the target-side Vulkan resources and destroys them when dropped.
    ///
    /// # Safety
    ///
    /// - This image must have been created with DRM format modifier tiling (`VK_IMAGE_TILING_DRM_FORMAT_MODIFIER_EXT`)
    ///   and its memory must have been allocated with `VkExportMemoryAllocateInfo` including `VK_EXTERNAL_MEMORY_HANDLE_TYPE_DMA_BUF_BIT_EXT`.
    /// - This image must be in `R8G8B8A8_UNORM` format, with one mip level, one array layer, a sample count of 1, be 2D, and have a single non-disjoint memory plane.
    pub unsafe fn to_rgba8_wgpu_texture_foreign(
        &self,
        target_device: &wgpu::Device,
    ) -> Result<wgpu::Texture, VulkanError> {
        struct ForeignTextureResources {
            device: ash_stable::Device,
            image: ash_stable::vk::Image,
            memory: ash_stable::vk::DeviceMemory,
        }

        impl Drop for ForeignTextureResources {
            fn drop(&mut self) {
                unsafe {
                    self.device.destroy_image(self.image, None);
                    self.device.free_memory(self.memory, None);
                }
            }
        }

        let (fd, modifier) = self.export_as_dma_fd()?;

        let src_layout = self.inner.device.ash().get_image_subresource_layout(
            self.inner.image,
            vk::ImageSubresource::default()
                .aspect_mask(vk::ImageAspectFlags::MEMORY_PLANE_0_EXT)
                .mip_level(0)
                .array_layer(0),
        );

        let extent = self.inner.extent;
        let src_usage = self.inner.usage;

        let hal_device = target_device
            .as_hal::<wgpu::hal::vulkan::Api>()
            .expect("target wgpu device must be backed by Vulkan");

        let dst_ash = hal_device.raw_device();
        let dst_instance = hal_device.shared_instance().raw_instance();
        let dst_physical = hal_device.raw_physical_device();

        // Transcribe the plane layout from the source subresource query.
        let plane_layout = ash_stable::vk::SubresourceLayout {
            offset: src_layout.offset,
            size: 0,
            row_pitch: src_layout.row_pitch,
            array_pitch: src_layout.array_pitch,
            depth_pitch: src_layout.depth_pitch,
        };

        let mut drm_modifier_info =
            ash_stable::vk::ImageDrmFormatModifierExplicitCreateInfoEXT::default()
                .drm_format_modifier(modifier)
                .plane_layouts(std::slice::from_ref(&plane_layout));

        let mut external_memory_image_info =
            ash_stable::vk::ExternalMemoryImageCreateInfo::default()
                .handle_types(ash_stable::vk::ExternalMemoryHandleTypeFlags::DMA_BUF_EXT);

        // Reinterpret usage flags; both ash versions use the same underlying bit values.
        let dst_usage = ash_stable::vk::ImageUsageFlags::from_raw(src_usage.as_raw());

        let image_create_info = ash_stable::vk::ImageCreateInfo::default()
            .flags(ash_stable::vk::ImageCreateFlags::empty())
            .image_type(ash_stable::vk::ImageType::TYPE_2D)
            .format(ash_stable::vk::Format::R8G8B8A8_UNORM)
            .extent(ash_stable::vk::Extent3D {
                width: extent.width,
                height: extent.height,
                depth: extent.depth,
            })
            .mip_levels(1)
            .array_layers(1)
            .samples(ash_stable::vk::SampleCountFlags::TYPE_1)
            .tiling(ash_stable::vk::ImageTiling::DRM_FORMAT_MODIFIER_EXT)
            .usage(dst_usage)
            .initial_layout(ash_stable::vk::ImageLayout::UNDEFINED)
            .push_next(&mut external_memory_image_info)
            .push_next(&mut drm_modifier_info);

        let dst_image = unsafe { dst_ash.create_image(&image_create_info, None) }
            .map_err(|e| VulkanError::from(vk::Result::from_raw(e.as_raw())))?;

        let mut memory_requirements = {
            let mut memory_requirements = ash_stable::vk::MemoryRequirements2::default();
            unsafe {
                dst_ash.get_image_memory_requirements2(
                    &ash_stable::vk::ImageMemoryRequirementsInfo2::default().image(dst_image),
                    &mut memory_requirements,
                )
            };

            memory_requirements.memory_requirements
        };

        // Determine which memory types are compatible with the DMA-BUF fd on the target.
        let mut memory_fd_properties = ash_stable::vk::MemoryFdPropertiesKHR::default();
        ash_stable::khr::external_memory_fd::Device::new(dst_instance, dst_ash)
            .get_memory_fd_properties(
                ash_stable::vk::ExternalMemoryHandleTypeFlags::DMA_BUF_EXT,
                fd.as_raw_fd(),
                &mut memory_fd_properties,
            )
            .map_err(|e| {
                unsafe { dst_ash.destroy_image(dst_image, None) };
                VulkanError::from(vk::Result::from_raw(e.as_raw()))
            })?;

        memory_requirements.memory_type_bits &= memory_fd_properties.memory_type_bits;

        let phys_mem_props =
            unsafe { dst_instance.get_physical_device_memory_properties(dst_physical) };

        let memory_type_index = find_memory_type_stable(
            phys_mem_props,
            memory_requirements.memory_type_bits,
            ash_stable::vk::MemoryPropertyFlags::DEVICE_LOCAL,
        )
        .or_else(|_e| {
            // When sharing memory across physical GPUs DEVICE_LOCAL may not work, fall back to some other compatible memory
            find_memory_type_stable(
                phys_mem_props,
                memory_requirements.memory_type_bits,
                ash_stable::vk::MemoryPropertyFlags::empty(),
            )
        })?;

        let mut dedicated = ash_stable::vk::MemoryDedicatedAllocateInfo::default().image(dst_image);

        let mut import_fd_info = ash_stable::vk::ImportMemoryFdInfoKHR::default()
            .handle_type(ash_stable::vk::ExternalMemoryHandleTypeFlags::DMA_BUF_EXT)
            .fd(fd.as_raw_fd());

        let allocate_info = ash_stable::vk::MemoryAllocateInfo::default()
            .allocation_size(memory_requirements.size)
            .memory_type_index(memory_type_index)
            .push_next(&mut import_fd_info)
            .push_next(&mut dedicated);

        let dst_memory = unsafe { dst_ash.allocate_memory(&allocate_info, None) }.map_err(|e| {
            unsafe { dst_ash.destroy_image(dst_image, None) };
            VulkanError::from(vk::Result::from_raw(e.as_raw()))
        })?;

        // Vulkan now owns the fd
        std::mem::forget(fd);

        if let Err(e) = unsafe { dst_ash.bind_image_memory(dst_image, dst_memory, 0) } {
            unsafe {
                dst_ash.destroy_image(dst_image, None);
                dst_ash.free_memory(dst_memory, None);
            }
            return Err(VulkanError::from(vk::Result::from_raw(e.as_raw())));
        }

        let size = wgpu::Extent3d {
            width: extent.width,
            height: extent.height,
            depth_or_array_layers: extent.depth,
        };

        let hal_texture = hal_device.texture_from_raw(
            dst_image,
            &wgpu::hal::TextureDescriptor {
                label: None,
                size,
                mip_level_count: 1,
                sample_count: 1,
                dimension: wgpu::TextureDimension::D2,
                format: wgpu::TextureFormat::Rgba8Unorm,
                usage: wgpu::TextureUses::RESOURCE
                    | wgpu::TextureUses::STORAGE_READ_ONLY
                    | wgpu::TextureUses::COPY_DST,
                memory_flags: wgpu::hal::MemoryFlags::empty(),
                view_formats: vec![],
            },
            Some(Box::new({
                let resources = ForeignTextureResources {
                    device: dst_ash.clone(),
                    image: dst_image,
                    memory: dst_memory,
                };
                move || drop(resources)
            })),
            TextureMemory::External,
        );

        let mut usage = wgpu::TextureUsages::empty();

        if src_usage.contains(vk::ImageUsageFlags::TRANSFER_SRC) {
            usage.insert(wgpu::TextureUsages::COPY_SRC);
        }
        if src_usage.contains(vk::ImageUsageFlags::TRANSFER_DST) {
            usage.insert(wgpu::TextureUsages::COPY_DST);
        }
        if src_usage.contains(vk::ImageUsageFlags::SAMPLED) {
            usage.insert(wgpu::TextureUsages::TEXTURE_BINDING);
        }
        if src_usage.contains(vk::ImageUsageFlags::STORAGE) {
            usage.insert(wgpu::TextureUsages::STORAGE_BINDING);
        }
        if src_usage.contains(vk::ImageUsageFlags::COLOR_ATTACHMENT) {
            usage.insert(wgpu::TextureUsages::RENDER_ATTACHMENT);
        }

        Ok(
            target_device.create_texture_from_hal::<wgpu::hal::vulkan::Api>(
                hal_texture,
                &wgpu::TextureDescriptor {
                    label: None,
                    size,
                    mip_level_count: 1,
                    sample_count: 1,
                    dimension: wgpu::TextureDimension::D2,
                    format: wgpu::TextureFormat::Rgba8Unorm,
                    usage,
                    view_formats: &[],
                },
            ),
        )
    }

    unsafe fn export_as_dma_fd(&self) -> Result<(OwnedFd, u64), VulkanError> {
        let mut modifier_props = vk::ImageDrmFormatModifierPropertiesEXT::default();
        ash::ext::image_drm_format_modifier::Device::load(
            self.inner.device.instance().ash(),
            self.inner.device.ash(),
        )
        .get_image_drm_format_modifier_properties(self.inner.image, &mut modifier_props)?;

        let modifier = modifier_props.drm_format_modifier;

        let raw_fd = ash::khr::external_memory_fd::Device::load(
            self.inner.device.instance().ash(),
            self.inner.device.ash(),
        )
        .get_memory_fd(
            &vk::MemoryGetFdInfoKHR::default()
                .memory(self.inner.memory[0])
                .handle_type(vk::ExternalMemoryHandleTypeFlags::DMA_BUF_EXT),
        )?;

        let fd = unsafe { OwnedFd::from_raw_fd(raw_fd) };

        Ok((fd, modifier))
    }

    /// Create a [`wgpu::Texture`] handle from this Image
    ///
    /// # Safety
    ///
    /// - Image must be created from the same Device as passed into as parameter
    /// - Image must be format `R8G8B8A8_UNORM`
    /// - Image must have have one mip level
    /// - Image must have a sample count of 1
    /// - Image must be 2D
    pub unsafe fn to_rgba8_wgpu_texture(&self, device: &wgpu::Device) -> wgpu::Texture {
        let size = wgpu::Extent3d {
            width: self.inner.extent.width,
            height: self.inner.extent.height,
            depth_or_array_layers: self.inner.extent.depth,
        };

        let this = self.clone();
        let hal_texture = device
            .as_hal::<wgpu::hal::vulkan::Api>()
            .unwrap()
            .texture_from_raw(
                ash_stable::vk::Handle::from_raw(self.inner.image.as_raw()),
                &wgpu::hal::TextureDescriptor {
                    label: None,
                    size,
                    mip_level_count: 1,
                    sample_count: 1,
                    dimension: wgpu::TextureDimension::D2,
                    format: wgpu::TextureFormat::Rgba8Unorm,
                    usage: wgpu::TextureUses::RESOURCE
                        | wgpu::TextureUses::STORAGE_READ_ONLY
                        | wgpu::TextureUses::COPY_DST,
                    memory_flags: wgpu::hal::MemoryFlags::empty(),
                    view_formats: vec![],
                },
                Some(Box::new(|| drop(this))),
                TextureMemory::External,
            );

        let mut usage = wgpu::TextureUsages::empty();

        if self.inner.usage.contains(vk::ImageUsageFlags::TRANSFER_SRC) {
            usage.insert(wgpu::TextureUsages::COPY_SRC);
        }

        if self.inner.usage.contains(vk::ImageUsageFlags::TRANSFER_DST) {
            usage.insert(wgpu::TextureUsages::COPY_DST);
        }

        if self.inner.usage.contains(vk::ImageUsageFlags::SAMPLED) {
            usage.insert(wgpu::TextureUsages::TEXTURE_BINDING);
        }

        if self.inner.usage.contains(vk::ImageUsageFlags::STORAGE) {
            usage.insert(wgpu::TextureUsages::STORAGE_BINDING);
        }

        if self
            .inner
            .usage
            .contains(vk::ImageUsageFlags::COLOR_ATTACHMENT)
        {
            usage.insert(wgpu::TextureUsages::RENDER_ATTACHMENT);
        }

        device.create_texture_from_hal::<wgpu::hal::vulkan::Api>(
            hal_texture,
            &wgpu::TextureDescriptor {
                label: None,
                size,
                mip_level_count: 1,
                sample_count: 1,
                dimension: wgpu::TextureDimension::D2,
                format: wgpu::TextureFormat::Rgba8Unorm,
                usage,
                view_formats: &[],
            },
        )
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        unsafe {
            self.device.ash().destroy_image(self.image, None);

            for memory in &self.memory {
                self.device.ash().free_memory(*memory, None);
            }
        }
    }
}

#[derive(Debug)]
pub struct ImageMemoryBarrier {
    dst: (vk::ImageLayout, vk::PipelineStageFlags2, vk::AccessFlags2),
    src: Option<(vk::ImageLayout, vk::PipelineStageFlags2, vk::AccessFlags2)>,

    src_queue_family_index: u32,
    dst_queue_family_index: u32,
}

impl ImageMemoryBarrier {
    pub fn dst(
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

    pub fn src(
        mut self,
        old_layout: vk::ImageLayout,
        src_stage_mask: vk::PipelineStageFlags2,
        src_access_flags: vk::AccessFlags2,
    ) -> Self {
        self.src = Some((old_layout, src_stage_mask, src_access_flags));
        self
    }

    pub fn queue_family_indices(
        mut self,
        src_queue_family_index: u32,
        dst_queue_family_index: u32,
    ) -> Self {
        self.src_queue_family_index = src_queue_family_index;
        self.dst_queue_family_index = dst_queue_family_index;
        self
    }
}
