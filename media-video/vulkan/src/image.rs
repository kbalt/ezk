use crate::{Device, VulkanError};
use ash::vk;
use std::sync::Arc;

#[derive(Clone)]
pub struct Image {
    inner: Arc<Inner>,
}

struct Inner {
    device: Device,
    image: vk::Image,
    memory: vk::DeviceMemory,
}

impl Image {
    pub unsafe fn create(
        device: &Device,
        create_info: &vk::ImageCreateInfo<'_>,
    ) -> Result<Self, VulkanError> {
        let image = device.device().create_image(create_info, None)?;
        let memory_requirements = device.device().get_image_memory_requirements(image);

        let alloc_info = vk::MemoryAllocateInfo::default()
            .allocation_size(memory_requirements.size)
            .memory_type_index(device.find_memory_type(
                memory_requirements.memory_type_bits,
                vk::MemoryPropertyFlags::DEVICE_LOCAL,
            )?);

        let memory = device.device().allocate_memory(&alloc_info, None)?;
        device.device().bind_image_memory(image, memory, 0)?;

        Ok(Self {
            inner: Arc::new(Inner {
                device: device.clone(),
                image,
                memory,
            }),
        })
    }

    pub fn device(&self) -> &Device {
        &self.inner.device
    }

    pub unsafe fn image(&self) -> vk::Image {
        self.inner.image
    }

    #[allow(clippy::too_many_arguments)]
    pub unsafe fn cmd_memory_barrier2(
        &self,
        command_buffer: vk::CommandBuffer,

        old_layout: vk::ImageLayout,
        new_layout: vk::ImageLayout,

        src_queue_family_index: u32,
        dst_queue_family_index: u32,

        src_stage_mask: vk::PipelineStageFlags2,
        src_access_mask: vk::AccessFlags2,

        dst_stage_mask: vk::PipelineStageFlags2,
        dst_access_mask: vk::AccessFlags2,

        base_array_layer: u32,
    ) {
        let barrier = vk::ImageMemoryBarrier2::default()
            .image(self.image())
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
                base_array_layer,
                layer_count: 1,
            });

        let barriers = [barrier];
        let dependency_info = vk::DependencyInfoKHR::default().image_memory_barriers(&barriers);

        self.inner
            .device
            .device()
            .cmd_pipeline_barrier2(command_buffer, &dependency_info);
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        unsafe {
            self.device.device().destroy_image(self.image, None);
            self.device.device().free_memory(self.memory, None);
        }
    }
}
