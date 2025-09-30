use std::sync::Arc;

use ash::vk;

use crate::Device;

pub struct CommandBuffer {
    inner: Arc<Inner>,
    command_buffer: vk::CommandBuffer,
}

struct Inner {
    device: Device,
    pool: vk::CommandPool,
}

impl CommandBuffer {
    pub unsafe fn create(
        device: &Device,
        queue_family_index: u32,
        command_buffer_count: u32,
    ) -> Vec<Self> {
        let pool_create_info = vk::CommandPoolCreateInfo::default()
            .queue_family_index(queue_family_index)
            .flags(vk::CommandPoolCreateFlags::RESET_COMMAND_BUFFER);
        let pool = device
            .device()
            .create_command_pool(&pool_create_info, None)
            .unwrap();

        let command_buffer_create_info = vk::CommandBufferAllocateInfo::default()
            .command_buffer_count(command_buffer_count)
            .command_pool(pool)
            .level(vk::CommandBufferLevel::PRIMARY);

        let command_buffers = device
            .device()
            .allocate_command_buffers(&command_buffer_create_info)
            .unwrap();

        let inner = Arc::new(Inner {
            device: device.clone(),
            pool,
        });

        command_buffers
            .into_iter()
            .map(|command_buffer| CommandBuffer {
                inner: inner.clone(),
                command_buffer,
            })
            .collect()
    }

    pub fn device(&self) -> &Device {
        &self.inner.device
    }

    pub unsafe fn command_buffer(&self) -> vk::CommandBuffer {
        self.command_buffer
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        unsafe {
            self.device.device().destroy_command_pool(self.pool, None);
        }
    }
}
