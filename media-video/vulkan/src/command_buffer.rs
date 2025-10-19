use ash::vk::{self};
use std::sync::Arc;

use crate::{Device, VulkanError};

#[derive(Debug)]
pub(crate) struct CommandBuffer {
    inner: Arc<Inner>,
    command_buffer: vk::CommandBuffer,
}

#[derive(Debug)]
struct Inner {
    device: Device,
    pool: vk::CommandPool,
}

impl CommandBuffer {
    pub(crate) fn create(
        device: &Device,
        queue_family_index: u32,
        command_buffer_count: u32,
    ) -> Result<Vec<Self>, VulkanError> {
        let pool_create_info = vk::CommandPoolCreateInfo::default()
            .queue_family_index(queue_family_index)
            .flags(vk::CommandPoolCreateFlags::RESET_COMMAND_BUFFER);
        let pool = unsafe { device.ash().create_command_pool(&pool_create_info, None)? };

        let command_buffer_create_info = vk::CommandBufferAllocateInfo::default()
            .command_buffer_count(command_buffer_count)
            .command_pool(pool)
            .level(vk::CommandBufferLevel::PRIMARY);

        let command_buffers = unsafe {
            device
                .ash()
                .allocate_command_buffers(&command_buffer_create_info)?
        };

        let inner = Arc::new(Inner {
            device: device.clone(),
            pool,
        });

        let command_buffers = command_buffers
            .into_iter()
            .map(|command_buffer| CommandBuffer {
                inner: inner.clone(),
                command_buffer,
            })
            .collect();

        Ok(command_buffers)
    }

    pub(crate) fn device(&self) -> &Device {
        &self.inner.device
    }

    pub(crate) unsafe fn command_buffer(&self) -> vk::CommandBuffer {
        self.command_buffer
    }

    pub(crate) unsafe fn begin(
        &self,
        begin_info: &vk::CommandBufferBeginInfo,
    ) -> Result<RecordingCommandBuffer<'_>, vk::Result> {
        self.device()
            .ash()
            .begin_command_buffer(self.command_buffer(), begin_info)?;

        Ok(RecordingCommandBuffer {
            command_buffer: self,
            ended: false,
        })
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        unsafe {
            self.device.ash().destroy_command_pool(self.pool, None);
        }
    }
}

impl Drop for CommandBuffer {
    fn drop(&mut self) {
        unsafe {
            self.inner
                .device
                .ash()
                .free_command_buffers(self.inner.pool, &[self.command_buffer]);
        }
    }
}

#[derive(Debug)]
pub(crate) struct RecordingCommandBuffer<'a> {
    command_buffer: &'a CommandBuffer,
    ended: bool,
}

impl RecordingCommandBuffer<'_> {
    pub(crate) unsafe fn command_buffer(&self) -> vk::CommandBuffer {
        self.command_buffer.command_buffer()
    }

    pub(crate) fn end(mut self) -> Result<(), vk::Result> {
        self.ended = true;
        self.end_ref()
    }

    fn end_ref(&mut self) -> Result<(), vk::Result> {
        unsafe {
            self.command_buffer
                .device()
                .ash()
                .end_command_buffer(self.command_buffer())
        }
    }
}

impl Drop for RecordingCommandBuffer<'_> {
    fn drop(&mut self) {
        if self.ended {
            return;
        }

        if let Err(e) = self.end_ref() {
            log::error!("Failed to end command buffer: {e}");
        }
    }
}
