use crate::{Device, VulkanError};
use ash::vk;
use std::sync::Arc;

#[derive(Clone)]
pub struct VideoSession {
    inner: Arc<Inner>,
}

struct Inner {
    device: Device,
    video_session: vk::VideoSessionKHR,
    video_session_memory: Vec<vk::DeviceMemory>,
}

impl VideoSession {
    pub unsafe fn create(
        device: &Device,
        create_info: &vk::VideoSessionCreateInfoKHR,
    ) -> Result<Self, VulkanError> {
        let video_session = device
            .video_queue_device()
            .create_video_session(create_info, None)?;

        let len = device
            .video_queue_device()
            .get_video_session_memory_requirements_len(video_session)?;

        let mut video_session_memory_requirements =
            vec![vk::VideoSessionMemoryRequirementsKHR::default(); len];

        device
            .video_queue_device()
            .get_video_session_memory_requirements(
                video_session,
                &mut video_session_memory_requirements,
            )?;

        let mut bind_session_memory_infos = vec![];
        let mut video_session_memory = vec![];

        for video_session_memory_requirement in video_session_memory_requirements {
            let memory_type_index = device.find_memory_type(
                video_session_memory_requirement
                    .memory_requirements
                    .memory_type_bits,
                vk::MemoryPropertyFlags::empty(),
            )?;

            let allocate_info = vk::MemoryAllocateInfo::default()
                .memory_type_index(memory_type_index)
                .allocation_size(video_session_memory_requirement.memory_requirements.size);

            let memory = device.device().allocate_memory(&allocate_info, None)?;

            let bind_session_memory_info = vk::BindVideoSessionMemoryInfoKHR::default()
                .memory(memory)
                .memory_bind_index(video_session_memory_requirement.memory_bind_index)
                .memory_size(video_session_memory_requirement.memory_requirements.size);

            video_session_memory.push(memory);
            bind_session_memory_infos.push(bind_session_memory_info);
        }

        device
            .video_queue_device()
            .bind_video_session_memory(video_session, &bind_session_memory_infos)?;

        let memory = bind_session_memory_infos
            .into_iter()
            .map(|info| info.memory)
            .collect();

        Ok(Self {
            inner: Arc::new(Inner {
                device: device.clone(),
                video_session,
                video_session_memory: memory,
            }),
        })
    }

    pub fn device(&self) -> &Device {
        &self.inner.device
    }

    pub unsafe fn video_session(&self) -> vk::VideoSessionKHR {
        self.inner.video_session
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        unsafe {
            self.device
                .video_queue_device()
                .destroy_video_session(self.video_session, None);

            for memory in &self.video_session_memory {
                self.device.device().free_memory(*memory, None);
            }
        }
    }
}
