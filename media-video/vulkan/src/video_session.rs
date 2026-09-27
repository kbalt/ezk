use crate::{Device, VulkanError};
use ash::vk;
use std::{
    ptr::{null, null_mut},
    sync::Arc,
};

#[derive(Debug, Clone)]
pub(crate) struct VideoSession {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    device: Device,
    video_session: vk::VideoSessionKHR,
    video_session_memory: Vec<vk::DeviceMemory>,
}

impl VideoSession {
    pub(crate) unsafe fn create(
        device: &Device,
        create_info: &vk::VideoSessionCreateInfoKHR,
    ) -> Result<Self, VulkanError> {
        let create_video_session = device
            .ash_video_queue_device()
            .fp()
            .create_video_session_khr;
        let get_video_session_memory_requirements = device
            .ash_video_queue_device()
            .fp()
            .get_video_session_memory_requirements_khr;
        let bind_video_session_memory = device
            .ash_video_queue_device()
            .fp()
            .bind_video_session_memory_khr;

        let mut video_session = vk::VideoSessionKHR::null();
        (create_video_session)(
            device.ash().handle(),
            &raw const *create_info,
            null(),
            &raw mut video_session,
        )
        .result()?;

        let mut len = 0;
        (get_video_session_memory_requirements)(
            device.ash().handle(),
            video_session,
            &raw mut len,
            null_mut(),
        )
        .result()?;

        let mut video_session_memory_requirements =
            vec![vk::VideoSessionMemoryRequirementsKHR::default(); len as usize];

        (get_video_session_memory_requirements)(
            device.ash().handle(),
            video_session,
            &raw mut len,
            video_session_memory_requirements.as_mut_ptr(),
        )
        .result()?;

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

            let memory = device.ash().allocate_memory(&allocate_info, None)?;

            let bind_session_memory_info = vk::BindVideoSessionMemoryInfoKHR::default()
                .memory(memory)
                .memory_bind_index(video_session_memory_requirement.memory_bind_index)
                .memory_size(video_session_memory_requirement.memory_requirements.size);

            video_session_memory.push(memory);
            bind_session_memory_infos.push(bind_session_memory_info);
        }

        bind_video_session_memory(
            device.ash().handle(),
            video_session,
            len,
            bind_session_memory_infos.as_ptr(),
        )
        .result()?;

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

    pub(crate) fn device(&self) -> &Device {
        &self.inner.device
    }

    pub(crate) unsafe fn video_session(&self) -> vk::VideoSessionKHR {
        self.inner.video_session
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        unsafe {
            let destroy_video_session = self
                .device
                .ash_video_queue_device()
                .fp()
                .destroy_video_session_khr;

            (destroy_video_session)(self.device.ash().handle(), self.video_session, null());

            for memory in &self.video_session_memory {
                self.device.ash().free_memory(*memory, None);
            }
        }
    }
}
