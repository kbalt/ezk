use crate::Device;
use ash::vk;
use std::sync::Arc;

#[derive(Clone)]
pub struct VideoSession {
    inner: Arc<Inner>,
}

struct Inner {
    device: Device,
    video_session: vk::VideoSessionKHR,
    memory: Vec<vk::DeviceMemory>,
}

impl VideoSession {
    pub unsafe fn create(
        device: &Device,
        physical_device_memory_properties: &vk::PhysicalDeviceMemoryProperties,
        create_info: &vk::VideoSessionCreateInfoKHR,
    ) -> Self {
        let video_session = device
            .video_queue_device()
            .create_video_session(create_info, None)
            .unwrap();

        let len = device
            .video_queue_device()
            .get_video_session_memory_requirements_len(video_session)
            .unwrap();

        let mut video_session_memory_requirements =
            vec![vk::VideoSessionMemoryRequirementsKHR::default(); len];

        device
            .video_queue_device()
            .get_video_session_memory_requirements(
                video_session,
                &mut video_session_memory_requirements,
            )
            .unwrap();

        let bind_session_memory_infos: Vec<_> = video_session_memory_requirements
            .iter()
            .map(|video_session_memory_requirement| {
                let memory_type_index = crate::find_memory_type(
                    video_session_memory_requirement
                        .memory_requirements
                        .memory_type_bits,
                    vk::MemoryPropertyFlags::empty(),
                    physical_device_memory_properties,
                )
                .unwrap();

                let allocate_info = vk::MemoryAllocateInfo::default()
                    .memory_type_index(memory_type_index)
                    .allocation_size(video_session_memory_requirement.memory_requirements.size);

                let memory = device
                    .device()
                    .allocate_memory(&allocate_info, None)
                    .unwrap();

                vk::BindVideoSessionMemoryInfoKHR::default()
                    .memory(memory)
                    .memory_bind_index(video_session_memory_requirement.memory_bind_index)
                    .memory_size(video_session_memory_requirement.memory_requirements.size)
            })
            .collect();

        device
            .video_queue_device()
            .bind_video_session_memory(video_session, &bind_session_memory_infos)
            .unwrap();

        let memory = bind_session_memory_infos
            .into_iter()
            .map(|info| info.memory)
            .collect();

        Self {
            inner: Arc::new(Inner {
                device: device.clone(),
                video_session,
                memory,
            }),
        }
    }

    pub fn device(&self) -> &Device {
        &self.inner.device
    }

    pub fn video_session(&self) -> vk::VideoSessionKHR {
        self.inner.video_session
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        unsafe {
            self.device
                .video_queue_device()
                .destroy_video_session(self.video_session, None);

            for memory in &self.memory {
                self.device.device().free_memory(*memory, None);
            }
        }
    }
}
