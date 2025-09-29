use std::sync::Arc;

use ash::vk;

use crate::Device;

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
        physical_device_memory_properties: &vk::PhysicalDeviceMemoryProperties,
        create_info: &vk::ImageCreateInfo<'_>,
    ) -> Self {
        let image = device.device().create_image(create_info, None).unwrap();
        let memory_requirements = device.device().get_image_memory_requirements(image);

        let alloc_info = vk::MemoryAllocateInfo::default()
            .allocation_size(memory_requirements.size)
            .memory_type_index(
                crate::find_memory_type(
                    memory_requirements.memory_type_bits,
                    vk::MemoryPropertyFlags::DEVICE_LOCAL,
                    physical_device_memory_properties,
                )
                .unwrap(),
            );

        let memory = device.device().allocate_memory(&alloc_info, None).unwrap();
        device.device().bind_image_memory(image, memory, 0).unwrap();

        Self {
            inner: Arc::new(Inner {
                device: device.clone(),
                image,
                memory,
            }),
        }
    }

    pub fn device(&self) -> &Device {
        &self.inner.device
    }

    pub fn image(&self) -> vk::Image {
        self.inner.image
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
