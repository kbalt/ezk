use crate::VulkanError;

use super::Instance;
use ash::{
    khr::{video_encode_queue, video_queue},
    vk,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct Device {
    inner: Arc<Inner>,
}

struct Inner {
    instance: Instance,
    device: ash::Device,
    video_queue_device: video_queue::Device,
    video_encode_queue_device: video_encode_queue::Device,

    physical_device_memory_properties: vk::PhysicalDeviceMemoryProperties,
}

impl Device {
    pub unsafe fn create(
        instance: &Instance,
        physical_device: vk::PhysicalDevice,
        create_device_info: &vk::DeviceCreateInfo,
    ) -> Result<Device, VulkanError> {
        unsafe {
            let device =
                instance
                    .instance()
                    .create_device(physical_device, create_device_info, None)?;

            let video_queue_device =
                ash::khr::video_queue::Device::new(instance.instance(), &device);
            let video_encode_queue_device =
                video_encode_queue::Device::new(instance.instance(), &device);
            let physical_device_memory_properties = instance
                .instance()
                .get_physical_device_memory_properties(physical_device);

            Ok(Self {
                inner: Arc::new(Inner {
                    instance: instance.clone(),
                    device,
                    video_queue_device,
                    video_encode_queue_device,
                    physical_device_memory_properties,
                }),
            })
        }
    }

    pub(crate) fn find_memory_type(
        &self,
        memory_type_bits: u32,
        properties: vk::MemoryPropertyFlags,
    ) -> Result<u32, VulkanError> {
        for (i, memory_type) in self
            .inner
            .physical_device_memory_properties
            .memory_types
            .iter()
            .enumerate()
        {
            let type_supported = (memory_type_bits & (1 << i)) != 0;
            let has_properties = memory_type.property_flags.contains(properties);
            if type_supported && has_properties {
                return Ok(i as u32);
            }
        }

        Err(VulkanError::CannotFindMemoryType {
            memory_type_bits,
            properties,
        })
    }

    pub fn instance(&self) -> &Instance {
        &self.inner.instance
    }

    pub fn device(&self) -> &ash::Device {
        &self.inner.device
    }

    pub fn video_queue_device(&self) -> &video_queue::Device {
        &self.inner.video_queue_device
    }

    pub fn video_encode_queue_device(&self) -> &video_encode_queue::Device {
        &self.inner.video_encode_queue_device
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        unsafe {
            if let Err(e) = self.device.device_wait_idle() {
                log::warn!("device_wait_idle failed: {e:?}");
            }

            self.device.destroy_device(None);
        }
    }
}
