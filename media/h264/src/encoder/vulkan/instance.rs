use super::Device;
use ash::{khr::video_queue, vk};
use std::sync::Arc;

#[derive(Clone)]
pub struct Instance {
    inner: Arc<InstanceInner>,
}

struct InstanceInner {
    instance: ash::Instance,
    video_queue_instance: video_queue::Instance,
}

impl Instance {
    pub fn load(entry: &ash::Entry) -> Self {
        unsafe {
            let app_info = vk::ApplicationInfo {
                api_version: vk::make_api_version(0, 1, 4, 316),
                ..Default::default()
            };

            let instance_layers = [c"VK_LAYER_KHRONOS_validation".as_ptr()];
            let instance_extensions = [
                ash::ext::debug_utils::NAME.as_ptr(),
                c"VK_KHR_get_physical_device_properties2".as_ptr(),
            ];

            let create_info = vk::InstanceCreateInfo {
                p_application_info: &app_info,
                ..Default::default()
            }
            .enabled_layer_names(&instance_layers)
            .enabled_extension_names(&instance_extensions);

            let instance = entry.create_instance(&create_info, None).unwrap();
            let video_queue_instance = video_queue::Instance::new(entry, &instance);

            Self {
                inner: Arc::new(InstanceInner {
                    instance,
                    video_queue_instance,
                }),
            }
        }
    }

    pub fn create_device(
        &self,
        physical_device: vk::PhysicalDevice,
        create_device_info: &vk::DeviceCreateInfo,
    ) -> Device {
        unsafe {
            let device = self
                .instance()
                .create_device(physical_device, create_device_info, None)
                .unwrap();

            Device::new(self.clone(), device)
        }
    }

    pub fn instance(&self) -> &ash::Instance {
        &self.inner.instance
    }

    pub fn video_queue_instance(&self) -> &video_queue::Instance {
        &self.inner.video_queue_instance
    }
}

impl Drop for InstanceInner {
    fn drop(&mut self) {
        unsafe {
            self.instance.destroy_instance(None);
        }
    }
}
