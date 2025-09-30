use ash::{khr::video_queue, vk};
use std::sync::Arc;

use crate::VulkanError;

#[derive(Clone)]
pub struct Instance {
    inner: Arc<Inner>,
}

struct Inner {
    instance: ash::Instance,
    video_queue_instance: video_queue::Instance,
}

impl Instance {
    pub fn load(entry: &ash::Entry) -> Result<Self, VulkanError> {
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

            let instance = entry.create_instance(&create_info, None)?;
            let video_queue_instance = video_queue::Instance::new(entry, &instance);

            Ok(Self {
                inner: Arc::new(Inner {
                    instance,
                    video_queue_instance,
                }),
            })
        }
    }

    pub fn instance(&self) -> &ash::Instance {
        &self.inner.instance
    }

    pub fn video_queue_instance(&self) -> &video_queue::Instance {
        &self.inner.video_queue_instance
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        unsafe {
            self.instance.destroy_instance(None);
        }
    }
}
