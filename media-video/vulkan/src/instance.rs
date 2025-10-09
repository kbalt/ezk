use ash::{ext::debug_utils, khr::video_queue, vk};
use std::sync::Arc;

use crate::{PhysicalDevice, VulkanError};

#[derive(Clone)]
pub struct Instance {
    inner: Arc<Inner>,
}

struct Inner {
    _entry: ash::Entry,
    instance: ash::Instance,
    video_queue_instance: video_queue::Instance,

    #[cfg(debug_assertions)]
    debug_messenger: vk::DebugUtilsMessengerEXT,
}

impl Instance {
    pub fn load(entry: ash::Entry) -> Result<Self, VulkanError> {
        unsafe {
            let app_info = vk::ApplicationInfo {
                api_version: vk::make_api_version(0, 1, 3, 316),
                ..Default::default()
            };

            let instance_layers = [
                #[cfg(debug_assertions)]
                c"VK_LAYER_KHRONOS_validation".as_ptr(),
            ];
            let instance_extensions = [
                #[cfg(debug_assertions)]
                ash::ext::debug_utils::NAME.as_ptr(),
            ];

            let enabled = [
                // vk::ValidationFeatureEnableEXT::BEST_PRACTICES, // TODO: SEGFAULT under RADV
                vk::ValidationFeatureEnableEXT::SYNCHRONIZATION_VALIDATION,
            ];
            let mut validation_features =
                vk::ValidationFeaturesEXT::default().enabled_validation_features(&enabled);

            let mut create_info = vk::InstanceCreateInfo {
                p_application_info: &app_info,
                ..Default::default()
            }
            .enabled_layer_names(&instance_layers)
            .enabled_extension_names(&instance_extensions);

            if cfg!(debug_assertions) {
                create_info = create_info.push_next(&mut validation_features);
            }

            let instance = entry.create_instance(&create_info, None)?;

            #[cfg(debug_assertions)]
            let debug_messenger = debug_utils::Instance::new(&entry, &instance)
                .create_debug_utils_messenger(
                    &vk::DebugUtilsMessengerCreateInfoEXT::default()
                        .message_severity(
                            vk::DebugUtilsMessageSeverityFlagsEXT::VERBOSE
                                | vk::DebugUtilsMessageSeverityFlagsEXT::WARNING
                                | vk::DebugUtilsMessageSeverityFlagsEXT::INFO
                                | vk::DebugUtilsMessageSeverityFlagsEXT::ERROR,
                        )
                        .message_type(
                            vk::DebugUtilsMessageTypeFlagsEXT::GENERAL
                                | vk::DebugUtilsMessageTypeFlagsEXT::VALIDATION
                                | vk::DebugUtilsMessageTypeFlagsEXT::PERFORMANCE,
                        )
                        .pfn_user_callback(Some(debug_utils_callback)),
                    None,
                )?;

            let video_queue_instance = video_queue::Instance::new(&entry, &instance);

            Ok(Self {
                inner: Arc::new(Inner {
                    _entry: entry,
                    instance,
                    video_queue_instance,
                    #[cfg(debug_assertions)]
                    debug_messenger,
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

    pub fn physical_devices(&self) -> Result<Vec<PhysicalDevice>, vk::Result> {
        unsafe {
            let physical_devices = self
                .instance()
                .enumerate_physical_devices()?
                .into_iter()
                .map(|physical_device| PhysicalDevice::new(self.clone(), physical_device))
                .collect();

            Ok(physical_devices)
        }
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        unsafe {
            #[cfg(debug_assertions)]
            debug_utils::Instance::new(&self._entry, &self.instance)
                .destroy_debug_utils_messenger(self.debug_messenger, None);

            self.instance.destroy_instance(None);
        }
    }
}

#[cfg(debug_assertions)]
unsafe extern "system" fn debug_utils_callback(
    message_severity: vk::DebugUtilsMessageSeverityFlagsEXT,
    message_types: vk::DebugUtilsMessageTypeFlagsEXT,
    p_callback_data: *const vk::DebugUtilsMessengerCallbackDataEXT<'_>,
    _p_user_data: *mut std::ffi::c_void,
) -> vk::Bool32 {
    use std::ffi::CStr;

    let data = &*p_callback_data;
    match message_severity {
        vk::DebugUtilsMessageSeverityFlagsEXT::ERROR => {
            log::error!(target: "vulkan", "{message_types:?}: {:?}", CStr::from_ptr(data.p_message))
        }
        vk::DebugUtilsMessageSeverityFlagsEXT::WARNING => {
            log::warn!(target: "vulkan", "{message_types:?}: {:?}", CStr::from_ptr(data.p_message))
        }
        vk::DebugUtilsMessageSeverityFlagsEXT::INFO => {
            log::info!(target: "vulkan", "{message_types:?}: {:?}", CStr::from_ptr(data.p_message))
        }
        vk::DebugUtilsMessageSeverityFlagsEXT::VERBOSE => {
            log::debug!(target: "vulkan", "{message_types:?}: {:?}", CStr::from_ptr(data.p_message))
        }
        _ => {
            log::error!(target: "vulkan", "{message_severity:?} - {message_types:?}: {:?}", CStr::from_ptr(data.p_message))
        }
    }

    0
}
