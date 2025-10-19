use ash::{ext::debug_utils, khr::video_queue, vk};
use std::{ffi::CStr, fmt, sync::Arc};

use crate::{PhysicalDevice, VulkanError};

const INSTANCE_API_VERSION: u32 = vk::make_api_version(0, 1, 3, 316);

#[derive(Clone)]
pub struct Instance {
    inner: Arc<Inner>,
}

struct Inner {
    _entry: ash::Entry,
    instance: ash::Instance,
    video_queue_instance: video_queue::Instance,

    // This instance was created by wgpu, so hold a reference and don't destroy it on drop
    wgpu: Option<wgpu::Instance>,

    // enabled_extensions: Vec<&'static CStr>,
    debug_messenger: Option<vk::DebugUtilsMessengerEXT>,
}

impl fmt::Debug for Instance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Instance")
            .field(&self.inner.instance.handle())
            .finish_non_exhaustive()
    }
}

impl Instance {
    pub const INSTANCE_VERSION: u32 = vk::make_api_version(0, 1, 3, 316);

    pub unsafe fn from_wgpu(wgpu: wgpu::Instance) -> Instance {
        let vk_instance = wgpu.as_hal::<wgpu::hal::vulkan::Api>().unwrap();

        let entry = vk_instance.shared_instance().entry().clone();
        let instance = vk_instance.shared_instance().raw_instance().clone();

        let video_queue_instance = video_queue::Instance::new(&entry, &instance);

        Instance {
            inner: Arc::new(Inner {
                _entry: entry,
                instance,
                video_queue_instance,
                wgpu: Some(wgpu),
                debug_messenger: None,
            }),
        }
    }

    pub fn create(
        entry: ash::Entry,
        additional_extensions: &[&'static CStr],
    ) -> Result<Self, VulkanError> {
        unsafe {
            let app_info = vk::ApplicationInfo {
                api_version: INSTANCE_API_VERSION,
                ..Default::default()
            };

            let instance_layers = [
                #[cfg(debug_assertions)]
                c"VK_LAYER_KHRONOS_validation".as_ptr(),
            ];

            let mut instance_extensions = vec![
                #[cfg(debug_assertions)]
                ash::ext::debug_utils::NAME.as_ptr(),
            ];

            for extension in additional_extensions {
                instance_extensions.push(extension.as_ptr());
            }

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

            let debug_messenger = if cfg!(debug_assertions) {
                Some(
                    debug_utils::Instance::new(&entry, &instance).create_debug_utils_messenger(
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
                    )?,
                )
            } else {
                None
            };

            let video_queue_instance = video_queue::Instance::new(&entry, &instance);

            Ok(Self {
                inner: Arc::new(Inner {
                    _entry: entry,
                    instance,
                    video_queue_instance,
                    // enabled_extensions: instance_extensions
                    //     .into_iter()
                    //     .map(|c| CStr::from_ptr(c))
                    //     .collect(),
                    wgpu: None,
                    debug_messenger,
                }),
            })
        }
    }

    // pub fn to_wgpu(&self) -> Result<wgpu::Instance, wgpu::hal::InstanceError> {
    //     let this = self.clone();

    //     unsafe {
    //         let hal_instance = wgpu::hal::vulkan::Instance::from_raw(
    //             self.inner._entry.clone(),
    //             self.inner.instance.clone(),
    //             INSTANCE_API_VERSION,
    //             0,
    //             None,
    //             self.inner.enabled_extensions.clone(),
    //             wgpu::InstanceFlags::default(),
    //             Default::default(),
    //             false,
    //             Some(Box::new(|| drop(this))),
    //         )?;

    //         Ok(wgpu::Instance::from_hal::<wgpu::hal::vulkan::Api>(
    //             hal_instance,
    //         ))
    //     }
    // }

    pub fn ash(&self) -> &ash::Instance {
        &self.inner.instance
    }

    pub fn video_queue_instance(&self) -> &video_queue::Instance {
        &self.inner.video_queue_instance
    }

    pub fn physical_devices(&self) -> Result<Vec<PhysicalDevice>, vk::Result> {
        unsafe {
            let physical_devices = self
                .ash()
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
            if self.wgpu.is_none() {
                if let Some(debug_messenger) = self.debug_messenger.take() {
                    debug_utils::Instance::new(&self._entry, &self.instance)
                        .destroy_debug_utils_messenger(debug_messenger, None);
                }

                self.instance.destroy_instance(None);
            }
        }
    }
}

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

    vk::FALSE
}
