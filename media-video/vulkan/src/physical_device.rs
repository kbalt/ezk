use std::{ffi::CStr, fmt, ptr};

use crate::{Instance, encoder::codec::VulkanEncCodec};
use anyhow::Context as _;
use ash::vk::{self, Handle, PhysicalDeviceProperties, TaggedStructure};
use ash_stable::vk::Handle as _;

#[derive(Debug, Clone, Copy)]
pub struct DrmModifier {
    pub modifier: u64,
    pub plane_count: u32,
    pub tiling_features: vk::FormatFeatureFlags2,
}

#[derive(Clone)]
pub struct PhysicalDevice {
    instance: Instance,
    physical_device: vk::PhysicalDevice,
}

impl PhysicalDevice {
    pub(crate) fn new(instance: Instance, physical_device: vk::PhysicalDevice) -> Self {
        PhysicalDevice {
            instance,
            physical_device,
        }
    }

    pub fn instance(&self) -> &Instance {
        &self.instance
    }

    pub fn handle(&self) -> vk::PhysicalDevice {
        self.physical_device
    }

    pub fn properties(&self) -> vk::PhysicalDeviceProperties {
        unsafe {
            self.instance
                .ash()
                .get_physical_device_properties(self.physical_device)
        }
    }

    pub fn queue_family_properties(&self) -> Vec<vk::QueueFamilyProperties> {
        unsafe {
            self.instance
                .ash()
                .get_physical_device_queue_family_properties(self.physical_device)
        }
    }

    pub fn video_format_properties(
        &self,
        video_profile_infos: &[vk::VideoProfileInfoKHR<'_>],
    ) -> Result<Vec<vk::VideoFormatPropertiesKHR<'static>>, vk::Result> {
        let mut video_profile_list_info =
            vk::VideoProfileListInfoKHR::default().profiles(video_profile_infos);
        let physical_device_video_format_info = vk::PhysicalDeviceVideoFormatInfoKHR::default()
            .image_usage(vk::ImageUsageFlags::VIDEO_ENCODE_SRC_KHR)
            .push(&mut video_profile_list_info);

        let get_physical_device_video_format_properties = self
            .instance
            .video_queue_instance()
            .fp()
            .get_physical_device_video_format_properties_khr;

        let mut len = 0;
        unsafe {
            (get_physical_device_video_format_properties)(
                self.physical_device,
                &raw const physical_device_video_format_info,
                &raw mut len,
                ptr::null_mut(),
            )
            .result()?
        };

        let mut video_format_properties =
            vec![vk::VideoFormatPropertiesKHR::default(); len as usize];
        unsafe {
            (get_physical_device_video_format_properties)(
                self.physical_device,
                &raw const physical_device_video_format_info,
                &raw mut len,
                video_format_properties.as_mut_ptr(),
            )
            .result()?
        };

        Ok(video_format_properties)
    }

    pub fn video_capabilities<'a, C: VulkanEncCodec>(
        &self,
        video_profile_info: vk::VideoProfileInfoKHR<'a>,
    ) -> Result<
        (
            vk::VideoCapabilitiesKHR<'static>,
            vk::VideoEncodeCapabilitiesKHR<'static>,
            C::Capabilities<'static>,
        ),
        vk::Result,
    > {
        let mut codec_caps = C::Capabilities::default();
        let mut encode_caps = vk::VideoEncodeCapabilitiesKHR {
            p_next: (&raw mut codec_caps).cast(),
            ..Default::default()
        };
        let mut caps = vk::VideoCapabilitiesKHR {
            p_next: (&raw mut encode_caps).cast(),
            ..Default::default()
        };

        let get_physical_device_video_capabilities = self
            .instance()
            .video_queue_instance()
            .fp()
            .get_physical_device_video_capabilities_khr;

        unsafe {
            (get_physical_device_video_capabilities)(
                self.physical_device,
                &raw const video_profile_info,
                &raw mut caps,
            )
            .result()?;
        }

        Ok((caps, encode_caps, codec_caps))
    }

    pub fn supported_drm_modifier(&self, format: vk::Format) -> Vec<DrmModifier> {
        unsafe {
            let mut modifier_list = vk::DrmFormatModifierPropertiesList2EXT::default();
            let mut format_properties = vk::FormatProperties2::default().push(&mut modifier_list);

            self.instance()
                .ash()
                .get_physical_device_format_properties2(
                    self.handle(),
                    format,
                    &mut format_properties,
                );

            let mut properties = vec![
                vk::DrmFormatModifierProperties2EXT::default();
                modifier_list.drm_format_modifier_count as usize
            ];

            let mut modifier_list = vk::DrmFormatModifierPropertiesList2EXT::default()
                .drm_format_modifier_properties(&mut properties);
            let mut format_properties = vk::FormatProperties2::default().push(&mut modifier_list);

            self.instance()
                .ash()
                .get_physical_device_format_properties2(
                    self.handle(),
                    format,
                    &mut format_properties,
                );

            properties
                .into_iter()
                .map(|props| DrmModifier {
                    modifier: props.drm_format_modifier,
                    plane_count: props.drm_format_modifier_plane_count,
                    tiling_features: props.drm_format_modifier_tiling_features,
                })
                .collect()
        }
    }

    pub unsafe fn to_wgpu(&self, instance: &wgpu::Instance) -> anyhow::Result<wgpu::Adapter> {
        instance
            .enumerate_adapters(wgpu::Backends::VULKAN)
            .into_iter()
            .find(|a| {
                let raw = a
                    .as_hal::<wgpu::hal::vulkan::Api>()
                    .unwrap()
                    .raw_physical_device();

                self.handle().as_raw() == raw.as_raw()
            })
            .context("Failed to find adapter when enumerating vulkan adapters")
    }
}

impl fmt::Debug for PhysicalDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let PhysicalDeviceProperties {
            api_version,
            driver_version,
            vendor_id,
            device_id,
            device_type,
            mut device_name,
            ..
        } = self.properties();

        let api_version = (
            vk::api_version_major(api_version),
            vk::api_version_minor(api_version),
            vk::api_version_patch(api_version),
        );

        let driver_version = (
            vk::api_version_major(driver_version),
            vk::api_version_minor(driver_version),
            vk::api_version_patch(driver_version),
        );

        device_name[vk::MAX_PHYSICAL_DEVICE_NAME_SIZE - 1] = 0; // you never know
        let device_name = unsafe { CStr::from_ptr(device_name.as_ptr()) };

        f.debug_struct("PhysicalDevice")
            .field("physical_device", &self.physical_device)
            .field("api_version", &api_version)
            .field("driver_version", &driver_version)
            .field("vendor_id", &vendor_id)
            .field("device_id", &device_id)
            .field("device_type", &device_type)
            .field("device_name", &device_name)
            .finish()
    }
}
