use super::Instance;
use crate::{PhysicalDevice, VulkanError};
use anyhow::Context;
use ash::{
    khr::{video_encode_queue, video_queue},
    vk,
};
use std::{ffi::CStr, fmt, sync::Arc};

#[derive(Clone)]
pub struct Device {
    inner: Arc<Inner>,
}

struct Inner {
    instance: Instance,
    physical_device: PhysicalDevice,
    physical_device_memory_properties: vk::PhysicalDeviceMemoryProperties,

    device: ash::Device,

    device_extensions: DeviceVideoExtensions,

    video_queue_device: video_queue::Device,
    video_encode_queue_device: video_encode_queue::Device,

    graphics_queue_family_index: u32,
    encode_queue_family_index: u32,

    graphics_queue: vk::Queue,
    encode_queue: vk::Queue,
}

impl fmt::Debug for Device {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Device")
            .field(&self.inner.device.handle())
            .finish()
    }
}

/// All relevant extensions for video encoding
#[derive(Debug)]
pub struct DeviceVideoExtensions {
    pub video_queue: bool,
    pub video_encode_queue: bool,
    pub video_encode_h264: bool,
    pub video_encode_h265: bool,
    pub video_decode_queue: bool,
    pub video_decode_h264: bool,
    pub video_decode_h265: bool,
    pub external_memory_fd: bool,
    pub external_memory_dma_buf: bool,
    pub image_drm_format_modifier: bool,
    pub timeline_semaphore: bool,
    pub external_semaphore_fd: bool,
}

impl Device {
    /// Create a new device from a WGPU Instance
    ///
    /// This will let WGPU create the vulkan device, making sure that everything is setup just as wgpu wants it,
    /// any extensions and features for video will be added to WGPU's device creation process.
    pub fn create_wgpu(
        instance: &wgpu::Instance,
        adapter: &wgpu::Adapter,
    ) -> Result<(Device, wgpu::Device, wgpu::Queue), anyhow::Error> {
        unsafe {
            let vk_adapter = adapter.as_hal::<wgpu::hal::vulkan::Api>().unwrap();

            // Query all available device extensions
            let props = vk_adapter
                .shared_instance()
                .raw_instance()
                .enumerate_device_extension_properties(vk_adapter.raw_physical_device())?;

            let mut extensions = vec![];

            // Add all desired device extensions if they are available
            let device_extensions = DeviceVideoExtensions {
                video_queue: add2(&props, ash::khr::video_queue::NAME, &mut extensions),
                video_encode_queue: add2(
                    &props,
                    ash::khr::video_encode_queue::NAME,
                    &mut extensions,
                ),
                video_encode_h264: add2(&props, ash::khr::video_encode_h264::NAME, &mut extensions),
                video_encode_h265: add2(&props, ash::khr::video_encode_h265::NAME, &mut extensions),
                video_decode_queue: add2(
                    &props,
                    ash::khr::video_decode_queue::NAME,
                    &mut extensions,
                ),
                video_decode_h264: add2(&props, ash::khr::video_decode_h264::NAME, &mut extensions),
                video_decode_h265: add2(&props, ash::khr::video_decode_h265::NAME, &mut extensions),
                external_memory_fd: add2(
                    &props,
                    ash::khr::external_memory_fd::NAME,
                    &mut extensions,
                ),
                external_memory_dma_buf: add2(
                    &props,
                    ash::ext::external_memory_dma_buf::NAME,
                    &mut extensions,
                ),
                image_drm_format_modifier: add2(
                    &props,
                    ash::ext::image_drm_format_modifier::NAME,
                    &mut extensions,
                ),
                timeline_semaphore: add2(
                    &props,
                    ash::khr::timeline_semaphore::NAME,
                    &mut extensions,
                ),
                external_semaphore_fd: add2(
                    &props,
                    ash::khr::external_semaphore_fd::NAME,
                    &mut extensions,
                ),
            };

            // Query all available queues families
            let queue_family_properties = dbg!(
                vk_adapter
                    .shared_instance()
                    .raw_instance()
                    .get_physical_device_queue_family_properties(vk_adapter.raw_physical_device())
            );

            let mut separate_encode_queue_family_index = None;

            // Always enabling these features since they are always required
            let mut synchronization2_features =
                vk::PhysicalDeviceSynchronization2Features::default().synchronization2(true);

            let device = vk_adapter
                .open_with_callback(
                    adapter.features(),
                    &wgpu::MemoryHints::default(),
                    Some(Box::new(|args| {
                        // Add all desired extensions
                        args.extensions.extend(extensions);

                        // Add all required features
                        *args.create_info =
                            args.create_info.push_next(&mut synchronization2_features);

                        // Find the encode queue and request it
                        // TODO: currently forcing a different queue for encode operations
                        let graphics_queue_family_index =
                            args.queue_create_infos[0].queue_family_index;
                        let encode_queue_family_index = queue_family_properties
                            .iter()
                            .enumerate()
                            .position(|(i, properties)| {
                                i as u32 != graphics_queue_family_index
                                    && properties
                                        .queue_flags
                                        .contains(vk::QueueFlags::VIDEO_ENCODE_KHR)
                            });

                        // If there's a (separate) encode queue, request that
                        if let Some(index) = encode_queue_family_index {
                            separate_encode_queue_family_index = Some(index as u32);

                            args.queue_create_infos.push(
                                vk::DeviceQueueCreateInfo::default()
                                    .queue_family_index(index as u32)
                                    .queue_priorities(&[1.0]),
                            );
                        }
                    })),
                )
                .context("Failed to open WGPU device")?;

            let graphics_queue_family_index = device.device.queue_family_index();
            let encode_queue_family_index = separate_encode_queue_family_index.unwrap(); // TODO

            let (wgpu_device, wgpu_queue) = adapter
                .create_device_from_hal(
                    device,
                    &wgpu::DeviceDescriptor {
                        label: None,
                        required_features: adapter.features(),
                        required_limits: adapter.limits(),
                        experimental_features: wgpu::ExperimentalFeatures::disabled(),
                        memory_hints: wgpu::MemoryHints::default(),
                        trace: wgpu::Trace::default(),
                    },
                )
                .context("Failed to create wgpu Device & Queue pair from hal device")?;

            let vk_device = wgpu_device
                .as_hal::<wgpu::hal::vulkan::Api>()
                .expect("Just created a vulkan device");

            let graphics_queue = vk_device
                .raw_device()
                .get_device_queue(graphics_queue_family_index, 0);

            let encode_queue = vk_device
                .raw_device()
                .get_device_queue(encode_queue_family_index, 0);

            let video_queue_device = ash::khr::video_queue::Device::new(
                vk_adapter.shared_instance().raw_instance(),
                vk_device.raw_device(),
            );

            let video_encode_queue_device = video_encode_queue::Device::new(
                vk_adapter.shared_instance().raw_instance(),
                vk_device.raw_device(),
            );

            let physical_device_memory_properties = vk_adapter
                .shared_instance()
                .raw_instance()
                .get_physical_device_memory_properties(vk_adapter.raw_physical_device());

            let instance = Instance::from_wgpu(instance.clone());
            let physical_device =
                PhysicalDevice::new(instance.clone(), vk_adapter.raw_physical_device());

            let device = Device {
                inner: Arc::new(Inner {
                    instance,
                    physical_device,
                    physical_device_memory_properties,
                    device: vk_device.raw_device().clone(),
                    device_extensions,
                    video_queue_device,
                    video_encode_queue_device,
                    graphics_queue_family_index,
                    encode_queue_family_index,
                    graphics_queue,
                    encode_queue,
                }),
            };

            Ok((device, wgpu_device, wgpu_queue))
        }
    }

    pub fn create(
        physical_device: &PhysicalDevice,
        additional_extensions: &[&'static CStr],
    ) -> Result<Device, VulkanError> {
        let instance = physical_device.instance();

        // Set up queues
        let queue_family_properties = physical_device.queue_family_properties();

        let graphics_queue_family_index = queue_family_properties
            .iter()
            .position(|properties| {
                properties.queue_flags.contains(
                    vk::QueueFlags::GRAPHICS | vk::QueueFlags::COMPUTE | vk::QueueFlags::TRANSFER,
                )
            })
            .unwrap() as u32;

        let encode_queue_family_index = queue_family_properties
            .iter()
            .enumerate()
            .position(|(i, properties)| {
                i as u32 != graphics_queue_family_index
                    && properties
                        .queue_flags
                        .contains(vk::QueueFlags::VIDEO_ENCODE_KHR)
            })
            .unwrap() as u32;

        // Set up extensions
        let props = unsafe {
            instance
                .ash()
                .enumerate_device_extension_properties(physical_device.handle())?
        };

        let mut extensions = vec![];

        let device_extensions = DeviceVideoExtensions {
            video_queue: add(&props, ash::khr::video_queue::NAME, &mut extensions),
            video_encode_queue: add(&props, ash::khr::video_encode_queue::NAME, &mut extensions),
            video_encode_h264: add(&props, ash::khr::video_encode_h264::NAME, &mut extensions),
            video_encode_h265: add(&props, ash::khr::video_encode_h265::NAME, &mut extensions),
            video_decode_queue: add(&props, ash::khr::video_decode_queue::NAME, &mut extensions),
            video_decode_h264: add(&props, ash::khr::video_decode_h264::NAME, &mut extensions),
            video_decode_h265: add(&props, ash::khr::video_decode_h265::NAME, &mut extensions),
            external_memory_fd: add(&props, ash::khr::external_memory_fd::NAME, &mut extensions),
            external_memory_dma_buf: add(
                &props,
                ash::ext::external_memory_dma_buf::NAME,
                &mut extensions,
            ),
            image_drm_format_modifier: add(
                &props,
                ash::ext::image_drm_format_modifier::NAME,
                &mut extensions,
            ),
            timeline_semaphore: add(&props, ash::khr::timeline_semaphore::NAME, &mut extensions),
            external_semaphore_fd: add(
                &props,
                ash::khr::external_semaphore_fd::NAME,
                &mut extensions,
            ),
        };

        for extension in additional_extensions {
            add(&props, extension, &mut extensions);
        }

        // Always enabling these features since they are always required
        let mut synchronization2_features =
            vk::PhysicalDeviceSynchronization2Features::default().synchronization2(true);
        let mut timeline_sempahore_feature =
            vk::PhysicalDeviceTimelineSemaphoreFeatures::default().timeline_semaphore(true);

        // Currently always creating two queues
        let queue_create_infos = [
            vk::DeviceQueueCreateInfo::default()
                .queue_family_index(graphics_queue_family_index)
                .queue_priorities(&[1.0]),
            vk::DeviceQueueCreateInfo::default()
                .queue_family_index(encode_queue_family_index)
                .queue_priorities(&[1.0]),
        ];

        let create_device_info = vk::DeviceCreateInfo::default()
            .enabled_extension_names(&extensions)
            .queue_create_infos(&queue_create_infos)
            .push_next(&mut synchronization2_features)
            .push_next(&mut timeline_sempahore_feature);

        let device = unsafe {
            instance
                .ash()
                .create_device(physical_device.handle(), &create_device_info, None)?
        };

        let video_queue_device = ash::khr::video_queue::Device::new(instance.ash(), &device);
        let video_encode_queue_device = video_encode_queue::Device::new(instance.ash(), &device);

        let physical_device_memory_properties = unsafe {
            instance
                .ash()
                .get_physical_device_memory_properties(physical_device.handle())
        };

        let (graphics_queue, encode_queue) = unsafe {
            (
                device.get_device_queue(graphics_queue_family_index, 0),
                device.get_device_queue(encode_queue_family_index, 0),
            )
        };

        Ok(Device {
            inner: Arc::new(Inner {
                instance: instance.clone(),
                physical_device: physical_device.clone(),
                physical_device_memory_properties,
                device,
                device_extensions,
                video_queue_device,
                video_encode_queue_device,
                graphics_queue_family_index,
                encode_queue_family_index,
                graphics_queue,
                encode_queue,
            }),
        })
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

    pub fn physical_device(&self) -> &PhysicalDevice {
        &self.inner.physical_device
    }

    pub fn ash(&self) -> &ash::Device {
        &self.inner.device
    }

    pub fn ash_video_queue_device(&self) -> &video_queue::Device {
        &self.inner.video_queue_device
    }

    pub fn ash_video_encode_queue_device(&self) -> &video_encode_queue::Device {
        &self.inner.video_encode_queue_device
    }

    pub fn graphics_queue_family_index(&self) -> u32 {
        self.inner.graphics_queue_family_index
    }

    pub fn encode_queue_family_index(&self) -> u32 {
        self.inner.encode_queue_family_index
    }

    pub fn graphics_queue(&self) -> vk::Queue {
        self.inner.graphics_queue
    }

    pub fn encode_queue(&self) -> vk::Queue {
        self.inner.encode_queue
    }

    pub fn enabled_extensions(&self) -> &DeviceVideoExtensions {
        &self.inner.device_extensions
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

fn add(
    properties: &[vk::ExtensionProperties],
    extension: &'static CStr,
    extensions: &mut Vec<*const i8>,
) -> bool {
    let is_supported = properties
        .iter()
        .any(|x| unsafe { CStr::from_ptr(x.extension_name.as_ptr()) } == extension);

    if is_supported {
        extensions.push(extension.as_ptr());
    }

    is_supported
}

fn add2(
    properties: &[vk::ExtensionProperties],
    extension: &'static CStr,
    extensions: &mut Vec<&'static CStr>,
) -> bool {
    let is_supported = properties
        .iter()
        .any(|x| unsafe { CStr::from_ptr(x.extension_name.as_ptr()) } == extension);

    if is_supported {
        extensions.push(extension);
    }

    is_supported
}
