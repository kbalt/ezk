use crate::{Device, VulkanError};
use ash::vk::{self, TaggedStructure};
use std::{
    os::fd::{AsRawFd, OwnedFd},
    sync::Arc,
};

#[derive(Debug, Clone)]
pub struct Semaphore {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    device: Device,
    handle: vk::Semaphore,
}

impl Semaphore {
    pub fn create(device: &Device) -> Result<Self, VulkanError> {
        unsafe {
            let handle = device
                .ash()
                .create_semaphore(&vk::SemaphoreCreateInfo::default(), None)?;

            Ok(Semaphore {
                inner: Arc::new(Inner {
                    device: device.clone(),
                    handle,
                }),
            })
        }
    }

    pub fn create_timeline(device: &Device) -> Result<Self, VulkanError> {
        if !device.enabled_extensions().timeline_semaphore {
            return Err(VulkanError::MissingExtension("timeline_semaphore"));
        }

        unsafe {
            let mut type_create_info =
                vk::SemaphoreTypeCreateInfo::default().semaphore_type(vk::SemaphoreType::TIMELINE);
            let create_info = vk::SemaphoreCreateInfo::default().push(&mut type_create_info);

            let handle = device.ash().create_semaphore(&create_info, None)?;

            Ok(Semaphore {
                inner: Arc::new(Inner {
                    device: device.clone(),
                    handle,
                }),
            })
        }
    }

    pub unsafe fn import_timeline_fd(device: &Device, fd: OwnedFd) -> Result<Self, VulkanError> {
        if !device.enabled_extensions().timeline_semaphore {
            return Err(VulkanError::MissingExtension("timeline_semaphore"));
        }

        if !device.enabled_extensions().external_semaphore_fd {
            return Err(VulkanError::MissingExtension("external_semaphore_fd"));
        }

        let mut type_create_info =
            vk::SemaphoreTypeCreateInfo::default().semaphore_type(vk::SemaphoreType::TIMELINE);
        let create_info = vk::SemaphoreCreateInfo::default().push(&mut type_create_info);

        let handle = device.ash().create_semaphore(&create_info, None)?;

        let import_semaphore_fd_info = vk::ImportSemaphoreFdInfoKHR::default()
            .semaphore(handle)
            .handle_type(vk::ExternalSemaphoreHandleTypeFlags::OPAQUE_FD)
            .fd(fd.as_raw_fd());

        ash::khr::external_semaphore_fd::Device::load(device.instance().ash(), device.ash())
            .import_semaphore_fd(&import_semaphore_fd_info)?;

        // Ownership of the fd transferred to the vulkan driver, forget about it
        std::mem::forget(fd);

        Ok(Semaphore {
            inner: Arc::new(Inner {
                device: device.clone(),
                handle,
            }),
        })
    }

    pub unsafe fn handle(&self) -> vk::Semaphore {
        self.inner.handle
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        unsafe {
            self.device.ash().destroy_semaphore(self.handle, None);
        }
    }
}
