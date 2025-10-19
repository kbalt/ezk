use std::os::fd::{AsRawFd, OwnedFd};

use crate::{Device, VulkanError};
use ash::vk;

#[derive(Debug)]
pub struct Semaphore {
    device: Device,
    semaphore: vk::Semaphore,
}

impl Semaphore {
    pub(crate) fn create(device: &Device) -> Result<Self, VulkanError> {
        unsafe {
            let semaphore = device
                .ash()
                .create_semaphore(&vk::SemaphoreCreateInfo::default(), None)?;

            Ok(Self {
                device: device.clone(),
                semaphore,
            })
        }
    }

    pub unsafe fn import_timeline_fd(device: &Device, fd: OwnedFd) -> Result<Self, VulkanError> {
        let mut type_create_info =
            vk::SemaphoreTypeCreateInfo::default().semaphore_type(vk::SemaphoreType::TIMELINE);
        let create_info = vk::SemaphoreCreateInfo::default().push_next(&mut type_create_info);

        let semaphore = device.ash().create_semaphore(&create_info, None)?;

        let import_semaphore_fd_info = vk::ImportSemaphoreFdInfoKHR::default()
            .semaphore(semaphore)
            .handle_type(vk::ExternalSemaphoreHandleTypeFlags::OPAQUE_FD)
            .fd(fd.as_raw_fd());

        ash::khr::external_semaphore_fd::Device::new(device.instance().ash(), device.ash())
            .import_semaphore_fd(&import_semaphore_fd_info)?;

        // Ownership of the fd transferred to the vulkan driver, forget about it
        std::mem::forget(fd);

        Ok(Self {
            device: device.clone(),
            semaphore,
        })
    }

    pub(crate) unsafe fn handle(&self) -> vk::Semaphore {
        self.semaphore
    }
}

impl Drop for Semaphore {
    fn drop(&mut self) {
        unsafe {
            self.device.ash().destroy_semaphore(self.semaphore, None);
        }
    }
}
