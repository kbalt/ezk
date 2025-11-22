use crate::{Device, VulkanError};
use ash::vk;

pub struct Semaphore {
    device: Device,
    semaphore: vk::Semaphore,
}

impl Semaphore {
    pub fn create(device: &Device) -> Result<Self, VulkanError> {
        unsafe {
            let semaphore = device
                .device()
                .create_semaphore(&vk::SemaphoreCreateInfo::default(), None)?;

            Ok(Self {
                device: device.clone(),
                semaphore,
            })
        }
    }

    pub fn device(&self) -> &Device {
        &self.device
    }

    /// Access to the raw semaphore handle
    ///
    /// # Safety
    ///
    /// The semaphore must not be destroyed using this handle.
    ///
    /// `Semaphore` must outlive operations that depend on it.
    pub unsafe fn semaphore(&self) -> vk::Semaphore {
        self.semaphore
    }
}

impl Drop for Semaphore {
    fn drop(&mut self) {
        unsafe {
            self.device.device().destroy_semaphore(self.semaphore, None);
        }
    }
}
