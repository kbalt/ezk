use crate::Device;
use ash::vk;

pub struct Semaphore {
    device: Device,
    semaphore: vk::Semaphore,
}

impl Semaphore {
    pub fn create(device: &Device) -> Result<Self, vk::Result> {
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
