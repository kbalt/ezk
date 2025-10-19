use crate::{Device, VulkanError};
use ash::vk;

#[derive(Debug)]
pub(crate) struct Fence {
    device: Device,
    fence: vk::Fence,
}

impl Fence {
    pub(crate) fn create(device: &Device) -> Result<Self, VulkanError> {
        unsafe {
            let fence = device
                .ash()
                .create_fence(&vk::FenceCreateInfo::default(), None)?;

            Ok(Self {
                device: device.clone(),
                fence,
            })
        }
    }

    pub(crate) unsafe fn fence(&self) -> vk::Fence {
        self.fence
    }

    pub(crate) fn wait(&self, timeout: u64) -> Result<bool, VulkanError> {
        unsafe {
            match self
                .device
                .ash()
                .wait_for_fences(&[self.fence], true, timeout)
            {
                Ok(()) => Ok(true),
                Err(result) if result == vk::Result::TIMEOUT => Ok(false),
                Err(e) => Err(e.into()),
            }
        }
    }

    pub(crate) fn reset(&self) -> Result<(), VulkanError> {
        unsafe { Ok(self.device.ash().reset_fences(&[self.fence])?) }
    }
}

impl Drop for Fence {
    fn drop(&mut self) {
        unsafe {
            self.device.ash().destroy_fence(self.fence, None);
        }
    }
}
