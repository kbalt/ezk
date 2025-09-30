use crate::Device;
use ash::vk;

pub struct Fence {
    device: Device,
    fence: vk::Fence,
}

impl Fence {
    pub fn create(device: &Device) -> Result<Self, vk::Result> {
        unsafe {
            let fence = device
                .device()
                .create_fence(&vk::FenceCreateInfo::default(), None)?;

            Ok(Self {
                device: device.clone(),
                fence,
            })
        }
    }

    pub fn device(&self) -> &Device {
        &self.device
    }

    /// Access the raw fence handle
    ///
    /// # Safety
    ///
    /// The fence must not be destroyed using this handle.
    ///
    /// `Fence` must outlive operations that rely on this fence
    pub unsafe fn fence(&self) -> vk::Fence {
        self.fence
    }

    /// Wait for the fence completion with the given timeout in nanoseconds
    ///
    /// Returns wether `true` if the fence was signalled, and `false` if the timeout elapsed
    pub fn wait(&self, timeout: u64) -> Result<bool, vk::Result> {
        unsafe {
            match self
                .device
                .device()
                .wait_for_fences(&[self.fence], true, timeout)
            {
                Ok(()) => Ok(true),
                Err(result) if result == vk::Result::TIMEOUT => Ok(false),
                Err(e) => Err(e),
            }
        }
    }

    /// Reset the fence after it was signalled
    pub fn reset(&self) -> Result<(), vk::Result> {
        unsafe { self.device.device().reset_fences(&[self.fence]) }
    }
}

impl Drop for Fence {
    fn drop(&mut self) {
        unsafe {
            self.device.device().destroy_fence(self.fence, None);
        }
    }
}
