use crate::{Device, VulkanError};
use ash::vk;

#[derive(Debug)]
pub struct Sampler {
    device: Device,
    sampler: vk::Sampler,
}

impl Sampler {
    pub unsafe fn create(
        device: &Device,
        create_info: &vk::SamplerCreateInfo,
    ) -> Result<Sampler, VulkanError> {
        let sampler = device.ash().create_sampler(create_info, None)?;

        Ok(Sampler {
            device: device.clone(),
            sampler,
        })
    }

    pub unsafe fn sampler(&self) -> vk::Sampler {
        self.sampler
    }
}

impl Drop for Sampler {
    fn drop(&mut self) {
        unsafe {
            self.device.ash().destroy_sampler(self.sampler, None);
        }
    }
}
