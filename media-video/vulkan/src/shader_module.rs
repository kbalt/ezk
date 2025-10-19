use std::sync::Arc;

use crate::{Device, VulkanError};
use ash::vk;

#[derive(Debug, Clone)]
pub(crate) struct ShaderModule {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    device: Device,
    shader_module: vk::ShaderModule,
}

impl ShaderModule {
    pub(crate) fn from_spv(device: &Device, spv: &[u32]) -> Result<Self, VulkanError> {
        unsafe {
            let create_info = vk::ShaderModuleCreateInfo::default().code(spv);

            let shader_module = device.ash().create_shader_module(&create_info, None)?;

            Ok(Self {
                inner: Arc::new(Inner {
                    device: device.clone(),
                    shader_module,
                }),
            })
        }
    }

    pub(crate) unsafe fn shader_module(&self) -> vk::ShaderModule {
        self.inner.shader_module
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        unsafe {
            self.device
                .ash()
                .destroy_shader_module(self.shader_module, None);
        }
    }
}
