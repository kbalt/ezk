use crate::{Device, VulkanError};
use ash::vk;
use naga::{
    back::spv,
    front::wgsl,
    valid::{Capabilities, ShaderStages, SubgroupOperationSet, ValidationFlags, Validator},
};
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ShaderModule {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    device: Device,
    shader_module: vk::ShaderModule,
}

impl ShaderModule {
    pub fn from_spv(device: &Device, spv: &[u32]) -> Result<Self, VulkanError> {
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

    pub fn compile_wgsl_to_spv(source: &str) -> Vec<u32> {
        let module = match wgsl::parse_str(source) {
            Ok(module) => module,
            Err(e) => {
                panic!("{}", e.emit_to_string(source))
            }
        };

        let module_info = match Validator::new(ValidationFlags::all(), Capabilities::all())
            .subgroup_stages(ShaderStages::COMPUTE)
            .subgroup_operations(SubgroupOperationSet::all())
            .validate(&module)
        {
            Ok(module_info) => module_info,
            Err(e) => {
                panic!("{}", e.emit_to_string(source));
            }
        };

        let mut spv = Vec::new();

        if let Err(e) = spv::Writer::new(&spv::Options::default()).unwrap().write(
            &module,
            &module_info,
            None,
            &None,
            &mut spv,
        ) {
            panic!("{e}")
        }

        spv
    }

    pub unsafe fn shader_module(&self) -> vk::ShaderModule {
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
