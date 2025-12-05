use std::{ffi::CStr, sync::Arc};

use crate::{DescriptorSetLayout, Device, ShaderModule, VulkanError};
use ash::vk;

#[derive(Debug, Clone)]
pub struct PipelineLayout {
    inner: Arc<PipelineLayoutInner>,
}

#[derive(Debug)]
struct PipelineLayoutInner {
    descriptor_set_layout: DescriptorSetLayout,
    pipeline_layout: vk::PipelineLayout,
}

impl PipelineLayout {
    pub fn create(
        device: &Device,
        descriptor_set_layout: &DescriptorSetLayout,
    ) -> Result<PipelineLayout, VulkanError> {
        let set_layouts = [unsafe { descriptor_set_layout.descriptor_set_layout() }];
        let create_info = vk::PipelineLayoutCreateInfo::default().set_layouts(&set_layouts);
        let pipeline_layout = unsafe { device.ash().create_pipeline_layout(&create_info, None)? };

        Ok(PipelineLayout {
            inner: Arc::new(PipelineLayoutInner {
                descriptor_set_layout: descriptor_set_layout.clone(),
                pipeline_layout,
            }),
        })
    }

    pub unsafe fn pipeline_layout(&self) -> vk::PipelineLayout {
        self.inner.pipeline_layout
    }
}

impl Drop for PipelineLayoutInner {
    fn drop(&mut self) {
        unsafe {
            self.descriptor_set_layout
                .device()
                .ash()
                .destroy_pipeline_layout(self.pipeline_layout, None);
        }
    }
}

#[derive(Debug)]
pub struct Pipeline {
    _shader_module: ShaderModule,
    layout: PipelineLayout,
    pipeline: vk::Pipeline,
}

impl Pipeline {
    pub fn create(
        device: &Device,
        layout: PipelineLayout,
        shader_module: ShaderModule,
        stage: vk::ShaderStageFlags,
        name: &CStr,
        num: u32,
    ) -> Result<Vec<Pipeline>, VulkanError> {
        let stage_info = vk::PipelineShaderStageCreateInfo::default()
            .stage(stage)
            .module(unsafe { shader_module.shader_module() })
            .name(name);

        let create_info = vk::ComputePipelineCreateInfo::default()
            .stage(stage_info)
            .layout(unsafe { layout.pipeline_layout() });

        let create_result = unsafe {
            device.ash().create_compute_pipelines(
                vk::PipelineCache::null(),
                &vec![create_info; num as usize],
                None,
            )
        };

        let pipelines = match create_result {
            Ok(pipelines) => pipelines,
            Err((pipelines, result)) => {
                for pipeline in pipelines {
                    unsafe { device.ash().destroy_pipeline(pipeline, None) };
                }

                return Err(VulkanError::from(result));
            }
        };

        Ok(pipelines
            .into_iter()
            .map(|pipeline| Pipeline {
                _shader_module: shader_module.clone(),
                layout: layout.clone(),
                pipeline,
            })
            .collect())
    }

    pub unsafe fn pipeline_layout(&self) -> vk::PipelineLayout {
        self.layout.pipeline_layout()
    }

    pub unsafe fn pipeline(&self) -> vk::Pipeline {
        self.pipeline
    }
}

impl Drop for Pipeline {
    fn drop(&mut self) {
        unsafe {
            self.layout
                .inner
                .descriptor_set_layout
                .device()
                .ash()
                .destroy_pipeline(self.pipeline, None);
        }
    }
}
