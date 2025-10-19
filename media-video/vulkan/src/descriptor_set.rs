use crate::{Device, VulkanError};
use ash::vk;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub(crate) struct DescriptorSetLayout {
    inner: Arc<DescriptorSetLayoutInner>,
}

#[derive(Debug)]
struct DescriptorSetLayoutInner {
    device: Device,
    descriptor_set_layout: vk::DescriptorSetLayout,
}

impl DescriptorSetLayout {
    pub(crate) fn create(
        device: &Device,
        bindings: &[vk::DescriptorSetLayoutBinding<'_>],
    ) -> Result<DescriptorSetLayout, VulkanError> {
        let descriptor_set_layout = unsafe {
            let create_info = vk::DescriptorSetLayoutCreateInfo::default().bindings(bindings);

            device
                .ash()
                .create_descriptor_set_layout(&create_info, None)?
        };

        Ok(DescriptorSetLayout {
            inner: Arc::new(DescriptorSetLayoutInner {
                device: device.clone(),
                descriptor_set_layout,
            }),
        })
    }

    pub(crate) fn device(&self) -> &Device {
        &self.inner.device
    }

    pub(crate) unsafe fn descriptor_set_layout(&self) -> vk::DescriptorSetLayout {
        self.inner.descriptor_set_layout
    }
}

impl Drop for DescriptorSetLayoutInner {
    fn drop(&mut self) {
        unsafe {
            self.device
                .ash()
                .destroy_descriptor_set_layout(self.descriptor_set_layout, None);
        }
    }
}

#[derive(Debug)]
pub(crate) struct DescriptorSet {
    _inner: Arc<DescriptorSetInner>,
    descriptor_set: vk::DescriptorSet,
}

#[derive(Debug)]
struct DescriptorSetInner {
    layout: DescriptorSetLayout,
    pool: vk::DescriptorPool,
}

impl DescriptorSet {
    pub(crate) fn create(
        device: &Device,
        pool_sizes: &[vk::DescriptorPoolSize],
        layout: &DescriptorSetLayout,
        num_sets: u32,
    ) -> Result<Vec<DescriptorSet>, VulkanError> {
        let create_info = vk::DescriptorPoolCreateInfo::default()
            .pool_sizes(pool_sizes)
            .max_sets(num_sets)
            .flags(vk::DescriptorPoolCreateFlags::empty());

        let descriptor_pool = unsafe { device.ash().create_descriptor_pool(&create_info, None)? };

        let set_layouts = vec![unsafe { layout.descriptor_set_layout() }; num_sets as usize];

        let alloc_info = vk::DescriptorSetAllocateInfo::default()
            .descriptor_pool(descriptor_pool)
            .set_layouts(&set_layouts);

        let descriptor_sets = match unsafe { device.ash().allocate_descriptor_sets(&alloc_info) } {
            Ok(descriptor_sets) => descriptor_sets,
            Err(e) => {
                unsafe { device.ash().destroy_descriptor_pool(descriptor_pool, None) };

                return Err(VulkanError::from(e));
            }
        };

        let inner = Arc::new(DescriptorSetInner {
            layout: layout.clone(),
            pool: descriptor_pool,
        });

        Ok(descriptor_sets
            .into_iter()
            .map(|descriptor_set| DescriptorSet {
                _inner: inner.clone(),
                descriptor_set,
            })
            .collect())
    }

    pub(crate) unsafe fn descriptor_set(&self) -> vk::DescriptorSet {
        self.descriptor_set
    }
}

impl Drop for DescriptorSetInner {
    fn drop(&mut self) {
        unsafe {
            self.layout
                .inner
                .device
                .ash()
                .destroy_descriptor_pool(self.pool, None);
        }
    }
}
