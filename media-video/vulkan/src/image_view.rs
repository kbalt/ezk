use crate::{Image, VulkanError};
use ash::vk;
use std::sync::Arc;

#[derive(Debug, Clone)]
pub struct ImageView {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    image: Image,
    handle: vk::ImageView,
    subresource_range: vk::ImageSubresourceRange,
}

impl ImageView {
    pub unsafe fn create(
        image: &Image,
        create_info: &vk::ImageViewCreateInfo<'_>,
    ) -> Result<Self, VulkanError> {
        let device = image.device();

        let handle = device.ash().create_image_view(create_info, None)?;

        Ok(Self {
            inner: Arc::new(Inner {
                image: image.clone(),
                handle,
                subresource_range: create_info.subresource_range,
            }),
        })
    }

    pub fn image(&self) -> &Image {
        &self.inner.image
    }

    pub unsafe fn handle(&self) -> vk::ImageView {
        self.inner.handle
    }

    pub(crate) fn subresource_range(&self) -> &vk::ImageSubresourceRange {
        &self.inner.subresource_range
    }
}

impl Drop for Inner {
    fn drop(&mut self) {
        unsafe {
            let device = self.image.device();

            device.ash().destroy_image_view(self.handle, None);
        }
    }
}
