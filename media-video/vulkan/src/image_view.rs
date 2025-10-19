use crate::{Image, VulkanError};
use ash::vk;

#[derive(Debug)]
pub struct ImageView {
    image: Image,
    image_view: vk::ImageView,
    subresource_range: vk::ImageSubresourceRange,
}

impl ImageView {
    pub unsafe fn create(
        image: &Image,
        create_info: &vk::ImageViewCreateInfo<'_>,
    ) -> Result<Self, VulkanError> {
        let device = image.device();

        let image_view = device.ash().create_image_view(create_info, None)?;

        Ok(Self {
            image: image.clone(),
            image_view,
            subresource_range: create_info.subresource_range,
        })
    }

    pub(crate) fn image(&self) -> &Image {
        &self.image
    }

    pub(crate) unsafe fn handle(&self) -> vk::ImageView {
        self.image_view
    }

    pub(crate) fn subresource_range(&self) -> &vk::ImageSubresourceRange {
        &self.subresource_range
    }
}

impl Drop for ImageView {
    fn drop(&mut self) {
        unsafe {
            let device = self.image.device();

            device.ash().destroy_image_view(self.image_view, None);
        }
    }
}
