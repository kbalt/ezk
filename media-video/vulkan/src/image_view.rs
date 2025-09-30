use crate::{Image, VulkanError};
use ash::vk;

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

        let image_view = device.device().create_image_view(create_info, None)?;

        Ok(Self {
            image: image.clone(),
            image_view,
            subresource_range: create_info.subresource_range,
        })
    }

    pub fn image(&self) -> &Image {
        &self.image
    }

    pub unsafe fn image_view(&self) -> vk::ImageView {
        self.image_view
    }

    pub fn subresource_range(&self) -> &vk::ImageSubresourceRange {
        &self.subresource_range
    }
}

impl Drop for ImageView {
    fn drop(&mut self) {
        unsafe {
            let device = self.image.device();

            device.device().destroy_image_view(self.image_view, None);
        }
    }
}
