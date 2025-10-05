use crate::{Device, Image, ImageView, VulkanError};
use ash::vk::{self};

pub fn create_dpb(
    device: &Device,
    video_profile_info: vk::VideoProfileInfoKHR<'_>,
    num_slots: u32,
    width: u32,
    height: u32,
) -> Result<Vec<ImageView>, VulkanError> {
    let profiles = [video_profile_info];

    let mut video_profile_list_info = vk::VideoProfileListInfoKHR::default().profiles(&profiles);
    let input_image_info = vk::ImageCreateInfo::default()
        .image_type(vk::ImageType::TYPE_2D)
        .format(vk::Format::G8_B8R8_2PLANE_420_UNORM)
        .extent(vk::Extent3D {
            width,
            height,
            depth: 1,
        })
        .mip_levels(1)
        .array_layers(num_slots)
        .tiling(vk::ImageTiling::OPTIMAL)
        .sharing_mode(vk::SharingMode::EXCLUSIVE)
        .initial_layout(vk::ImageLayout::UNDEFINED)
        .samples(vk::SampleCountFlags::TYPE_1)
        .usage(vk::ImageUsageFlags::VIDEO_ENCODE_DPB_KHR)
        .push_next(&mut video_profile_list_info);

    let image = unsafe { Image::create(device, &input_image_info)? };

    let mut slots = Vec::with_capacity(num_slots as usize);

    for array_layer in 0..num_slots {
        let mut view_usage_create_info = vk::ImageViewUsageCreateInfo::default()
            .usage(vk::ImageUsageFlags::VIDEO_ENCODE_DPB_KHR);

        let create_info = vk::ImageViewCreateInfo::default()
            .image(unsafe { image.image() })
            .view_type(vk::ImageViewType::TYPE_2D)
            .format(vk::Format::G8_B8R8_2PLANE_420_UNORM)
            .components(vk::ComponentMapping::default())
            .subresource_range(vk::ImageSubresourceRange {
                aspect_mask: vk::ImageAspectFlags::COLOR,
                base_mip_level: 0,
                level_count: 1,
                base_array_layer: array_layer,
                layer_count: 1,
            })
            .push_next(&mut view_usage_create_info);

        let image_view = unsafe { ImageView::create(&image, &create_info)? };

        slots.push(image_view)
    }

    Ok(slots)
}
