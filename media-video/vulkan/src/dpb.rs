use crate::{Device, Image, ImageView, VulkanError};
use ash::vk::{self, TaggedStructure};

pub(crate) fn create_dpb(
    device: &Device,
    video_profile_info: &vk::VideoProfileInfoKHR<'_>,
    num_slots: u32,
    extent: vk::Extent2D,
    usage: vk::ImageUsageFlags,
    separate_images: bool,
) -> Result<Vec<ImageView>, VulkanError> {
    if separate_images {
        create_dpb_separate_images(device, video_profile_info, num_slots, extent, usage)
    } else {
        create_dpb_layers(device, video_profile_info, num_slots, extent, usage)
    }
}

fn create_dpb_layers(
    device: &Device,
    video_profile_info: &vk::VideoProfileInfoKHR<'_>,
    num_slots: u32,
    extent: vk::Extent2D,
    usage: vk::ImageUsageFlags,
) -> Result<Vec<ImageView>, VulkanError> {
    let mut video_profile_list_info =
        vk::VideoProfileListInfoKHR::default().profiles(std::slice::from_ref(video_profile_info));
    let input_image_info = vk::ImageCreateInfo::default()
        .image_type(vk::ImageType::TYPE_2D)
        .format(vk::Format::G8_B8R8_2PLANE_420_UNORM)
        .extent(vk::Extent3D {
            width: extent.width,
            height: extent.height,
            depth: 1,
        })
        .mip_levels(1)
        .array_layers(num_slots)
        .tiling(vk::ImageTiling::OPTIMAL)
        .sharing_mode(vk::SharingMode::EXCLUSIVE)
        .initial_layout(vk::ImageLayout::UNDEFINED)
        .samples(vk::SampleCountFlags::TYPE_1)
        .usage(usage)
        .push(&mut video_profile_list_info);

    let image = unsafe { Image::create(device, &input_image_info)? };

    device.set_debug_name(unsafe { image.handle() }, &format!("DPB-Image\0"));

    let mut slots = Vec::with_capacity(num_slots as usize);

    for array_layer in 0..num_slots {
        let mut view_usage_create_info = vk::ImageViewUsageCreateInfo::default().usage(usage);

        let create_info = vk::ImageViewCreateInfo::default()
            .image(unsafe { image.handle() })
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
            .push(&mut view_usage_create_info);

        let image_view = unsafe { ImageView::create(&image, &create_info)? };

        device.set_debug_name(
            unsafe { image_view.handle() },
            &format!("DPB-ImageView {array_layer}\0"),
        );

        slots.push(image_view)
    }

    Ok(slots)
}

fn create_dpb_separate_images(
    device: &Device,
    video_profile_info: &vk::VideoProfileInfoKHR<'_>,
    num_slots: u32,
    extent: vk::Extent2D,
    usage: vk::ImageUsageFlags,
) -> Result<Vec<ImageView>, VulkanError> {
    let mut slots = Vec::with_capacity(num_slots as usize);

    for i in 0..num_slots {
        let mut video_profile_list_info = vk::VideoProfileListInfoKHR::default()
            .profiles(std::slice::from_ref(video_profile_info));
        let input_image_info = vk::ImageCreateInfo::default()
            .image_type(vk::ImageType::TYPE_2D)
            .format(vk::Format::G8_B8R8_2PLANE_420_UNORM)
            .extent(vk::Extent3D {
                width: extent.width,
                height: extent.height,
                depth: 1,
            })
            .mip_levels(1)
            .array_layers(1)
            .tiling(vk::ImageTiling::OPTIMAL)
            .sharing_mode(vk::SharingMode::EXCLUSIVE)
            .initial_layout(vk::ImageLayout::UNDEFINED)
            .samples(vk::SampleCountFlags::TYPE_1)
            .usage(usage)
            .push(&mut video_profile_list_info);

        let image = unsafe { Image::create(device, &input_image_info)? };

        device.set_debug_name(unsafe { image.handle() }, &format!("DPB-Image {i}\0"));

        let mut view_usage_create_info = vk::ImageViewUsageCreateInfo::default().usage(usage);

        let create_info = vk::ImageViewCreateInfo::default()
            .image(unsafe { image.handle() })
            .view_type(vk::ImageViewType::TYPE_2D)
            .format(vk::Format::G8_B8R8_2PLANE_420_UNORM)
            .components(vk::ComponentMapping::default())
            .subresource_range(vk::ImageSubresourceRange {
                aspect_mask: vk::ImageAspectFlags::COLOR,
                base_mip_level: 0,
                level_count: 1,
                base_array_layer: 0,
                layer_count: 1,
            })
            .push(&mut view_usage_create_info);

        let image_view = unsafe { ImageView::create(&image, &create_info)? };

        device.set_debug_name(
            unsafe { image_view.handle() },
            &format!("DPB-ImageView {i}\0"),
        );

        slots.push(image_view)
    }

    Ok(slots)
}
