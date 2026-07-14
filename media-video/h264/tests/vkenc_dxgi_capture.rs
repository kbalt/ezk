#![cfg(target_family = "windows")]

use capture::dxgi_desktop_duplication::DxgiDesktopDuplication;
use ezk_h264::{
    Level, Profile,
    encoder::{
        backends::vulkan::{
            VkH264Encoder, VulkanH264EncoderConfig, VulkanH264RateControlConfig,
            VulkanH264RateControlMode,
        },
        config::{FramePattern, SliceMode},
    },
};
use std::{fs::OpenOptions, io::Write, time::Instant};
use vulkan::{
    ash::vk,
    encoder::{
        VulkanEncoderConfig,
        input::{InputData, InputPixelFormat, VulkanImageInput},
    },
};

#[tokio::test]
async fn vk_encode_d3d11() {
    vk_encode_d3d11_inner().await;
}

async fn vk_encode_d3d11_inner() {
    env_logger::init();

    let entry = unsafe { vulkan::ash::Entry::load().unwrap() };
    let instance = vulkan::Instance::create(entry, &[]).unwrap();
    let mut physical_devices: Vec<vulkan::PhysicalDevice> = instance.physical_devices().unwrap();
    let physical_device = &mut physical_devices[0];

    let width = 2560;
    let height = 1440;

    let capabilities = VkH264Encoder::capabilities(physical_device, Profile::Baseline).unwrap();

    let device = vulkan::Device::create(physical_device, &[]).unwrap();

    let a = DxgiDesktopDuplication::new();
    let b = a.output(0).unwrap();
    let mut c = b.create_duplication();

    let mut encoder = VkH264Encoder::new(
        &device,
        &capabilities,
        VulkanH264EncoderConfig {
            encoder: VulkanEncoderConfig {
                max_encode_resolution: vk::Extent2D { width, height },
                initial_encode_resolution: vk::Extent2D {
                    width: width / 2,
                    height: height / 2,
                },
                max_input_resolution: vk::Extent2D { width, height },
                input_as_vulkan_image: true,
                input_pixel_format: InputPixelFormat::RGBA {
                    primaries: vulkan::encoder::input::Primaries::BT709,
                },
                usage_hints: vk::VideoEncodeUsageFlagsKHR::DEFAULT,
                content_hints: vk::VideoEncodeContentFlagsKHR::DEFAULT,
                tuning_mode: vk::VideoEncodeTuningModeKHR::DEFAULT,
            },
            profile: Profile::Baseline,
            level: Level::Level_6_2,
            frame_pattern: FramePattern {
                intra_idr_period: 60,
                intra_period: 30,
                ip_period: 1,
            },
            rate_control: VulkanH264RateControlConfig {
                mode: VulkanH264RateControlMode::VariableBitrate {
                    average_bitrate: 5_000_000,
                    max_bitrate: 6_000_000,
                },
                framerate: None,
                min_qp: None,
                max_qp: None,
            },
            slice_mode: SliceMode::Picture,
        },
    )
    .unwrap();

    let mut file = OpenOptions::new()
        .truncate(true)
        .create(true)
        .write(true)
        .open("../../test.h264")
        .unwrap();

    for _ in 0..100 {
        let (texture, [width, height]) = loop {
            let Some(captured) = c.try_capture_shared_texture().unwrap() else {
                std::thread::yield_now();
                continue;
            };

            break captured;
        };

        println!("{}x{}", width, height);

        let image = unsafe {
            vulkan::Image::import_d3d11_rgba(
                &device,
                &texture,
                width,
                height,
                vk::ImageUsageFlags::SAMPLED | vk::ImageUsageFlags::COLOR_ATTACHMENT,
            )
            .unwrap()
        };

        let view = unsafe {
            vulkan::ImageView::create(
                &image,
                &vk::ImageViewCreateInfo::default()
                    .image(image.handle())
                    .format(vk::Format::B8G8R8A8_UNORM)
                    .view_type(vk::ImageViewType::TYPE_2D)
                    .subresource_range(vk::ImageSubresourceRange {
                        aspect_mask: vk::ImageAspectFlags::COLOR,
                        base_mip_level: 0,
                        level_count: 1,
                        base_array_layer: 0,
                        layer_count: 1,
                    }),
            )
            .unwrap()
        };

        let start = Instant::now();
        encoder
            .encode_frame(InputData::VulkanImage(VulkanImageInput {
                view,
                extent: vk::Extent2D { width, height },
                acquire: None,
                release: None,
                texture_is_win32_keyedmutex: true,
            }))
            .inspect_err(|e| println!("{e}"))
            .unwrap();

        println!("Took: {:?}", start.elapsed());

        while let Some(buf) = encoder.wait_result().unwrap() {
            println!("buf: {}", buf.len());

            file.write_all(&buf).unwrap();
        }
    }

    while let Some(buf) = encoder.wait_result().unwrap() {
        file.write_all(&buf).unwrap();
    }
}
