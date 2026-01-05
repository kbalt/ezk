use capture::wayland::{
    BitFlag, CapturedDmaBufferSync, CapturedFrameBuffer, DmaPlane, DmaUsageOptions, PersistMode,
    PipewireOptions, PixelFormat, RgbaSwizzle, ScreenCaptureOptions, SourceType,
};
use ezk_h264::{
    H264Level, H264Profile,
    encoder::{
        backends::vulkan::{
            VkH264Encoder, VulkanH264EncoderConfig, VulkanH264RateControlConfig,
            VulkanH264RateControlMode,
        },
        config::{FramePattern, Framerate, SliceMode},
    },
};
use ezk_image::ImageRef;
use std::{fs::OpenOptions, io::Write, time::Instant};
use tokio::sync::mpsc;
use vulkan::{
    DrmPlane, Semaphore,
    ash::vk,
    encoder::{
        VulkanEncoderConfig,
        input::{InputData, InputPixelFormat, InputSync, VulkanImageInput},
    },
};

#[tokio::test]
async fn vk_encode_dma() {
    vk_encode_dma_inner().await;
}

async fn vk_encode_dma_inner() {
    env_logger::builder().is_test(true).init();

    let entry = unsafe { vulkan::ash::Entry::load().unwrap() };
    let instance = vulkan::Instance::create(entry, &[]).unwrap();
    let mut physical_devices: Vec<vulkan::PhysicalDevice> = instance.physical_devices().unwrap();
    let physical_device = &mut physical_devices[0];

    let drm_modifer: Vec<u64> = physical_device
        .supported_drm_modifier(vk::Format::R8G8B8A8_UNORM)
        .into_iter()
        .map(|m| m.modifier)
        .collect();

    let width = 2560;
    let height = 1440;

    let capabilities = VkH264Encoder::capabilities(physical_device, H264Profile::Baseline).unwrap();

    let device = vulkan::Device::create(physical_device, &[]).unwrap();

    let (tx, mut rx) = mpsc::channel(8);

    let options = ScreenCaptureOptions {
        show_cursor: true,
        source_types: SourceType::all(),
        persist_mode: PersistMode::DoNot,
        restore_token: None,
        pipewire: PipewireOptions {
            max_framerate: 30,
            pixel_formats: vec![PixelFormat::RGBA(RgbaSwizzle::BGRA)],
            dma_usage: Some(DmaUsageOptions {
                request_sync_obj: true,
                num_buffers: 16,
                supported_modifier: drm_modifer,
            }),
        },
    };

    let device_ = device.clone();
    capture::wayland::start_screen_capture(options, move |frame| {
        let buffer = match frame.buffer {
            CapturedFrameBuffer::Dma(buffer) => buffer,
            _ => {
                panic!("Test requires DMA buffers")
            }
        };

        let mut sync = buffer.sync.map(
            |CapturedDmaBufferSync {
                 acquire_point,
                 release_point,
                 acquire_fd,
                 release_fd,
             }| {
                (
                    Some(InputSync {
                        semaphore: unsafe {
                            Semaphore::import_timeline_fd(&device_, acquire_fd).unwrap()
                        },
                        timeline_point: Some(acquire_point),
                    }),
                    Some(InputSync {
                        semaphore: unsafe {
                            Semaphore::import_timeline_fd(&device_, release_fd).unwrap()
                        },
                        timeline_point: Some(release_point),
                    }),
                )
            },
        );

        let swizzle = match frame.format {
            PixelFormat::RGBA(swizzle) => swizzle,
            _ => unreachable!(),
        };

        let image = unsafe {
            vulkan::Image::import_dma_fd(
                &device_,
                frame.width,
                frame.height,
                buffer
                    .planes
                    .into_iter()
                    .map(|DmaPlane { fd, offset, stride }| DrmPlane { fd, offset, stride })
                    .collect(),
                buffer.modifier,
                vk::Format::R8G8B8A8_UNORM,
                vk::ImageUsageFlags::SAMPLED,
            )
        }
        .unwrap();

        let components = match swizzle {
            capture::wayland::RgbaSwizzle::RGBA => vk::ComponentMapping::default(),
            capture::wayland::RgbaSwizzle::BGRA => vk::ComponentMapping {
                r: vk::ComponentSwizzle::B,
                g: vk::ComponentSwizzle::G,
                b: vk::ComponentSwizzle::R,
                a: vk::ComponentSwizzle::A,
            },
            capture::wayland::RgbaSwizzle::ARGB => vk::ComponentMapping {
                r: vk::ComponentSwizzle::G,
                g: vk::ComponentSwizzle::B,
                b: vk::ComponentSwizzle::A,
                a: vk::ComponentSwizzle::R,
            },
            capture::wayland::RgbaSwizzle::ABGR => vk::ComponentMapping {
                r: vk::ComponentSwizzle::A,
                g: vk::ComponentSwizzle::B,
                b: vk::ComponentSwizzle::G,
                a: vk::ComponentSwizzle::R,
            },
        };

        let view = unsafe {
            vulkan::ImageView::create(
                &image,
                &vk::ImageViewCreateInfo::default()
                    .image(image.handle())
                    .components(components)
                    .format(vk::Format::R8G8B8A8_UNORM)
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

        tx.blocking_send(VulkanImageInput {
            view,
            extent: vk::Extent2D {
                width: frame.width,
                height: frame.height,
            },
            acquire: sync.as_mut().and_then(|(acquire, _release)| acquire.take()),
            release: sync.as_mut().and_then(|(_acquire, release)| release.take()),
        })
        .is_ok()
    })
    .await
    .unwrap();

    let mut encoder = VkH264Encoder::new(
        &device,
        &capabilities,
        VulkanH264EncoderConfig {
            encoder: VulkanEncoderConfig {
                max_encode_resolution: vk::Extent2D { width, height },
                initial_encode_resolution: vk::Extent2D { width, height },
                max_input_resolution: vk::Extent2D { width, height },
                input_as_vulkan_image: true,
                input_pixel_format: InputPixelFormat::RGBA {
                    primaries: vulkan::encoder::input::Primaries::BT709,
                },
                usage_hints: vk::VideoEncodeUsageFlagsKHR::DEFAULT,
                content_hints: vk::VideoEncodeContentFlagsKHR::DEFAULT,
                tuning_mode: vk::VideoEncodeTuningModeKHR::DEFAULT,
            },
            profile: H264Profile::Main,
            level: H264Level::Level_6_0,
            frame_pattern: FramePattern {
                intra_idr_period: u16::MAX,
                intra_period: u16::MAX,
                ip_period: 1,
            },
            rate_control: VulkanH264RateControlConfig {
                mode: VulkanH264RateControlMode::VariableBitrate {
                    average_bitrate: 500_000,
                    max_bitrate: 1_000_000,
                },
                framerate: Some(Framerate::from_fps(240)),
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

    for _ in 0..1000 {
        let input = rx.recv().await.unwrap();

        let start = Instant::now();
        encoder
            .encode_frame(InputData::VulkanImage(input))
            .inspect_err(|e| println!("{e}"))
            .unwrap();
        println!("Took: {:?}", start.elapsed());

        while let Some((_, buf)) = encoder.poll_result().unwrap() {
            println!("buf: {}", buf.len());

            file.write_all(&buf).unwrap();
        }
    }

    while let Some((_, buf)) = encoder.wait_result().unwrap() {
        file.write_all(&buf).unwrap();
    }
}

#[tokio::test]
async fn vk_encode_memory() {
    vk_encode_memory_inner().await;
}

async fn vk_encode_memory_inner() {
    env_logger::builder().is_test(true).init();

    let entry = unsafe { vulkan::ash::Entry::load().unwrap() };
    let instance = vulkan::Instance::create(entry, &[]).unwrap();
    let mut physical_devices: Vec<vulkan::PhysicalDevice> = instance.physical_devices().unwrap();
    let physical_device = &mut physical_devices[0];

    let (tx, mut rx) = mpsc::channel(8);

    let options = ScreenCaptureOptions {
        show_cursor: true,
        source_types: SourceType::all(),
        persist_mode: PersistMode::DoNot,
        restore_token: None,
        pipewire: PipewireOptions {
            max_framerate: 30,
            pixel_formats: vec![PixelFormat::RGBA(RgbaSwizzle::BGRA)],
            dma_usage: None,
        },
    };

    capture::wayland::start_screen_capture(options, move |frame| {
        let buffer = match frame.buffer {
            CapturedFrameBuffer::Mem(buffer) => buffer,
            _ => {
                panic!("Test requires DMA buffers")
            }
        };

        println!("{:?}", frame.format);

        let image = ezk_image::Image::from_buffer(
            ezk_image::PixelFormat::BGRA,
            buffer.memory,
            None,
            frame.width as usize,
            frame.height as usize,
            ezk_image::ColorInfo::RGB(ezk_image::RgbColorInfo {
                transfer: ezk_image::ColorTransfer::Linear,
                primaries: ezk_image::ColorPrimaries::BT709,
            }),
        )
        .unwrap();

        tx.blocking_send(image).is_ok()
    })
    .await
    .unwrap();

    let first_image = rx.recv().await.unwrap();

    let width = first_image.width() as u32;
    let height = first_image.height() as u32;

    println!("{width}x{height}");

    let capabilities = VkH264Encoder::capabilities(physical_device, H264Profile::Baseline).unwrap();
    let device = vulkan::Device::create(physical_device, &[]).unwrap();

    let mut encoder = VkH264Encoder::new(
        &device,
        &capabilities,
        VulkanH264EncoderConfig {
            encoder: VulkanEncoderConfig {
                max_encode_resolution: vk::Extent2D { width, height },
                initial_encode_resolution: vk::Extent2D {
                    width,
                    height: height / 2,
                },
                max_input_resolution: vk::Extent2D {
                    width: width * 2,
                    height,
                },
                input_as_vulkan_image: false,
                input_pixel_format: InputPixelFormat::RGBA {
                    primaries: vulkan::encoder::input::Primaries::BT709,
                },
                usage_hints: vk::VideoEncodeUsageFlagsKHR::DEFAULT,
                content_hints: vk::VideoEncodeContentFlagsKHR::DEFAULT,
                tuning_mode: vk::VideoEncodeTuningModeKHR::DEFAULT,
            },
            profile: H264Profile::Baseline,
            level: H264Level::Level_6_2,
            frame_pattern: FramePattern {
                intra_idr_period: 60,
                intra_period: 30,
                ip_period: 1,
            },
            rate_control: VulkanH264RateControlConfig {
                mode: VulkanH264RateControlMode::ConstantBitrate { bitrate: 6_000_000 },
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
        let image = rx.recv().await.unwrap();

        let start = Instant::now();
        encoder.encode_frame(InputData::Image(&image)).unwrap();
        println!("Took: {:?}", start.elapsed());
        while let Some((_, buf)) = encoder.poll_result().unwrap() {
            file.write_all(&buf).unwrap();
        }
    }

    while let Some((_, buf)) = encoder.wait_result().unwrap() {
        file.write_all(&buf).unwrap();
    }
}
