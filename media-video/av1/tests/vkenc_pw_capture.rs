use capture::wayland::{
    BitFlag, CapturedDmaBufferSync, CapturedFrameBuffer, DmaPlane, DmaUsageOptions, PersistMode,
    PipewireOptions, PixelFormat, RgbaSwizzle, ScreenCaptureOptions, SourceType,
};
use ezk_av1::{
    AV1DePayloader, AV1Framerate, AV1Level, AV1Payloader, AV1Profile,
    encoder::{
        AV1FramePattern,
        backends::vulkan::{
            VkAV1Encoder, VulkanAV1EncoderConfig, VulkanAV1RateControlConfig,
            VulkanAV1RateControlMode,
        },
    },
};
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

    let capabilities = VkAV1Encoder::capabilities(physical_device, AV1Profile::Main).unwrap();

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
                request_sync_obj: false,
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

    let mut encoder = VkAV1Encoder::new(
        &device,
        &capabilities,
        VulkanAV1EncoderConfig {
            encoder: VulkanEncoderConfig {
                max_encode_resolution: vk::Extent2D {
                    width: 608,
                    height: 1080,
                },
                initial_encode_resolution: vk::Extent2D {
                    width: 608,
                    height: 1080,
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
            profile: AV1Profile::Main,
            level: AV1Level::Level_6_0,
            frame_pattern: AV1FramePattern {
                keyframe_interval: u16::MAX,
            },
            rate_control: VulkanAV1RateControlConfig {
                mode: VulkanAV1RateControlMode::VariableBitrate {
                    average_bitrate: 10_000_000,
                    max_bitrate: 12_000_000,
                },
                framerate: Some(AV1Framerate::from_fps(240)),
                min_q_index: None, //Some(0),
                max_q_index: None, //Some(255),
            },
        },
    )
    .unwrap();

    let mut file = OpenOptions::new()
        .truncate(true)
        .create(true)
        .write(true)
        .open("../../test-av1.ivf")
        .unwrap();

    ivf::write_ivf_header(&mut file, width as usize, height as usize, 1000, 1);

    let epoch = Instant::now();

    let mut depayloader = AV1DePayloader::new();

    for _ in 0..200 {
        let input = rx.recv().await.unwrap();

        let start = Instant::now();
        encoder
            .encode_frame(InputData::VulkanImage(input))
            .inspect_err(|e| println!("{e}"))
            .unwrap();
        println!("Took: {:?}", start.elapsed());

        while let Some((ts, buf)) = encoder.poll_result().unwrap() {
            println!("buf: {}", buf.len());

            ivf::write_ivf_frame(&mut file, (ts - epoch).as_millis() as _, &buf);

            let packets = AV1Payloader::new().payload(buf.clone().into(), 1000);

            for packet in packets {
                for depayloaded in depayloader.depayload(&packet).unwrap() {
                    assert!(depayloaded.len() == buf.len());
                    println!("Depayloaded OBU: {}", depayloaded.len());
                }
            }
        }
    }

    while let Some((ts, buf)) = encoder.wait_result().unwrap() {
        println!("buf: {}", buf.len());

        ivf::write_ivf_frame(&mut file, (ts - epoch).as_millis() as _, &buf);
        let packets = AV1Payloader::new().payload(buf.clone().into(), 1000);
        for packet in packets {
            for depayloaded in depayloader.depayload(&packet).unwrap() {
                assert!(depayloaded.len() == buf.len());
                println!("Depayloaded OBU: {}", depayloaded.len());
            }
        }
    }

    file.flush().unwrap();
}
