use capture::wayland::{
    BitFlag, CapturedFrameBuffer, PersistMode, PipewireOptions, PixelFormat, RgbaSwizzle,
    ScreenCaptureOptions, SourceType,
};
use ezk_h264::{
    Level, Profile,
    encoder::{
        backends::libva::{VaH264Encoder, VaH264EncoderConfig},
        config::{FramePattern, SliceMode},
    },
};
use ezk_image::ImageRef;
use libva::{
    Display,
    encoder::{VaEncoderConfig, VaEncoderRateControlConfig, VaEncoderRateControlMode},
};
use std::{fs::OpenOptions, io::Write};
use tokio::sync::mpsc;

#[tokio::test]
async fn va_encode_memory() {
    va_encode_memory_inner().await;
}

async fn va_encode_memory_inner() {
    env_logger::init();

    let mut devices = Display::enumerate_drm().unwrap();
    let device = &mut devices[0];

    let (tx, mut rx) = mpsc::channel(8);

    let options = ScreenCaptureOptions {
        show_cursor: true,
        source_types: SourceType::all(),
        persist_mode: PersistMode::DoNot,
        pipewire: PipewireOptions {
            max_framerate: 30,
            pixel_formats: vec![PixelFormat::RGBA(RgbaSwizzle::BGRA)],
            dma_usage: None,
        },
    };

    capture::wayland::start_screen_capture(options, move |frame| {
        let buffer = match frame.buffer {
            CapturedFrameBuffer::Vec(buffer) => buffer,
            _ => {
                panic!("Test requires DMA buffers")
            }
        };

        let image = ezk_image::Image::from_buffer(
            ezk_image::PixelFormat::BGRA,
            buffer,
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

    let capabilities = VaH264Encoder::capabilities(device, Profile::ConstrainedBaseline).unwrap();

    let mut encoder = VaH264Encoder::new(
        &capabilities,
        VaH264EncoderConfig {
            encoder: VaEncoderConfig {
                max_encode_resolution: [width, height],
                initial_encode_resolution: [width, height],
                rate_control: VaEncoderRateControlConfig {
                    mode: VaEncoderRateControlMode::CBR,
                    window_size: 1000,
                    initial_qp: 24,
                    min_qp: 0,
                    max_qp: 51,
                    bitrate: 6_000_000,
                    target_percentage: 100,
                },
            },
            profile: Profile::ConstrainedBaseline,
            level: Level::Level_6_2,
            frame_pattern: FramePattern {
                intra_idr_period: 60,
                intra_period: 30,
                ip_period: 1,
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
        let image = rx.recv().await.unwrap();

        encoder.encode_frame(&image).unwrap();

        while let Some(buf) = encoder.poll_result().unwrap() {
            file.write_all(&buf).unwrap();
        }
    }

    while let Some(buf) = encoder.wait_result().unwrap() {
        file.write_all(&buf).unwrap();
    }
}
