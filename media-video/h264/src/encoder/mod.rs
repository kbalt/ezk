pub mod backends;
mod config;

use crate::Profile;
pub use config::{
    H264EncoderConfig, H264FramePattern, H264FrameRate, H264FrameType, H264RateControlConfig,
};
use ezk_image::{ImageRef, PixelFormat};
use std::error::Error;

pub(crate) mod util;

#[derive(Debug, Clone)]
pub struct H264EncoderCapabilities {
    pub min_qp: u8,
    pub max_qp: u8,

    pub min_resolution: (u32, u32),
    pub max_resolution: (u32, u32),

    pub max_l0_p_references: u32,
    pub max_l0_b_references: u32,
    pub max_l1_b_references: u32,

    pub max_quality_level: u32,

    pub formats: Vec<PixelFormat>,
}

pub trait H264EncoderDevice {
    type Encoder: H264Encoder;
    type CapabilitiesError: Error;
    type CreateEncoderError: Error;

    fn profiles(&mut self) -> Vec<Profile>;

    fn capabilities(
        &mut self,
        profile: Profile,
    ) -> Result<H264EncoderCapabilities, Self::CapabilitiesError>;

    fn create_encoder(
        &mut self,
        config: H264EncoderConfig,
    ) -> Result<Self::Encoder, Self::CreateEncoderError>;
}

pub trait H264Encoder {
    type Error: Error;

    fn encode_frame(&mut self, image: &dyn ImageRef) -> Result<(), Self::Error>;

    fn poll_result(&mut self) -> Result<Option<Vec<u8>>, Self::Error>;
    fn wait_result(&mut self) -> Result<Option<Vec<u8>>, Self::Error>;
}

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write;
    use std::time::Instant;

    use super::*;
    use crate::Profile;
    use crate::encoder::config::{
        H264EncodeContentHint, H264EncodeTuningHint, H264EncodeUsageHint,
    };
    use crate::encoder::{H264FramePattern, H264RateControlConfig};
    use ::libva::Display;
    use ::vulkan::{Instance, ash};
    use ezk_image::{
        ColorInfo, ColorPrimaries, ColorSpace, ColorTransfer, PixelFormat, YuvColorInfo,
    };

    #[test]
    fn generic() {
        env_logger::init();

        let monitors = xcap::Monitor::all().unwrap();
        let monitor = &monitors[1];
        // let (rec, receiver) = monitor.video_recorder().unwrap();
        // rec.start().unwrap();

        // Vulkan
        let entry = unsafe { ash::Entry::load().unwrap() };
        let instance = Instance::load(entry).unwrap();
        let mut devices = instance.physical_devices().unwrap();
        println!("{devices:?}");
        let mut device = &mut devices[0];

        // libva
        // let mut devices = Display::enumerate_drm().unwrap();
        // println!("{devices:#?}");
        // let device = &mut devices[1];

        // for profile in device.profiles() {
        //     match device.capabilities(profile) {
        //         Ok(capabilities) => println!("profile {profile:?} {capabilities:?}"),
        //         Err(e) => {
        //             log::error!("Failed to get capabilities: {e}");
        //             return;
        //         }
        //     };
        // }

        let capabilities = match device.capabilities(Profile::High) {
            Ok(capabilities) => capabilities,
            Err(e) => {
                log::error!("Failed to get capabilities: {e}");
                return;
            }
        };

        println!("Capabilities: {capabilities:#?}");

        let mut encoder = device
            .create_encoder(H264EncoderConfig {
                profile: crate::Profile::High,
                level: crate::Level::Level_4_2,
                resolution: (monitor.width().unwrap(), monitor.height().unwrap()),
                framerate: None,
                qp: None,
                frame_pattern: H264FramePattern {
                    intra_idr_period: 120,
                    intra_period: 120,
                    ip_period: 1,
                },
                rate_control: H264RateControlConfig::ConstantBitRate { bitrate: 6_000_000 },
                usage_hint: H264EncodeUsageHint::Default,
                content_hint: H264EncodeContentHint::Default,
                tuning_hint: H264EncodeTuningHint::Default,
                max_slice_len: None,
                max_l0_p_references: capabilities.max_l0_p_references,
                max_l0_b_references: capabilities.max_l0_b_references,
                max_l1_b_references: capabilities.max_l1_b_references,
                quality_level: 0,
            })
            .unwrap();

        let mut file = OpenOptions::new()
            .truncate(true)
            .create(true)
            .write(true)
            .open("va.h264")
            .unwrap();

        let captured = ezk_image::Image::blank(
            PixelFormat::NV12,
            monitor.width().unwrap() as usize,
            monitor.height().unwrap() as usize,
            ColorInfo::YUV(YuvColorInfo {
                transfer: ColorTransfer::Linear,
                full_range: true,
                primaries: ColorPrimaries::BT709,
                space: ColorSpace::BT709,
            }),
        );

        let mut i = 0;
        while i < 500 {
            i += 1;

            // std::thread::sleep_ms(32);

            // let image = receiver.recv().unwrap();
            // while receiver.try_recv().is_ok() {}

            // let captured_rgba = ezk_image::Image::from_buffer(
            //     PixelFormat::RGBA,
            //     image.raw,
            //     None,
            //     image.width as usize,
            //     image.height as usize,
            //     ColorInfo::YUV(YuvColorInfo {
            //         transfer: ColorTransfer::Linear,
            //         full_range: false,
            //         primaries: ColorPrimaries::BT2020,
            //         space: ColorSpace::BT709,
            //     }),
            // )
            // .unwrap();

            let now: Instant = Instant::now();

            encoder.encode_frame(&captured).unwrap();

            println!("Took: {:?}", now.elapsed());

            while let Some(buf) = encoder.wait_result().unwrap() {
                file.write_all(&buf).unwrap();
            }
        }

        while let Some(buf) = encoder.wait_result().unwrap() {
            file.write_all(&buf).unwrap();
        }
        std::mem::forget(encoder);
    }
}
