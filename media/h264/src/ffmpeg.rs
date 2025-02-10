use crate::{FmtpOptions, Level, PacketizationMode, Profile};
use ffmpeg::{codec::Context, ffi::AV_OPT_SEARCH_CHILDREN, format::Pixel, Rational};
use std::ffi::CStr;

/// ffmpeg nvenc codec
struct NvEnc {
    codec: ffmpeg::Codec,

    /// H.264 level 6+ is available
    has_lvl6: bool,
    /// YUV422 support is available
    has_422: bool,
    /// 10bit encoding is available
    has_high10: bool,
}

impl NvEnc {
    fn detect() -> Option<NvEnc> {
        let codec = ffmpeg::encoder::find_by_name("h264_nvenc")?;

        let mut caps = NvEnc {
            codec,
            has_lvl6: false,
            has_422: false,
            has_high10: false,
        };

        unsafe {
            let class = ((*codec.as_ptr()).priv_class).read_unaligned();
            let mut option_ptr = class.option;

            loop {
                let option = option_ptr.read_unaligned();
                option_ptr = option_ptr.add(1);

                if option.name.is_null() {
                    break;
                }

                let name = CStr::from_ptr(option.name);
                caps.has_lvl6 |= name == c"6.0";
                caps.has_high10 |= name == c"high10";
                caps.has_422 |= name == c"high422";
            }
        }

        Some(caps)
    }

    fn map_profile(&self, profile: Profile) -> Option<&'static CStr> {
        match profile {
            Profile::Baseline => Some(c"baseline"),
            Profile::Main => Some(c"main"),
            Profile::Extended => Some(c"baseline"),
            Profile::High => Some(c"high"),
            Profile::High10 => {
                if self.has_high10 {
                    Some(c"high10")
                } else {
                    None
                }
            }
            Profile::High422 => {
                if self.has_422 {
                    Some(c"high422")
                } else {
                    None
                }
            }
            Profile::High444Predictive => Some(c"high444p"),
            Profile::CAVLC444 => None,
        }
    }

    fn map_level(&self, level: Level) -> &'static CStr {
        match level {
            Level::Level_1_0 => c"1.0",
            Level::Level_1_B => c"1.0b",
            Level::Level_1_1 => c"1.1",
            Level::Level_1_2 => c"1.2",
            Level::Level_1_3 => c"1.3",
            Level::Level_2_0 => c"2.0",
            Level::Level_2_1 => c"2.1",
            Level::Level_2_2 => c"2.2",
            Level::Level_3_0 => c"3.0",
            Level::Level_3_1 => c"3.1",
            Level::Level_3_2 => c"3.2",
            Level::Level_4_0 => c"4.0",
            Level::Level_4_1 => c"4.1",
            Level::Level_4_2 => c"4.2",
            Level::Level_5_0 => c"5.0",
            Level::Level_5_1 => c"5.1",
            Level::Level_5_2 => c"5.2",
            Level::Level_6_0 if self.has_lvl6 => c"6.0",
            Level::Level_6_1 if self.has_lvl6 => c"6.1",
            Level::Level_6_2 if self.has_lvl6 => c"6.2",
            Level::Level_6_0 | Level::Level_6_1 | Level::Level_6_2 => c"5.2",
        }
    }

    fn open(&self, options: &FmtpOptions) -> ffmpeg::encoder::Video {
        let mut codec = Context::new_with_codec(self.codec)
            .encoder()
            .video()
            .expect("h264 is a video codec");

        codec.set_time_base(Rational::new(1, 1000));
        codec.set_format(Pixel::YUV420P);
        codec.set_width(dbg!(options.max_resolution(1920, 1080).0));
        codec.set_height(dbg!(options.max_resolution(1920, 1080).1));
        codec.set_frame_rate(Some(1.0));

        let bitrate_bps = (options
            .max_br
            .unwrap_or_else(|| options.profile_level_id.level.max_br())
            as usize)
            * 1000;

        codec.set_bit_rate(bitrate_bps);
        codec.set_max_bit_rate(bitrate_bps);

        unsafe {
            assert_eq!(
                ffmpeg::sys::av_opt_set(
                    codec.as_mut_ptr().cast(),
                    c"profile".as_ptr(),
                    self.map_profile(options.profile_level_id.profile)
                        .unwrap()
                        .as_ptr(),
                    AV_OPT_SEARCH_CHILDREN,
                ),
                0
            );

            assert_eq!(
                ffmpeg::sys::av_opt_set(
                    codec.as_mut_ptr().cast(),
                    c"level".as_ptr(),
                    self.map_level(options.profile_level_id.level).as_ptr(),
                    AV_OPT_SEARCH_CHILDREN,
                ),
                0
            );
        }

        match options.packetization_mode {
            PacketizationMode::SingleNAL => {
                // TODO: do not hardcode the mtu
                // dict.set("single-slice-intra-refresh", "false");
                // dict.set("max_slice_size", "1500");
            }
            PacketizationMode::NonInterleavedMode => todo!(),
            PacketizationMode::InterleavedMode => todo!(),
        }

        codec.open().unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn run_nvenc() {
        ffmpeg::init().unwrap();
        ffmpeg::log::set_level(ffmpeg::log::Level::Trace);

        let mut f = ffmpeg::frame::Video::new(Pixel::YUV420P, 1920, 1080);
        rand::fill(f.data_mut(0));

        let mut open = NvEnc::detect().unwrap().open(&FmtpOptions::default());

        loop {
            open.send_frame(&f).unwrap();
            rand::fill(f.data_mut(0));
            std::thread::sleep(Duration::from_millis(16));
            let mut packet = ffmpeg::Packet::empty();
            while open.receive_packet(&mut packet).is_ok() {
                println!("{}", packet.size());
            }
        }
    }
}
