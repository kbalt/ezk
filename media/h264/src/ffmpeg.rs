use crate::{H264EncoderConfig, Level, Profile};
use ffmpeg::{codec::Context, ffi::AV_OPT_SEARCH_CHILDREN, format::Pixel, Rational};
use std::{
    ffi::CStr,
    ptr::{self, addr_of},
};

/// ffmpeg nvenc codec
pub struct NvEnc {
    codec: ffmpeg::Codec,

    /// H.264 level 6+ is available
    has_lvl6: bool,
    /// YUV422 support is available
    has_422: bool,
    /// 10bit encoding is available
    has_high10: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum NvEncOpenError {
    #[error("packetization mode SingleNAL is not supported")]
    PacketizationModeSingleNalNotSupported,
    #[error("profile {0:?} not supported")]
    ProfileNotSupported(Profile),
    #[error("FFmpeg return an error{0}")]
    FFmpeg(#[from] ffmpeg::Error),
}

impl NvEnc {
    pub fn detect() -> Option<NvEnc> {
        let codec = ffmpeg::encoder::find_by_name("h264_nvenc")?;

        let mut this = NvEnc {
            codec,
            has_lvl6: false,
            has_422: false,
            has_high10: false,
        };

        unsafe {
            // av_opt_next takes a double pointer of AVClass (*const *const AVClass)
            let priv_class = addr_of!((*codec.as_ptr()).priv_class);
            let mut prev = ptr::null();
            loop {
                prev = ffmpeg::sys::av_opt_next(priv_class.cast(), prev);
                if prev.is_null() {
                    break;
                }

                let name = CStr::from_ptr((*prev).name);
                this.has_lvl6 |= name == c"6.0";
                this.has_high10 |= name == c"high10";
                this.has_422 |= name == c"high422";
            }
        }

        Some(this)
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

    pub fn open(
        &self,
        config: H264EncoderConfig,
    ) -> Result<ffmpeg::encoder::Video, NvEncOpenError> {
        if config.max_slice_len.is_some() {
            return Err(NvEncOpenError::PacketizationModeSingleNalNotSupported);
        }

        let mut codec = Context::new_with_codec(self.codec)
            .encoder()
            .video()
            .expect("h264 is a video codec");

        // Set the time base to nanoseconds or else nvenc will throw a fit complaining about the level being invalid?
        codec.set_time_base(Rational::new(1, 1_000_000_000));
        codec.set_format(Pixel::YUV420P);
        codec.set_width(config.resolution.0);
        codec.set_height(config.resolution.1);

        // Not using the set_ function to avoid casting to usize
        unsafe {
            if let Some(bitrate) = config.bitrate {
                (*codec.as_mut_ptr()).bit_rate = i64::from(bitrate);
            }

            if let Some(max_bitrate) = config.max_bitrate {
                (*codec.as_mut_ptr()).rc_max_rate = i64::from(max_bitrate);
            }
        }

        if let Some((qmin, qmax)) = config.qp {
            codec.set_qmin(qmin.try_into().expect("qmin must be 0..=51"));
            codec.set_qmax(qmax.try_into().expect("qmax must be 0..=51"));
        }

        if let Some(gop) = config.gop {
            codec.set_gop(gop);
        }

        set_opt(&mut codec, c"tune", c"ll")?;

        set_opt(
            &mut codec,
            c"profile",
            self.map_profile(config.profile)
                .ok_or(NvEncOpenError::ProfileNotSupported(config.profile))?,
        )?;

        set_opt(&mut codec, c"level", self.map_level(config.level))?;

        codec.open().map_err(NvEncOpenError::FFmpeg)
    }
}

fn set_opt(
    codec: &mut ffmpeg::encoder::video::Video,
    key: &CStr,
    value: &CStr,
) -> Result<(), ffmpeg::Error> {
    unsafe {
        err(ffmpeg::sys::av_opt_set(
            codec.as_mut_ptr().cast(),
            key.as_ptr(),
            value.as_ptr(),
            AV_OPT_SEARCH_CHILDREN,
        ))
    }
}

fn err(i: i32) -> Result<(), ffmpeg::Error> {
    if i < 0 {
        Err(ffmpeg::Error::from(i))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::FmtpOptions;

    use super::*;
    use std::time::Duration;

    #[test]
    fn run_nvenc() {
        ffmpeg::init().unwrap();
        ffmpeg::log::set_level(ffmpeg::log::Level::Trace);

        let mut f = ffmpeg::frame::Video::new(Pixel::YUV420P, 1280, 720 - 16);
        rand::fill(f.data_mut(0));

        let mut config = H264EncoderConfig::from_fmtp(FmtpOptions::default());
        config.max_slice_len = None;
        println!("resolution: {:?}", config.resolution);
        config.resolution = (1280, 720);

        let mut open = NvEnc::detect().unwrap().open(config).unwrap();

        open.set_width(1280);
        open.set_height(720 - 16);

        loop {
            open.send_frame(&f).unwrap();
            // rand::fill(f.data_mut(0));
            std::thread::sleep(Duration::from_millis(16));
            let mut packet = ffmpeg::Packet::empty();
            while open.receive_packet(&mut packet).is_ok() {
                println!("{}", packet.size());
            }
        }
    }
}
