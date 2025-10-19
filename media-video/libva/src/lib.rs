#![cfg(target_os = "linux")]

use ezk_image::PixelFormat;
use std::{
    backtrace::{Backtrace, BacktraceStatus},
    error::Error,
    ffi::{CStr, c_void},
    fmt,
    fs::File,
    path::PathBuf,
};

pub mod ffi {
    #![allow(unreachable_pub, dead_code, nonstandard_style, unsafe_op_in_unsafe_fn)]

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

mod buffer;
mod config;
mod context;
mod display;
pub mod encoder;
mod image;
mod surface;

pub use buffer::{Buffer, MappedBuffer};
pub use config::Config;
pub use context::Context;
pub use display::{Display, DisplayOpenDrmError};
pub use image::{Image, MappedImage};
pub use surface::Surface;

struct Handle {
    _drm_file: File,
    drm_path: PathBuf,
    vendor_id: u16,
    device_id: u16,
    dpy: *mut c_void,
}

unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

#[derive(Debug)]
pub struct VaError {
    status: ffi::VAStatus,
    text: Option<&'static CStr>,
    backtrace: Backtrace,
}

impl VaError {
    #[track_caller]
    fn try_(status: ffi::VAStatus) -> Result<(), Self> {
        if status == ffi::VA_STATUS_SUCCESS as ffi::VAStatus {
            Ok(())
        } else {
            let error_str = unsafe { ffi::vaErrorStr(status) };

            let text = if error_str.is_null() {
                None
            } else {
                Some(unsafe { CStr::from_ptr(error_str) })
            };

            let backtrace = Backtrace::capture();

            Err(Self {
                status,
                text,
                backtrace,
            })
        }
    }
}

impl fmt::Display for VaError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(text) = self.text {
            write!(f, " description={:?}", text)?;
        }

        if self.backtrace.status() != BacktraceStatus::Disabled {
            write!(f, " backtrace={}", self.backtrace)?;
        }

        Ok(())
    }
}

impl Error for VaError {}

fn map_pixel_format(fourcc: FourCC) -> Option<PixelFormat> {
    // Make sure to update used pixel formats in the ezk-image dependency
    match fourcc.bits() {
        ffi::VA_FOURCC_NV12 => Some(PixelFormat::NV12),
        ffi::VA_FOURCC_RGBA => Some(PixelFormat::RGBA),
        ffi::VA_FOURCC_RGBX => Some(PixelFormat::RGBA),
        ffi::VA_FOURCC_BGRA => Some(PixelFormat::BGRA),
        ffi::VA_FOURCC_BGRX => Some(PixelFormat::BGRA),
        ffi::VA_FOURCC_I420 => Some(PixelFormat::I420),
        ffi::VA_FOURCC_422H => Some(PixelFormat::I422),
        ffi::VA_FOURCC_444P => Some(PixelFormat::I444),
        ffi::VA_FOURCC_RGBP => Some(PixelFormat::RGB),
        ffi::VA_FOURCC_BGRP => Some(PixelFormat::BGR),
        ffi::VA_FOURCC_I010 => Some(PixelFormat::I010),
        _ => None,
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct FourCC: u32 {
        const _NV12 = ffi::VA_FOURCC_NV12;
        const _NV21 = ffi::VA_FOURCC_NV21;
        const _AI44 = ffi::VA_FOURCC_AI44;
        const _RGBA = ffi::VA_FOURCC_RGBA;
        const _RGBX = ffi::VA_FOURCC_RGBX;
        const _BGRA = ffi::VA_FOURCC_BGRA;
        const _BGRX = ffi::VA_FOURCC_BGRX;
        const _ARGB = ffi::VA_FOURCC_ARGB;
        const _XRGB = ffi::VA_FOURCC_XRGB;
        const _ABGR = ffi::VA_FOURCC_ABGR;
        const _XBGR = ffi::VA_FOURCC_XBGR;
        const _UYVY = ffi::VA_FOURCC_UYVY;
        const _YUY2 = ffi::VA_FOURCC_YUY2;
        const _AYUV = ffi::VA_FOURCC_AYUV;
        const _NV11 = ffi::VA_FOURCC_NV11;
        const _YV12 = ffi::VA_FOURCC_YV12;
        const _P208 = ffi::VA_FOURCC_P208;
        const _I420 = ffi::VA_FOURCC_I420;
        const _YV24 = ffi::VA_FOURCC_YV24;
        const _YV32 = ffi::VA_FOURCC_YV32;
        const _Y800 = ffi::VA_FOURCC_Y800;
        const _IMC3 = ffi::VA_FOURCC_IMC3;
        const _411P = ffi::VA_FOURCC_411P;
        const _411R = ffi::VA_FOURCC_411R;
        const _422H = ffi::VA_FOURCC_422H;
        const _422V = ffi::VA_FOURCC_422V;
        const _444P = ffi::VA_FOURCC_444P;
        const _RGBP = ffi::VA_FOURCC_RGBP;
        const _BGRP = ffi::VA_FOURCC_BGRP;
        const _RGB565 = ffi::VA_FOURCC_RGB565;
        const _BGR565 = ffi::VA_FOURCC_BGR565;
        const _Y210 = ffi::VA_FOURCC_Y210;
        const _Y212 = ffi::VA_FOURCC_Y212;
        const _Y216 = ffi::VA_FOURCC_Y216;
        const _Y410 = ffi::VA_FOURCC_Y410;
        const _Y412 = ffi::VA_FOURCC_Y412;
        const _Y416 = ffi::VA_FOURCC_Y416;
        const _YV16 = ffi::VA_FOURCC_YV16;
        const _P010 = ffi::VA_FOURCC_P010;
        const _P012 = ffi::VA_FOURCC_P012;
        const _P016 = ffi::VA_FOURCC_P016;
        const _I010 = ffi::VA_FOURCC_I010;
        const _IYUV = ffi::VA_FOURCC_IYUV;
        const _A2R10G10B10 = ffi::VA_FOURCC_A2R10G10B10;
        const _A2B10G10R10 = ffi::VA_FOURCC_A2B10G10R10;
        const _X2R10G10B10 = ffi::VA_FOURCC_X2R10G10B10;
        const _X2B10G10R10 = ffi::VA_FOURCC_X2B10G10R10;
        const _Y8 = ffi::VA_FOURCC_Y8;
        const _Y16 = ffi::VA_FOURCC_Y16;
        const _VYUY = ffi::VA_FOURCC_VYUY;
        const _YVYU = ffi::VA_FOURCC_YVYU;
        const _ARGB64 = ffi::VA_FOURCC_ARGB64;
        const _ABGR64 = ffi::VA_FOURCC_ABGR64;
        const _XYUV = ffi::VA_FOURCC_XYUV;
        const _Q416 = ffi::VA_FOURCC_Q416;
    }
}

bitflags::bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct RtFormat: u32 {
        const YUV420 = ffi::VA_RT_FORMAT_YUV420;
        const YUV422 = ffi::VA_RT_FORMAT_YUV422;
        const YUV444 = ffi::VA_RT_FORMAT_YUV444;
        const YUV411 = ffi::VA_RT_FORMAT_YUV411;
        const YUV400 = ffi::VA_RT_FORMAT_YUV400;
        const YUV420_10 = ffi::VA_RT_FORMAT_YUV420_10;
        const YUV422_10 = ffi::VA_RT_FORMAT_YUV422_10;
        const YUV444_10 = ffi::VA_RT_FORMAT_YUV444_10;
        const YUV420_12 = ffi::VA_RT_FORMAT_YUV420_12;
        const YUV422_12 = ffi::VA_RT_FORMAT_YUV422_12;
        const YUV444_12 = ffi::VA_RT_FORMAT_YUV444_12;
        const RGB16 = ffi::VA_RT_FORMAT_RGB16;
        const RGB32 = ffi::VA_RT_FORMAT_RGB32;
        const RGBP = ffi::VA_RT_FORMAT_RGBP;
        const RGB32_10 = ffi::VA_RT_FORMAT_RGB32_10;
        const PROTECTED = ffi::VA_RT_FORMAT_PROTECTED;
    }
}
