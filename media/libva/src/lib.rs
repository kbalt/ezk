use std::{
    ffi::{CStr, c_void},
    fs::File,
};

pub mod ffi {
    #![allow(unreachable_pub, dead_code, nonstandard_style, unsafe_op_in_unsafe_fn)]

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

mod buffer;
mod config;
mod context;
mod display;
mod image;
mod surface;

pub use buffer::{Buffer, MappedBuffer};
pub use config::Config;
pub use context::Context;
pub use display::{Display, DisplayOpenDrmError};
pub use image::{Image, MappedImage};
pub use surface::Surface;

#[derive(Debug, thiserror::Error)]
#[error("VAError, status={status}, text={text:?}")]
pub struct VaError {
    status: ffi::VAStatus,
    text: Option<&'static CStr>,
}

impl VaError {
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

            Err(Self { status, text })
        }
    }
}

struct Handle {
    _drm_file: File,
    dpy: *mut c_void,
}

unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}
