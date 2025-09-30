use std::{ptr::null_mut, sync::Arc};

use crate::{Handle, VaError, ffi};

pub struct Image {
    pub(crate) display: Arc<Handle>,
    pub(crate) image: ffi::VAImage,
}

impl Image {
    pub fn ffi(&self) -> &ffi::VAImage {
        &self.image
    }

    pub fn map(&mut self) -> MappedImage<'_> {
        unsafe {
            let mut mapped = null_mut();

            VaError::try_(ffi::vaMapBuffer(
                self.display.dpy,
                self.image.buf,
                &raw mut mapped,
            ))
            .unwrap();

            MappedImage {
                image: self,
                mapped,
            }
        }
    }
}

impl Drop for Image {
    fn drop(&mut self) {
        unsafe {
            if let Err(e) =
                VaError::try_(ffi::vaDestroyImage(self.display.dpy, self.image.image_id))
            {
                log::error!("Failed to destroy VAImage {}, {}", self.image.image_id, e)
            }
        }
    }
}

pub struct MappedImage<'a> {
    image: &'a mut Image,
    mapped: *mut std::ffi::c_void,
}
impl MappedImage<'_> {
    pub fn data(&mut self) -> *mut u8 {
        self.mapped.cast()
    }
}

impl Drop for MappedImage<'_> {
    fn drop(&mut self) {
        unsafe {
            if let Err(e) = VaError::try_(ffi::vaUnmapBuffer(
                self.image.display.dpy,
                self.image.image.buf,
            )) {
                log::error!("Failed to unmap VABuffer {}, {}", self.image.image.buf, e)
            }
        }
    }
}
