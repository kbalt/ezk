use std::{ffi::c_void, ptr::null_mut, sync::Arc};

use crate::{Handle, VaError, ffi};

#[must_use]
pub struct Buffer {
    pub(crate) display: Arc<Handle>,
    pub(crate) buf_id: ffi::VABufferID,
}

impl Buffer {
    pub fn id(&self) -> ffi::VABufferID {
        self.buf_id
    }

    pub fn map(&mut self) -> MappedBuffer<'_> {
        unsafe {
            let mut mapped = null_mut();

            VaError::try_(ffi::vaMapBuffer(
                self.display.dpy,
                self.buf_id,
                &raw mut mapped,
            ))
            .unwrap();

            MappedBuffer {
                encoded_buffer: self,
                mapped,
            }
        }
    }
}

impl Drop for Buffer {
    fn drop(&mut self) {
        unsafe {
            if let Err(e) = VaError::try_(ffi::vaDestroyBuffer(self.display.dpy, self.buf_id)) {
                log::error!("Failed to destroy VABuffer {}, {}", self.buf_id, e)
            }
        }
    }
}

pub struct MappedBuffer<'a> {
    encoded_buffer: &'a mut Buffer,
    mapped: *mut std::ffi::c_void,
}

impl MappedBuffer<'_> {
    pub fn data(&mut self) -> *mut c_void {
        self.mapped
    }
}

impl Drop for MappedBuffer<'_> {
    fn drop(&mut self) {
        unsafe {
            if let Err(e) = VaError::try_(ffi::vaUnmapBuffer(
                self.encoded_buffer.display.dpy,
                self.encoded_buffer.buf_id,
            )) {
                log::error!(
                    "Failed to unmap VABuffer {}, {}",
                    self.encoded_buffer.buf_id,
                    e
                )
            }
        }
    }
}
