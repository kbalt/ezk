use std::{ffi::c_void, ptr::null_mut, sync::Arc};

use crate::{Handle, Surface, VaError, buffer::Buffer, ffi};

pub struct Context {
    pub(crate) display: Arc<Handle>,
    pub(crate) context_id: ffi::VAContextID,
}

impl Context {
    pub fn create_buffer_empty(
        &self,
        type_: ffi::VABufferType,
        size: usize,
    ) -> Result<Buffer, VaError> {
        unsafe {
            let mut buf_id = ffi::VA_INVALID_ID;

            VaError::try_(ffi::vaCreateBuffer(
                self.display.dpy,
                self.context_id,
                type_,
                size as _,
                1,
                null_mut(),
                &raw mut buf_id,
            ))?;

            Ok(Buffer {
                display: self.display.clone(),
                buf_id,
            })
        }
    }

    pub fn create_buffer_with_data<T: Copy>(
        &self,
        type_: ffi::VABufferType,
        data: &T,
    ) -> Result<Buffer, VaError> {
        unsafe {
            let mut buf_id = ffi::VA_INVALID_ID;

            VaError::try_(ffi::vaCreateBuffer(
                self.display.dpy,
                self.context_id,
                type_,
                size_of::<T>() as _,
                1,
                data as *const T as *mut c_void,
                &raw mut buf_id,
            ))?;

            Ok(Buffer {
                display: self.display.clone(),
                buf_id,
            })
        }
    }

    pub fn create_buffer_from_bytes(
        &self,
        type_: ffi::VABufferType,
        bytes: &[u8],
    ) -> Result<Buffer, VaError> {
        unsafe {
            let mut buf_id = ffi::VA_INVALID_ID;

            VaError::try_(ffi::vaCreateBuffer(
                self.display.dpy,
                self.context_id,
                type_,
                bytes.len() as _,
                1,
                bytes.as_ptr().cast_mut().cast(),
                &raw mut buf_id,
            ))?;

            Ok(Buffer {
                display: self.display.clone(),
                buf_id,
            })
        }
    }

    pub fn begin_picture(&self, render_target: &Surface) -> Result<(), VaError> {
        debug_assert!(Arc::ptr_eq(&self.display, &render_target.display));

        unsafe {
            VaError::try_(ffi::vaBeginPicture(
                self.display.dpy,
                self.context_id,
                render_target.surface_id,
            ))
        }
    }

    pub fn render_picture<'a>(
        &self,
        buffers: impl IntoIterator<Item = &'a Buffer>,
    ) -> Result<(), VaError> {
        unsafe {
            let buffers: Vec<ffi::VABufferID> = buffers.into_iter().map(|b| b.buf_id).collect();

            VaError::try_(ffi::vaRenderPicture(
                self.display.dpy,
                self.context_id,
                buffers.as_ptr().cast_mut(),
                buffers.len() as _,
            ))
        }
    }

    pub fn end_picture(&self) -> Result<(), VaError> {
        unsafe { VaError::try_(ffi::vaEndPicture(self.display.dpy, self.context_id)) }
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            if let Err(e) = VaError::try_(ffi::vaDestroyContext(self.display.dpy, self.context_id))
            {
                log::error!("Failed to destroy VAContext {}, {}", self.context_id, e)
            }
        }
    }
}
