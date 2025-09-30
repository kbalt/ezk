use crate::{Handle, Image, VaError, ffi};
use std::{
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
    sync::Arc,
};

pub struct Surface {
    pub(crate) display: Arc<Handle>,
    pub(crate) surface_id: ffi::VASurfaceID,
}

impl Surface {
    pub fn id(&self) -> ffi::VASurfaceID {
        self.surface_id
    }

    pub fn derive_image(&mut self) -> SurfaceImage<'_> {
        unsafe {
            let mut image = MaybeUninit::uninit();

            VaError::try_(ffi::vaDeriveImage(
                self.display.dpy,
                self.surface_id,
                image.as_mut_ptr(),
            ))
            .unwrap();

            let image = Image {
                display: self.display.clone(),
                image: image.assume_init(),
            };

            SurfaceImage {
                _surface: self,
                image,
            }
        }
    }

    pub fn sync(&mut self) {
        unsafe {
            VaError::try_(ffi::vaSyncSurface(self.display.dpy, self.surface_id)).unwrap();
        }
    }

    pub fn try_sync(&mut self) -> bool {
        unsafe {
            if let Err(e) = VaError::try_(ffi::vaSyncSurface2(self.display.dpy, self.surface_id, 0))
            {
                if e.status == ffi::VA_STATUS_ERROR_TIMEDOUT as ffi::VAStatus {
                    false
                } else {
                    panic!("vaSyncSurface2 failed: {:?}", e);
                }
            } else {
                true
            }
        }
    }
}

impl Drop for Surface {
    fn drop(&mut self) {
        unsafe {
            if let Err(e) = VaError::try_(ffi::vaDestroySurfaces(
                self.display.dpy,
                &raw mut self.surface_id,
                1,
            )) {
                log::error!("Failed to destroy VASurface {}, {}", self.surface_id, e)
            }
        }
    }
}

/// [`Image`] derives from a [`Surface`]. Holds a lifetime since it may not outlive the `Surface`
pub struct SurfaceImage<'a> {
    _surface: &'a mut Surface,
    image: Image,
}

impl Deref for SurfaceImage<'_> {
    type Target = Image;

    fn deref(&self) -> &Self::Target {
        &self.image
    }
}

impl DerefMut for SurfaceImage<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.image
    }
}
