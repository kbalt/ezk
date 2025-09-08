use std::{fs::OpenOptions, io, mem::MaybeUninit, os::fd::AsRawFd, ptr::null_mut, sync::Arc};

use crate::{Config, Context, Handle, Image, Surface, VaError, ffi};

#[derive(Debug, thiserror::Error)]
pub enum DisplayOpenDrmError {
    #[error("Failed to open DRM device")]
    OpenDrmFile(#[from] io::Error),
    #[error("Call to vaGetDisplayDRM failed")]
    GetDisplayDRM,
    #[error("Failed to initialize the va library")]
    Initialize(#[source] VaError),
}

#[derive(Clone)]
pub struct Display {
    handle: Arc<Handle>,
}

impl Display {
    /// Open a DRM display
    ///
    /// Path should be something like `/dev/dri/renderD128` or `/dev/dri/renderD129`
    pub fn open_drm(path: &str) -> Result<Self, DisplayOpenDrmError> {
        let drm_file = OpenOptions::new().read(true).write(true).open(path)?;

        unsafe {
            let dpy = ffi::vaGetDisplayDRM(drm_file.as_raw_fd());

            if dpy.is_null() {
                return Err(DisplayOpenDrmError::GetDisplayDRM);
            }

            let mut major = ffi::VA_MAJOR_VERSION as i32;
            let mut minor = ffi::VA_MINOR_VERSION as i32;

            VaError::try_(ffi::vaInitialize(dpy, &mut major, &mut minor))
                .map_err(DisplayOpenDrmError::Initialize)?;

            Ok(Self {
                handle: Arc::new(Handle {
                    _drm_file: drm_file,
                    dpy,
                }),
            })
        }
    }

    /// Query all available profiles
    pub fn profiles(&self) -> Vec<ffi::VAProfile> {
        let mut num_profiles = unsafe { ffi::vaMaxNumProfiles(self.handle.dpy) };

        let mut profiles: Vec<ffi::VAProfile> = vec![0; num_profiles as usize];

        VaError::try_(unsafe {
            ffi::vaQueryConfigProfiles(
                self.handle.dpy,
                profiles.as_mut_ptr().cast(),
                &raw mut num_profiles,
            )
        })
        .unwrap();

        profiles.truncate(num_profiles as usize);

        profiles
    }

    /// Query all available entrypoints for the given profile
    pub fn entrypoints(&self, profile: ffi::VAProfile) -> Vec<ffi::VAEntrypoint> {
        let mut num_entrypoint = unsafe { ffi::vaMaxNumEntrypoints(self.handle.dpy) };

        let mut entrypoints: Vec<ffi::VAEntrypoint> = vec![0; num_entrypoint as usize];

        VaError::try_(unsafe {
            ffi::vaQueryConfigEntrypoints(
                self.handle.dpy,
                profile,
                entrypoints.as_mut_ptr().cast(),
                &raw mut num_entrypoint,
            )
        })
        .unwrap();

        entrypoints.truncate(num_entrypoint as usize);

        entrypoints
    }

    pub fn get_config_attributes(
        &self,
        profile: ffi::VAProfile,
        entrypoint: ffi::VAEntrypoint,
    ) -> Vec<ffi::VAConfigAttrib> {
        unsafe {
            const MAX_ATTRIBUTES: usize = ffi::VAConfigAttribType_VAConfigAttribTypeMax as usize;

            let mut attrib_list: Vec<ffi::VAConfigAttrib> = (0..MAX_ATTRIBUTES)
                .map(|i| ffi::VAConfigAttrib {
                    type_: i as _,
                    value: 0,
                })
                .collect();

            VaError::try_(ffi::vaGetConfigAttributes(
                self.handle.dpy,
                profile,
                entrypoint,
                attrib_list.as_mut_ptr(),
                MAX_ATTRIBUTES as _,
            ))
            .unwrap();

            attrib_list.set_len(MAX_ATTRIBUTES);

            attrib_list
        }
    }

    pub fn create_config(
        &self,
        profile: ffi::VAProfile,
        entrypoint: ffi::VAEntrypoint,
        attributes: &[ffi::VAConfigAttrib],
    ) -> Result<Config, VaError> {
        let mut config_id = ffi::VA_INVALID_ID;

        VaError::try_(unsafe {
            ffi::vaCreateConfig(
                self.handle.dpy,
                profile,
                entrypoint,
                attributes.as_ptr().cast_mut(),
                attributes.len() as _,
                &raw mut config_id,
            )
        })?;

        Ok(Config {
            display: self.handle.clone(),
            config_id,
        })
    }

    pub fn query_surface_attributes(&self, config: &Config) -> Vec<ffi::VASurfaceAttrib> {
        unsafe {
            let mut num = 0;

            VaError::try_(ffi::vaQuerySurfaceAttributes(
                self.handle.dpy,
                config.config_id,
                null_mut(),
                &raw mut num,
            ))
            .unwrap();

            let mut attrib_list = Vec::with_capacity(num as usize);

            VaError::try_(ffi::vaQuerySurfaceAttributes(
                self.handle.dpy,
                config.config_id,
                attrib_list.as_mut_ptr(),
                &raw mut num,
            ))
            .unwrap();

            attrib_list.set_len(num as usize);

            attrib_list
        }
    }

    pub fn create_surfaces(
        &self,
        format: u32,
        width: u32,
        height: u32,
        num: usize,
        attributes: &[ffi::VASurfaceAttrib],
    ) -> Vec<Surface> {
        unsafe {
            let mut surfaces: Vec<ffi::VASurfaceID> = vec![ffi::VA_INVALID_ID; num];

            VaError::try_(ffi::vaCreateSurfaces(
                self.handle.dpy,
                format,
                width,
                height,
                surfaces.as_mut_ptr(),
                num as _,
                attributes.as_ptr().cast_mut(),
                attributes.len() as _,
            ))
            .unwrap();

            surfaces
                .into_iter()
                .map(|surface_id| Surface {
                    display: self.handle.clone(),
                    surface_id,
                })
                .collect()
        }
    }

    pub fn create_context<'a>(
        &self,
        config: &Config,
        picture_width: i32,
        picture_height: i32,
        flag: i32,
        render_targets: impl IntoIterator<Item = &'a Surface>,
    ) -> Context {
        unsafe {
            let mut render_targets: Vec<ffi::VASurfaceID> =
                render_targets.into_iter().map(|c| c.surface_id).collect();
            let mut context_id = ffi::VA_INVALID_ID;

            VaError::try_(ffi::vaCreateContext(
                self.handle.dpy,
                config.config_id,
                picture_width,
                picture_height,
                flag,
                render_targets.as_mut_ptr(),
                render_targets.len() as _,
                &raw mut context_id,
            ))
            .unwrap();

            Context {
                display: self.handle.clone(),
                context_id,
            }
        }
    }

    pub fn query_image_formats(&self) -> Vec<ffi::VAImageFormat> {
        unsafe {
            let mut num_formats = ffi::vaMaxNumImageFormats(self.handle.dpy);

            let mut formats = Vec::with_capacity(num_formats as usize);

            VaError::try_(ffi::vaQueryImageFormats(
                self.handle.dpy,
                formats.as_mut_ptr(),
                &raw mut num_formats,
            ))
            .unwrap();

            formats.set_len(num_formats as usize);

            formats
        }
    }

    pub fn create_image(&self, mut format: ffi::VAImageFormat, width: i32, height: i32) -> Image {
        unsafe {
            let mut image = MaybeUninit::uninit();

            VaError::try_(ffi::vaCreateImage(
                self.handle.dpy,
                &raw mut format,
                width,
                height,
                image.as_mut_ptr(),
            ))
            .unwrap();

            Image {
                display: self.handle.clone(),
                image: image.assume_init(),
            }
        }
    }
}
