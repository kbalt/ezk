use std::{
    ffi::{CStr, c_int},
    fmt,
    fs::OpenOptions,
    io,
    mem::{MaybeUninit, zeroed},
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    ptr::null_mut,
    sync::Arc,
};

use crate::{
    Config, Context, Handle, Image, Surface, VaError,
    ffi::{self, vaQueryImageFormats},
};

#[derive(Debug, thiserror::Error)]
pub enum DisplayOpenDrmError {
    #[error("IO error {0}")]
    Io(#[from] io::Error),
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
    /// Enumerate all DRM displays
    pub fn enumerate_drm() -> Result<Vec<Self>, DisplayOpenDrmError> {
        let read_dir = std::fs::read_dir("/dev/dri")?;

        let mut devices = Vec::new();

        for entry in read_dir {
            let entry = entry?;

            if !entry.file_name().as_encoded_bytes().starts_with(b"renderD") {
                continue;
            }

            let display = Self::open_drm(entry.path())?;

            devices.push(display);
        }

        devices.sort_by(|l, r| l.drm_path().cmp(r.drm_path()));

        Ok(devices)
    }

    /// Open a DRM display
    ///
    /// Path should be something like `/dev/dri/renderD128` or `/dev/dri/renderD129`
    pub fn open_drm<P: AsRef<Path>>(path: P) -> Result<Self, DisplayOpenDrmError> {
        let drm_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path.as_ref())?;

        unsafe {
            let dpy = ffi::vaGetDisplayDRM(drm_file.as_raw_fd());

            if dpy.is_null() {
                return Err(DisplayOpenDrmError::GetDisplayDRM);
            }

            let mut major = ffi::VA_MAJOR_VERSION as i32;
            let mut minor = ffi::VA_MINOR_VERSION as i32;

            VaError::try_(ffi::vaInitialize(dpy, &mut major, &mut minor))
                .map_err(DisplayOpenDrmError::Initialize)?;

            // Query display attributes
            let mut attributes = [ffi::VADisplayAttribute {
                type_: ffi::VADisplayAttribType_VADisplayPCIID,
                ..zeroed()
            }];
            let mut num_attributes = attributes.len() as c_int;

            VaError::try_(ffi::vaQueryDisplayAttributes(
                dpy,
                attributes.as_mut_ptr(),
                &raw mut num_attributes,
            ))
            .map_err(DisplayOpenDrmError::Initialize)?;

            let [b0, b1, b2, b3] = attributes[0].value.to_ne_bytes();
            let device_id = u16::from_ne_bytes([b0, b1]);
            let vendor_id = u16::from_ne_bytes([b2, b3]);

            Ok(Self {
                handle: Arc::new(Handle {
                    _drm_file: drm_file,
                    drm_path: path.as_ref().into(),
                    vendor_id,
                    device_id,
                    dpy,
                }),
            })
        }
    }

    pub fn drm_path(&self) -> &PathBuf {
        &self.handle.drm_path
    }

    pub fn vendor_id(&self) -> u16 {
        self.handle.vendor_id
    }

    pub fn device_id(&self) -> u16 {
        self.handle.device_id
    }

    pub fn vendor(&self) -> Option<&'static CStr> {
        unsafe {
            let char_ptr = ffi::vaQueryVendorString(self.handle.dpy);

            if char_ptr.is_null() {
                None
            } else {
                Some(CStr::from_ptr(char_ptr))
            }
        }
    }

    /// Query all available profiles
    pub fn profiles(&self) -> Result<Vec<ffi::VAProfile>, VaError> {
        let mut num_profiles = unsafe { ffi::vaMaxNumProfiles(self.handle.dpy) };

        let mut profiles: Vec<ffi::VAProfile> = vec![0; num_profiles as usize];

        VaError::try_(unsafe {
            ffi::vaQueryConfigProfiles(
                self.handle.dpy,
                profiles.as_mut_ptr().cast(),
                &raw mut num_profiles,
            )
        })?;

        profiles.truncate(num_profiles as usize);

        Ok(profiles)
    }

    /// Query all available entrypoints for the given profile
    pub fn entrypoints(&self, profile: ffi::VAProfile) -> Result<Vec<ffi::VAEntrypoint>, VaError> {
        let mut num_entrypoint = unsafe { ffi::vaMaxNumEntrypoints(self.handle.dpy) };

        let mut entrypoints: Vec<ffi::VAEntrypoint> = vec![0; num_entrypoint as usize];

        VaError::try_(unsafe {
            ffi::vaQueryConfigEntrypoints(
                self.handle.dpy,
                profile,
                entrypoints.as_mut_ptr().cast(),
                &raw mut num_entrypoint,
            )
        })?;

        entrypoints.truncate(num_entrypoint as usize);

        Ok(entrypoints)
    }

    /// Query all supported image formats
    pub fn image_formats(&self) -> Result<Vec<ffi::VAImageFormat>, VaError> {
        unsafe {
            let mut len = ffi::vaMaxNumImageFormats(self.handle.dpy);

            let mut formats = vec![zeroed(); len as usize];

            VaError::try_(vaQueryImageFormats(
                self.handle.dpy,
                formats.as_mut_ptr(),
                &raw mut len,
            ))?;

            formats.truncate(len as usize);

            Ok(formats)
        }
    }

    pub fn get_config_attributes(
        &self,
        profile: ffi::VAProfile,
        entrypoint: ffi::VAEntrypoint,
    ) -> Result<Vec<ffi::VAConfigAttrib>, VaError> {
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
            ))?;

            attrib_list.set_len(MAX_ATTRIBUTES);

            Ok(attrib_list)
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

    pub fn query_surface_attributes(
        &self,
        config: &Config,
    ) -> Result<Vec<ffi::VASurfaceAttrib>, VaError> {
        unsafe {
            let mut num = 0;

            VaError::try_(ffi::vaQuerySurfaceAttributes(
                self.handle.dpy,
                config.config_id,
                null_mut(),
                &raw mut num,
            ))?;

            let mut attrib_list = Vec::with_capacity(num as usize);

            VaError::try_(ffi::vaQuerySurfaceAttributes(
                self.handle.dpy,
                config.config_id,
                attrib_list.as_mut_ptr(),
                &raw mut num,
            ))?;

            attrib_list.set_len(num as usize);

            Ok(attrib_list)
        }
    }

    pub fn create_surfaces(
        &self,
        format: u32,
        width: u32,
        height: u32,
        num: usize,
        attributes: &[ffi::VASurfaceAttrib],
    ) -> Result<Vec<Surface>, VaError> {
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
            ))?;

            let surfaces = surfaces
                .into_iter()
                .map(|surface_id| Surface {
                    display: self.handle.clone(),
                    surface_id,
                })
                .collect();

            Ok(surfaces)
        }
    }

    pub fn create_context<'a>(
        &self,
        config: &Config,
        picture_width: i32,
        picture_height: i32,
        flag: i32,
        render_targets: impl IntoIterator<Item = &'a Surface>,
    ) -> Result<Context, VaError> {
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
            ))?;

            Ok(Context {
                display: self.handle.clone(),
                context_id,
            })
        }
    }

    pub fn query_image_formats(&self) -> Result<Vec<ffi::VAImageFormat>, VaError> {
        unsafe {
            let mut num_formats = ffi::vaMaxNumImageFormats(self.handle.dpy);

            let mut formats = Vec::with_capacity(num_formats as usize);

            VaError::try_(ffi::vaQueryImageFormats(
                self.handle.dpy,
                formats.as_mut_ptr(),
                &raw mut num_formats,
            ))?;

            formats.set_len(num_formats as usize);

            Ok(formats)
        }
    }

    pub fn create_image(
        &self,
        mut format: ffi::VAImageFormat,
        width: i32,
        height: i32,
    ) -> Result<Image, VaError> {
        unsafe {
            let mut image = MaybeUninit::uninit();

            VaError::try_(ffi::vaCreateImage(
                self.handle.dpy,
                &raw mut format,
                width,
                height,
                image.as_mut_ptr(),
            ))?;

            Ok(Image {
                display: self.handle.clone(),
                image: image.assume_init(),
            })
        }
    }
}

impl fmt::Debug for Display {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Display")
            .field("dpy", &self.handle.dpy)
            .field("drm_path", &self.handle.drm_path)
            .field("vendor_id", &self.handle.vendor_id)
            .field("device_id", &self.handle.device_id)
            .field("vendor", &self.vendor())
            .finish()
    }
}
