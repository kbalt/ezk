use std::{iter::from_fn, rc::Rc, u32};

use windows::{
    Win32::Graphics::{
        Direct3D::{D3D_DRIVER_TYPE_HARDWARE, D3D_FEATURE_LEVEL, D3D_FEATURE_LEVEL_11_1},
        Direct3D11::{
            D3D11_BIND_RENDER_TARGET, D3D11_BIND_SHADER_RESOURCE, D3D11_CPU_ACCESS_FLAG,
            D3D11_CPU_ACCESS_READ, D3D11_CREATE_DEVICE_BGRA_SUPPORT, D3D11_CREATE_DEVICE_DEBUG,
            D3D11_MAP_READ, D3D11_MAPPED_SUBRESOURCE, D3D11_RESOURCE_MISC_FLAG,
            D3D11_RESOURCE_MISC_SHARED, D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX,
            D3D11_RESOURCE_MISC_SHARED_NTHANDLE, D3D11_SDK_VERSION, D3D11_TEXTURE2D_DESC,
            D3D11_USAGE, D3D11_USAGE_DEFAULT, D3D11_USAGE_STAGING, D3D11CreateDevice, ID3D11Device,
            ID3D11DeviceContext, ID3D11Texture2D,
        },
        Dxgi::{
            Common::{DXGI_FORMAT, DXGI_SAMPLE_DESC},
            DXGI_ERROR_NOT_FOUND, DXGI_ERROR_WAIT_TIMEOUT, DXGI_OUTDUPL_FRAME_INFO,
            DXGI_OUTPUT_DESC1, IDXGIAdapter, IDXGIDevice, IDXGIKeyedMutex, IDXGIOutput6,
            IDXGIOutputDuplication,
        },
        Gdi::{GetMonitorInfoA, MONITORINFOEXA},
    },
    core::Interface,
};

pub use windows;

use crate::utils::defer;

struct Ctx {
    device: ID3D11Device,
    device_ctx: ID3D11DeviceContext,
}

pub struct DxgiDesktopDuplication {
    ctx: Rc<Ctx>,
}

impl DxgiDesktopDuplication {
    pub fn new() -> DxgiDesktopDuplication {
        let mut device: Option<ID3D11Device> = None;
        let mut device_context: Option<ID3D11DeviceContext> = None;
        let mut feature_level = D3D_FEATURE_LEVEL::default();

        unsafe {
            D3D11CreateDevice(
                None,
                D3D_DRIVER_TYPE_HARDWARE,
                None,
                D3D11_CREATE_DEVICE_DEBUG | D3D11_CREATE_DEVICE_BGRA_SUPPORT,
                Some(&[D3D_FEATURE_LEVEL_11_1]),
                D3D11_SDK_VERSION,
                Some(&mut device as *mut _),
                Some(&mut feature_level as *mut _),
                Some(&mut device_context as *mut _),
            )
            .unwrap();
        }

        let device = device.unwrap();
        let device_ctx = device_context.unwrap();

        Self {
            ctx: Rc::new(Ctx { device, device_ctx }),
        }
    }

    pub fn output(&self, i: u32) -> Option<DxgiOutput> {
        let dxgi_device = self.ctx.device.cast::<IDXGIDevice>().unwrap();
        let dxgi_adapter = unsafe { dxgi_device.GetParent::<IDXGIAdapter>() }.unwrap();

        let dxgi_output = match unsafe { dxgi_adapter.EnumOutputs(i) } {
            Ok(o) => o.cast::<IDXGIOutput6>().unwrap(),
            Err(e) if e.code() == DXGI_ERROR_NOT_FOUND => return None,
            Err(e) => {
                log::warn!("Failed to get DXGIOutput at index={i} {e}");
                return None;
            }
        };

        let mut desc = DXGI_OUTPUT_DESC1::default();
        unsafe { dxgi_output.GetDesc1(&raw mut desc).unwrap() };

        Some(DxgiOutput {
            ctx: self.ctx.clone(),
            dxgi_output,
            desc,
        })
    }

    pub fn outputs(&self) -> impl Iterator<Item = DxgiOutput> + '_ {
        let mut i = 0;

        from_fn(move || {
            let index = i;
            i += 1;

            self.output(index)
        })
    }
}

pub struct DxgiOutput {
    ctx: Rc<Ctx>,
    dxgi_output: IDXGIOutput6,
    desc: DXGI_OUTPUT_DESC1,
}

impl DxgiOutput {
    pub fn raw(&self) -> &IDXGIOutput6 {
        &self.dxgi_output
    }

    pub fn raw_desc(&self) -> &DXGI_OUTPUT_DESC1 {
        &self.desc
    }

    pub fn monitor_info(&self) -> windows::core::Result<MONITORINFOEXA> {
        let mut info = MONITORINFOEXA::default();

        unsafe { GetMonitorInfoA(self.desc.Monitor, (&raw mut info).cast()).ok()? };

        Ok(info)
    }

    pub fn device_name(&self) -> String {
        let len = self.desc.DeviceName.iter().take_while(|c| **c != 0).count();
        String::from_utf16_lossy(&self.desc.DeviceName[..len])
    }

    pub fn create_duplication(&self) -> DxgiOutputDuplication {
        DxgiOutputDuplication {
            ctx: self.ctx.clone(),
            duplication: unsafe { self.dxgi_output.DuplicateOutput(&self.ctx.device).unwrap() },
        }
    }
}

pub struct DxgiOutputDuplication {
    ctx: Rc<Ctx>,
    duplication: IDXGIOutputDuplication,
}

impl DxgiOutputDuplication {
    fn make_dst_texture(
        &self,
        width: u32,
        height: u32,
        format: DXGI_FORMAT,
        usage: D3D11_USAGE,
        cpu_access_flags: D3D11_CPU_ACCESS_FLAG,
        misc_flags: D3D11_RESOURCE_MISC_FLAG,
    ) -> windows::core::Result<ID3D11Texture2D> {
        let desc = D3D11_TEXTURE2D_DESC {
            Width: width,
            Height: height,
            MipLevels: 1,
            ArraySize: 1,
            Format: format,
            SampleDesc: DXGI_SAMPLE_DESC {
                Count: 1,
                Quality: 0,
            },
            Usage: usage,
            BindFlags: D3D11_BIND_RENDER_TARGET.0 as u32 | D3D11_BIND_SHADER_RESOURCE.0 as u32,
            CPUAccessFlags: cpu_access_flags.0 as u32,
            MiscFlags: misc_flags.0 as u32,
        };

        let mut texture = None;
        unsafe {
            self.ctx
                .device
                .CreateTexture2D(&desc, None, Some(&mut texture as *mut _))
        }
        .unwrap();

        Ok(texture.unwrap())
    }

    fn try_capture(
        &mut self,
        usage: D3D11_USAGE,
        cpu_access_flags: D3D11_CPU_ACCESS_FLAG,
        misc_flags: D3D11_RESOURCE_MISC_FLAG,
    ) -> windows::core::Result<Option<(ID3D11Texture2D, [u32; 2])>> {
        unsafe {
            let mut dxgi_resource = None;
            let mut frame_info = DXGI_OUTDUPL_FRAME_INFO::default();

            loop {
                if let Err(e) =
                    self.duplication
                        .AcquireNextFrame(0, &mut frame_info, &mut dxgi_resource)
                {
                    if e.code() == DXGI_ERROR_WAIT_TIMEOUT {
                        return Ok(None);
                    } else {
                        return Err(e);
                    }
                }

                if frame_info.LastPresentTime == 0 {
                    std::thread::yield_now();
                    self.duplication.ReleaseFrame().unwrap();
                    continue;
                }

                break;
            }

            let src_texture = match dxgi_resource {
                Some(dxgi_resource) => dxgi_resource.cast::<ID3D11Texture2D>()?,
                None => return Ok(None),
            };

            let defer_release = defer(|| {
                if let Err(e) = self.duplication.ReleaseFrame() {
                    log::warn!("Failed to release frame: {e}");
                }
            });

            let mut src_desc = D3D11_TEXTURE2D_DESC::default();
            src_texture.GetDesc(&raw mut src_desc);

            let dst_texture = self.make_dst_texture(
                src_desc.Width,
                src_desc.Height,
                src_desc.Format,
                usage,
                cpu_access_flags,
                misc_flags,
            )?;

            dst_texture
                .cast::<IDXGIKeyedMutex>()
                .unwrap()
                .AcquireSync(0, u32::MAX)
                .unwrap();

            self.ctx.device_ctx.CopyResource(&dst_texture, &src_texture);

            dst_texture
                .cast::<IDXGIKeyedMutex>()
                .unwrap()
                .ReleaseSync(0)
                .unwrap();

            drop(defer_release);

            self.ctx.device_ctx.Flush();

            Ok(Some((dst_texture, [src_desc.Width, src_desc.Height])))
        }
    }

    pub fn try_capture_mapped(&mut self) -> windows::core::Result<Option<(Vec<u8>, [u32; 2])>> {
        let Some((texture, [width, height])) = self.try_capture(
            D3D11_USAGE_STAGING,
            D3D11_CPU_ACCESS_READ,
            D3D11_RESOURCE_MISC_FLAG::default(),
        )?
        else {
            return Ok(None);
        };

        unsafe {
            let mut mapped = D3D11_MAPPED_SUBRESOURCE::default();

            // TODO: async + do not wait?
            self.ctx
                .device_ctx
                .Map(&texture, 0, D3D11_MAP_READ, 0, Some(&raw mut mapped))?;

            let src_stride = mapped.RowPitch as usize;
            let src_len = src_stride * height as usize;
            let src = std::slice::from_raw_parts(mapped.pData.cast::<u8>(), src_len);

            let mut dst = vec![0u8; height as usize * width as usize * 4];
            let dst_stride = width as usize * 4;

            for y in 0..height as usize {
                let src_start = y * src_stride;
                let src = &src[src_start..(src_start + dst_stride)];

                let data_start = y * dst_stride;
                let dst = &mut dst[data_start..(data_start + dst_stride)];

                dst.copy_from_slice(src);
            }

            self.ctx.device_ctx.Unmap(&texture, 0);

            Ok(Some((dst, [width, height])))
        }
    }

    pub fn try_capture_shared_texture(
        &mut self,
    ) -> windows::core::Result<Option<(ID3D11Texture2D, [u32; 2])>> {
        self.try_capture(
            D3D11_USAGE_DEFAULT,
            D3D11_CPU_ACCESS_FLAG::default(),
            D3D11_RESOURCE_MISC_SHARED_NTHANDLE | D3D11_RESOURCE_MISC_SHARED_KEYEDMUTEX,
        )
    }
}
