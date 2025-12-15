use crate::wayland::{
    CapturedDmaBuffer, CapturedDmaBufferSync, CapturedDmaRegion, CapturedFrame,
    CapturedFrameBuffer, CapturedMemBuffer, DmaPlane, MemPlane, PipewireOptions, PixelFormat,
    RgbaSwizzle,
};
use pipewire::{
    context::ContextRc,
    main_loop::{MainLoopRc, MainLoopWeak},
    properties::properties,
    spa::{
        self,
        param::{
            ParamType,
            format::{FormatProperties, MediaSubtype, MediaType},
            video::{VideoFormat, VideoInfoRaw},
        },
        pod::{
            ChoiceValue, Object, Pod, Property, PropertyFlags, Value, object, property,
            serialize::PodSerializer,
        },
        utils::{Choice, ChoiceEnum, ChoiceFlags, Direction, Fraction, Id, Rectangle, SpaTypes},
    },
    stream::{Stream, StreamFlags, StreamListener, StreamRc, StreamState},
};
use smallvec::{SmallVec, smallvec};
use std::{
    cell::RefCell,
    io::Cursor,
    os::fd::{BorrowedFd, OwnedFd, RawFd},
    ptr::{null, null_mut},
    rc::Rc,
    slice::from_raw_parts,
};
use tokio::sync::oneshot;

struct BufferGuard<'a> {
    stream: &'a Stream,
    pw_buffer: *mut pipewire::sys::pw_buffer,
}

impl Drop for BufferGuard<'_> {
    fn drop(&mut self) {
        unsafe { self.stream.queue_raw_buffer(self.pw_buffer) };
    }
}

struct UserStreamState {
    main_loop: MainLoopWeak,
    options: PipewireOptions,
    has_video_modifier: bool,

    format: VideoInfoRaw,
    on_frame: Box<dyn FnMut(CapturedFrame) -> bool + Send>,
}

impl UserStreamState {
    fn update_params(&mut self, stream: &Stream) {
        if let Some(dma_options) = &self.options.dma_usage
            && self.has_video_modifier
        {
            let crop_region_params = serialize_object(crop_region_param());
            let dma_buffer_with_sync_params = serialize_object(dma_buffer_with_sync_params());
            let dma_buffer_without_sync_params = serialize_object(dma_buffer_without_sync_params());
            let sync_obj_params = serialize_object(sync_obj_params());

            let mut update_params: SmallVec<[&Pod; 2]> = smallvec::SmallVec::new();

            update_params.push(pod(&crop_region_params));

            if dma_options.request_sync_obj {
                update_params.push(pod(&dma_buffer_with_sync_params));
                update_params.push(pod(&sync_obj_params));
            }

            update_params.push(pod(&dma_buffer_without_sync_params));

            if let Err(e) = stream.update_params(&mut update_params) {
                log::error!("Failed to update stream params: {e}");
            }
        } else {
            let mem_buffer_params = serialize_object(mem_buffer_params());

            let mut update_params = [pod(&mem_buffer_params)];

            if let Err(e) = stream.update_params(&mut update_params) {
                log::error!("Failed to update stream params: {e}");
            }
        }
    }

    fn handle_state_changed(&mut self, _stream: &Stream, old: StreamState, new: StreamState) {
        log::debug!("stream changed: {old:?} -> {new:?}");

        if matches!(new, StreamState::Unconnected | StreamState::Error(..))
            && let Some(main_loop) = self.main_loop.upgrade()
        {
            main_loop.quit();
        }
    }

    fn handle_param_changed(&mut self, stream: &Stream, id: u32, param: Option<&Pod>) {
        let Some(param) = param else {
            return;
        };

        if id != ParamType::Format.as_raw() {
            return;
        }

        let (media_type, media_subtype) =
            match pipewire::spa::param::format_utils::parse_format(param) {
                Ok(v) => v,
                Err(_) => return,
            };

        if media_type != MediaType::Video || media_subtype != MediaSubtype::Raw {
            return;
        }

        self.format
            .parse(param)
            .expect("Failed to parse param changed to VideoInfoRaw");

        log::debug!(
            "Stream format changed to {:?}, resolution={}x{}, framerate={}, max_framerate={}, modifier={}",
            self.format.format(),
            self.format.size().width,
            self.format.size().height,
            (self.format.framerate().num as f32) / (self.format.framerate().denom.max(1) as f32),
            (self.format.max_framerate().num as f32)
                / (self.format.max_framerate().denom.max(1) as f32),
            self.format.modifier()
        );

        // Check explicitly if the Video modifier property has been set
        self.has_video_modifier = unsafe {
            let prop = spa::sys::spa_pod_find_prop(
                param.as_raw_ptr(),
                null(),
                spa::sys::SPA_FORMAT_VIDEO_modifier,
            );

            !prop.is_null()
        };

        self.update_params(stream);
    }

    fn handle_process(&mut self, stream: &Stream) {
        let mut pw_buffer: *mut pipewire::sys::pw_buffer = null_mut();

        // Get the newest buffer from the queue
        loop {
            let tmp = unsafe { stream.dequeue_raw_buffer() };

            if tmp.is_null() {
                break;
            }

            if !pw_buffer.is_null() {
                unsafe {
                    stream.queue_raw_buffer(pw_buffer);
                }
            }

            pw_buffer = tmp;
        }

        let Some(buffer) = (unsafe { pw_buffer.as_ref() }) else {
            return;
        };

        let defer_enqueue = BufferGuard { stream, pw_buffer };

        let Some(buffer) = (unsafe { buffer.buffer.as_ref() }) else {
            return;
        };

        let spa::sys::spa_rectangle { width, height } = self.format.size();
        let width = width as usize;
        let height = height as usize;

        let metas = unsafe { from_raw_parts(buffer.metas, buffer.n_metas as usize) };
        let datas = unsafe { from_raw_parts(buffer.datas, buffer.n_datas as usize) };

        // First check if memory buffers were sent
        let mem_data: SmallVec<[_; 3]> = datas
            .iter()
            .filter(|data| {
                matches!(
                    data.type_,
                    spa::sys::SPA_DATA_MemFd | spa::sys::SPA_DATA_MemPtr
                )
            })
            .collect();

        let frame = if !mem_data.is_empty() {
            self.handle_mem_data(width, height, &mem_data)
        } else {
            let dma_data: SmallVec<[_; 4]> = datas
                .iter()
                .filter(|data| data.type_ == spa::sys::SPA_DATA_DmaBuf)
                .collect();

            if dma_data.is_empty() {
                log::warn!("Got neither MemPtr nor DmaBuf data");
                return;
            }

            self.handle_dma_data(metas, datas, dma_data)
        };

        if !(self.on_frame)(frame) {
            // on_frame returned false, exit the main loop

            if let Some(main_loop) = self.main_loop.upgrade() {
                main_loop.quit();
            }
        }

        drop(defer_enqueue);
    }

    fn handle_dma_data(
        &mut self,
        metas: &[spa::sys::spa_meta],
        datas: &[spa::sys::spa_data],
        dma_data: SmallVec<[&spa::sys::spa_data; 4]>,
    ) -> CapturedFrame {
        fn clone_fd(fd: RawFd) -> OwnedFd {
            unsafe {
                BorrowedFd::borrow_raw(fd)
                    .try_clone_to_owned()
                    .expect("fd received from pipewire must be cloneable")
            }
        }

        let planes = dma_data
            .into_iter()
            .map(|data| {
                let chunk = unsafe { data.chunk.read_unaligned() };

                DmaPlane {
                    fd: clone_fd(data.fd as RawFd),
                    offset: chunk.offset as usize,
                    stride: chunk.stride as usize,
                }
            })
            .collect();

        let format = match self.format.format() {
            VideoFormat::NV12 => PixelFormat::NV12,
            VideoFormat::I420 => PixelFormat::I420,
            VideoFormat::RGBA
            | VideoFormat::RGBx
            | VideoFormat::BGRA
            | VideoFormat::BGRx
            | VideoFormat::ARGB
            | VideoFormat::xRGB
            | VideoFormat::ABGR
            | VideoFormat::xBGR => {
                let swizzle = match self.format.format() {
                    VideoFormat::RGBA | VideoFormat::RGBx => RgbaSwizzle::RGBA,
                    VideoFormat::BGRA | VideoFormat::BGRx => RgbaSwizzle::BGRA,
                    VideoFormat::ARGB | VideoFormat::xRGB => RgbaSwizzle::ARGB,
                    VideoFormat::ABGR | VideoFormat::xBGR => RgbaSwizzle::ABGR,
                    _ => unreachable!(),
                };

                PixelFormat::RGBA(swizzle)
            }
            _ => unreachable!(),
        };

        let region = metas.iter().find_map(|meta| {
            if meta.type_ == spa::sys::SPA_META_VideoCrop {
                let meta = unsafe {
                    meta.data
                        .cast::<spa::sys::spa_meta_region>()
                        .read_unaligned()
                };

                Some(CapturedDmaRegion {
                    x: meta.region.position.x,
                    y: meta.region.position.y,
                    width: meta.region.size.width,
                    height: meta.region.size.height,
                })
            } else {
                None
            }
        });

        let sync_timeline = metas
            .iter()
            .find(|m| m.type_ == spa::sys::SPA_META_SyncTimeline);

        let sync = if let Some(sync_timeline) = sync_timeline {
            let sync_timeline = unsafe {
                sync_timeline
                    .data
                    .cast::<spa::sys::spa_meta_sync_timeline>()
                    .read_unaligned()
            };

            let sync_objs: SmallVec<[_; 2]> = datas
                .iter()
                .filter(|d| d.type_ == spa::sys::SPA_DATA_SyncObj)
                .collect();

            let acquire_sync_obj = clone_fd(sync_objs[0].fd as RawFd);
            let release_sync_obj = clone_fd(sync_objs[1].fd as RawFd);

            Some(CapturedDmaBufferSync {
                acquire_point: sync_timeline.acquire_point,
                release_point: sync_timeline.release_point,
                acquire_fd: acquire_sync_obj,
                release_fd: release_sync_obj,
            })
        } else {
            None
        };

        CapturedFrame {
            width: self.format.size().width,
            height: self.format.size().height,
            format,
            buffer: CapturedFrameBuffer::Dma(CapturedDmaBuffer {
                modifier: self.format.modifier(),
                planes,
                region,
                sync,
            }),
        }
    }

    fn handle_mem_data(
        &mut self,
        width: usize,
        height: usize,
        data: &SmallVec<[&spa::sys::spa_data; 3]>,
    ) -> CapturedFrame {
        match self.format.format() {
            VideoFormat::NV12 => {
                let mut memory = vec![0u8; (width * height * 12).div_ceil(8)];

                let (y_plane, uv_plane) = memory.split_at_mut(width * height);

                copy_plane(data[0], y_plane, height, width);
                copy_plane(data[1], uv_plane, height / 2, width);

                let width = width as u32;
                let height = height as u32;

                CapturedFrame {
                    width,
                    height,
                    format: PixelFormat::NV12,
                    buffer: CapturedFrameBuffer::Mem(CapturedMemBuffer {
                        memory,
                        planes: smallvec![
                            MemPlane {
                                offset: 0,
                                stride: width as usize,
                            },
                            MemPlane {
                                offset: (width * height) as usize,
                                stride: width as usize,
                            }
                        ],
                    }),
                }
            }
            VideoFormat::I420 => {
                let mut memory = vec![0u8; (width * height * 12).div_ceil(8)];

                let (y_plane, uv_plane) = memory.split_at_mut(width * height);
                let (u_plane, v_plane) = uv_plane.split_at_mut((width * height) / 4);

                copy_plane(data[0], y_plane, height, width);
                copy_plane(data[1], u_plane, height / 2, width / 2);
                copy_plane(data[2], v_plane, height / 2, width / 2);

                let width = width as u32;
                let height = height as u32;

                let u_offset = width * height;
                let v_offset = u_offset + (width * height) / 4;

                CapturedFrame {
                    width,
                    height,
                    format: PixelFormat::I420,
                    buffer: CapturedFrameBuffer::Mem(CapturedMemBuffer {
                        memory,
                        planes: smallvec![
                            MemPlane {
                                offset: 0,
                                stride: width as usize
                            },
                            MemPlane {
                                offset: u_offset as usize,
                                stride: width as usize / 2,
                            },
                            MemPlane {
                                offset: v_offset as usize,
                                stride: width as usize / 2,
                            }
                        ],
                    }),
                }
            }
            VideoFormat::RGBA
            | VideoFormat::RGBx
            | VideoFormat::BGRA
            | VideoFormat::BGRx
            | VideoFormat::ARGB
            | VideoFormat::xRGB
            | VideoFormat::ABGR
            | VideoFormat::xBGR => {
                let swizzle = match self.format.format() {
                    VideoFormat::RGBA | VideoFormat::RGBx => RgbaSwizzle::RGBA,
                    VideoFormat::BGRA | VideoFormat::BGRx => RgbaSwizzle::BGRA,
                    VideoFormat::ARGB | VideoFormat::xRGB => RgbaSwizzle::ARGB,
                    VideoFormat::ABGR | VideoFormat::xBGR => RgbaSwizzle::ABGR,
                    _ => unreachable!(),
                };

                let mut memory = vec![0u8; width * height * 4];

                // Single plane
                copy_plane(data[0], &mut memory, height, width * 4);

                let width = width as u32;
                let height = height as u32;

                CapturedFrame {
                    width,
                    height,
                    format: PixelFormat::RGBA(swizzle),
                    buffer: CapturedFrameBuffer::Mem(CapturedMemBuffer {
                        memory,
                        planes: smallvec![MemPlane {
                            offset: 0,
                            stride: width as usize * 4,
                        }],
                    }),
                }
            }
            _ => unreachable!("Received unexpected video format"),
        }
    }
}

fn copy_plane(
    spa_data: &spa::sys::spa_data,
    buffer: &mut [u8],
    height: usize,
    buffer_stride: usize,
) {
    let data_slice = unsafe {
        from_raw_parts(
            spa_data.data.cast::<u8>(),
            spa_data
                .maxsize
                .try_into()
                .expect("maxsize must fit into usize"),
        )
    };

    let chunk = unsafe { spa_data.chunk.read_unaligned() };
    let chunk_offset = (chunk.offset % spa_data.maxsize) as usize;
    let chunk_size = chunk.size as usize;
    let chunk_stride = chunk.stride as usize;
    let chunk_slice = &data_slice[chunk_offset..chunk_offset + chunk_size];

    if chunk_stride == buffer_stride {
        buffer.copy_from_slice(chunk_slice);
    } else {
        // Copy per row
        for y in 0..height {
            let chunk_index = y * chunk_stride;
            let buffer_index = y * buffer_stride;

            let src_slice = &chunk_slice[chunk_index..chunk_index + buffer_stride];
            let dst_slice = &mut buffer[buffer_index..buffer_index + buffer_stride];

            dst_slice.copy_from_slice(src_slice);
        }
    }
}

pub(super) enum Command {
    Play,
    Pause,
    Close,
    RemoveModifier(u64),
}

pub(super) fn start(
    node_id: Option<u32>,
    fd: OwnedFd,
    options: PipewireOptions,
    role: &'static str,
    on_frame: Box<dyn FnMut(CapturedFrame) -> bool + Send>,
    result_tx: oneshot::Sender<Result<pipewire::channel::Sender<Command>, pipewire::Error>>,
) {
    pipewire::init();

    let mainloop = match MainLoopRc::new(None) {
        Ok(mainloop) => mainloop,
        Err(e) => {
            let _ = result_tx.send(Err(e));
            return;
        }
    };

    let (tx, rx) = pipewire::channel::channel();

    let data = match build_stream(&mainloop, node_id, fd, options, role, on_frame) {
        Ok(data_to_not_drop) => data_to_not_drop,
        Err(e) => {
            let _ = result_tx.send(Err(e));
            return;
        }
    };

    let _attach_guard = rx.attach(mainloop.loop_(), move |command| match command {
        Command::Play => {
            if let Err(e) = data.stream.set_active(true) {
                log::warn!("Failed to handle Play command: {e}");
            }
        }
        Command::Pause => {
            if let Err(e) = data.stream.set_active(false) {
                log::warn!("Failed to handle Pause command: {e}");
            }
        }
        Command::Close => {
            if let Err(e) = data.stream.disconnect() {
                log::warn!("Failed to handle Close command: {e}");
            }
        }
        Command::RemoveModifier(modifier) => {
            println!("Remove mod: {modifier}  1");
            let mut user_data = data.user_data.borrow_mut();

            if let Some(dma_usage) = &mut user_data.options.dma_usage {
                println!("Remove mod: {modifier}  2");
                let prev_modifier_len = dma_usage.supported_modifier.len();
                dma_usage.supported_modifier.retain(|m| *m != modifier);

                if prev_modifier_len != dma_usage.supported_modifier.len() {
                    println!("Remove mod: {modifier}  3");
                    if let Err(e) = data.stream.set_active(false) {
                        log::error!("Failed to pause stream to remove DRM modifier: {e}");
                    }

                    user_data.update_params(&data.stream);

                    if let Err(e) = data.stream.set_active(true) {
                        log::error!("Failed to unpause stream to remove DRM modifier: {e}");
                    }
                }
            }
        }
    });

    if result_tx.send(Ok(tx)).is_err() {
        return;
    }

    mainloop.run();
}

struct StreamData {
    stream: StreamRc,
    // This is just a guard object needed to keep alive
    #[expect(dead_code)]
    listener: StreamListener<Rc<RefCell<UserStreamState>>>,
    user_data: Rc<RefCell<UserStreamState>>,
}

fn build_stream(
    mainloop: &MainLoopRc,
    node_id: Option<u32>,
    fd: OwnedFd,
    options: PipewireOptions,
    role: &'static str,
    on_frame: Box<dyn FnMut(CapturedFrame) -> bool + Send>,
) -> Result<StreamData, pipewire::Error> {
    let context = ContextRc::new(mainloop, None)?;
    let core = context.connect_fd_rc(fd, None)?;
    let user_data = Rc::new(RefCell::new(UserStreamState {
        format: Default::default(),
        main_loop: mainloop.downgrade(),
        on_frame,
        options: options.clone(),
        has_video_modifier: false,
    }));

    let stream = StreamRc::new(
        core,
        "capture",
        properties! {
            *pipewire::keys::MEDIA_TYPE => "Video",
            *pipewire::keys::MEDIA_CATEGORY => "Capture",
            *pipewire::keys::MEDIA_ROLE => role,
        },
    )?;

    let listener = stream
        .add_local_listener_with_user_data(user_data.clone())
        .state_changed(|stream, user_data, old, new| {
            user_data
                .borrow_mut()
                .handle_state_changed(stream, old, new);
        })
        .param_changed(|stream, user_data, id, param| {
            user_data
                .borrow_mut()
                .handle_param_changed(stream, id, param);
        })
        .process(move |stream, user_data| {
            user_data.borrow_mut().handle_process(stream);
        })
        .register()?;

    let mut connect_params: SmallVec<[_; 2]> = SmallVec::new();

    // Add the format params with the video drm modifier property first if dma buffers are to be used
    if let Some(dma_usage) = options.dma_usage {
        let mut format_params = format_params(&options.pixel_formats, options.max_framerate);
        format_params
            .properties
            .push(drm_modifier_property(&dma_usage.supported_modifier));
        connect_params.push(serialize_object(format_params));
    }

    // Add format without video drm modifier property
    connect_params.push(serialize_object(format_params(
        &options.pixel_formats,
        options.max_framerate,
    )));

    let mut connect_params: SmallVec<[&Pod; 2]> =
        connect_params.iter().map(|param| pod(param)).collect();

    stream.connect(
        Direction::Input,
        node_id,
        StreamFlags::AUTOCONNECT | StreamFlags::MAP_BUFFERS,
        &mut connect_params,
    )?;

    Ok(StreamData {
        stream,
        listener,
        user_data,
    })
}

/// Build the video format capabilities which will be used to negotiate a video stream with pipewire
fn format_params(pixel_formats: &[PixelFormat], max_framerate: u32) -> Object {
    fn map(p: PixelFormat) -> &'static [VideoFormat] {
        match p {
            PixelFormat::NV12 => &[VideoFormat::NV12],
            PixelFormat::I420 => &[VideoFormat::I420],
            PixelFormat::RGBA(rgba_swizzle) => match rgba_swizzle {
                RgbaSwizzle::RGBA => &[VideoFormat::RGBA, VideoFormat::RGBx],
                RgbaSwizzle::BGRA => &[VideoFormat::BGRA, VideoFormat::BGRx],
                RgbaSwizzle::ARGB => &[VideoFormat::ARGB, VideoFormat::xRGB],
                RgbaSwizzle::ABGR => &[VideoFormat::ABGR, VideoFormat::xBGR],
            },
        }
    }

    let video_formats = Value::Choice(ChoiceValue::Id(Choice(
        ChoiceFlags::empty(),
        ChoiceEnum::Enum {
            default: Id(map(pixel_formats[0])[0].0),
            alternatives: pixel_formats
                .iter()
                .flat_map(|p| map(*p).iter().copied())
                .map(|video_format| Id(video_format.as_raw()))
                .collect(),
        },
    )));

    let video_formats_property = Property {
        key: FormatProperties::VideoFormat.as_raw(),
        flags: PropertyFlags::empty(),
        value: video_formats,
    };

    object!(
        SpaTypes::ObjectParamFormat,
        ParamType::EnumFormat,
        property!(FormatProperties::MediaType, Id, MediaType::Video),
        property!(FormatProperties::MediaSubtype, Id, MediaSubtype::Raw),
        video_formats_property,
        property!(
            FormatProperties::VideoSize,
            Choice,
            Range,
            Rectangle,
            // Default
            Rectangle {
                width: 320,
                height: 240
            },
            // Min
            Rectangle {
                width: 16,
                height: 16
            },
            // Max
            Rectangle {
                width: 32768,
                height: 32768
            }
        ),
        property!(
            FormatProperties::VideoFramerate,
            Choice,
            Range,
            Fraction,
            // Default
            Fraction {
                num: max_framerate,
                denom: 1
            },
            // Min
            Fraction { num: 0, denom: 1 },
            // Max
            Fraction {
                num: max_framerate,
                denom: 1
            }
        ),
    )
}

fn mem_buffer_params() -> Object {
    let mut params = object!(SpaTypes::ObjectParamBuffers, ParamType::Buffers,);

    params.properties.push(Property {
        key: spa::sys::SPA_PARAM_BUFFERS_dataType,
        flags: PropertyFlags::empty(),
        value: Value::Choice(ChoiceValue::Int(Choice(
            ChoiceFlags::empty(),
            ChoiceEnum::Flags {
                default: 1 << spa::sys::SPA_DATA_MemFd,
                flags: vec![
                    1 << spa::sys::SPA_DATA_MemFd,
                    1 << spa::sys::SPA_DATA_MemPtr,
                ],
            },
        ))),
    });

    params
}

fn dma_buffer_with_sync_params() -> Object {
    let mut params = object!(SpaTypes::ObjectParamBuffers, ParamType::Buffers,);

    params.properties.push(Property {
        key: spa::sys::SPA_PARAM_BUFFERS_dataType,
        flags: PropertyFlags::empty(),
        value: Value::Int(1 << spa::sys::SPA_DATA_DmaBuf),
    });

    params.properties.push(Property {
        key: spa::sys::SPA_PARAM_BUFFERS_metaType,
        flags: PropertyFlags::MANDATORY,
        value: Value::Int(1 << spa::sys::SPA_META_SyncTimeline),
    });

    params
}

fn dma_buffer_without_sync_params() -> Object {
    let mut params = object!(SpaTypes::ObjectParamBuffers, ParamType::Buffers,);

    params.properties.push(Property {
        key: spa::sys::SPA_PARAM_BUFFERS_dataType,
        flags: PropertyFlags::empty(),
        value: Value::Int(1 << spa::sys::SPA_DATA_DmaBuf),
    });

    params
}

fn drm_modifier_property(drm_modifier: &[u64]) -> Property {
    let default = drm_modifier[0].cast_signed();
    let alternatives = drm_modifier.iter().copied().map(u64::cast_signed).collect();

    Property {
        key: FormatProperties::VideoModifier.as_raw(),
        flags: PropertyFlags::MANDATORY | PropertyFlags::DONT_FIXATE,
        value: Value::Choice(ChoiceValue::Long(Choice(
            ChoiceFlags::empty(),
            ChoiceEnum::Enum {
                default,
                alternatives,
            },
        ))),
    }
}

fn sync_obj_params() -> Object {
    Object {
        type_: spa::sys::SPA_TYPE_OBJECT_ParamMeta,
        id: spa::sys::SPA_PARAM_Meta,
        properties: [
            Property {
                key: spa::sys::SPA_PARAM_META_type,
                flags: PropertyFlags::empty(),
                value: Value::Id(Id(spa::sys::SPA_META_SyncTimeline)),
            },
            Property {
                key: spa::sys::SPA_PARAM_META_size,
                flags: PropertyFlags::empty(),
                value: Value::Int(size_of::<spa::sys::spa_meta_sync_timeline>() as i32),
            },
        ]
        .into(),
    }
}

fn crop_region_param() -> Object {
    Object {
        type_: spa::sys::SPA_TYPE_OBJECT_ParamMeta,
        id: spa::sys::SPA_PARAM_Meta,
        properties: [
            Property {
                key: spa::sys::SPA_PARAM_META_type,
                flags: PropertyFlags::empty(),
                value: Value::Id(Id(spa::sys::SPA_META_VideoCrop)),
            },
            Property {
                key: spa::sys::SPA_PARAM_META_size,
                flags: PropertyFlags::empty(),
                value: Value::Int(size_of::<spa::sys::spa_meta_region>() as i32),
            },
        ]
        .into(),
    }
}

fn serialize_object(object: Object) -> Vec<u8> {
    PodSerializer::serialize(Cursor::new(Vec::new()), &Value::Object(object))
        .expect("objects must be serializable")
        .0
        .into_inner()
}

fn pod(pod: &[u8]) -> &Pod {
    Pod::from_bytes(pod).expect("Object was serialized as pod")
}
