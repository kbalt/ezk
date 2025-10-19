use ashpd::{
    desktop::screencast::{CursorMode, Screencast},
    enumflags2::BitFlags,
};
use std::{os::fd::OwnedFd, thread};
use tokio::sync::oneshot;

mod stream;

pub use ashpd::{
    desktop::{PersistMode, screencast::SourceType},
    enumflags2::BitFlag,
};

/// Options for configuring a Wayland/Pipewire capture session
#[derive(Debug)]
pub struct ScreenCaptureOptions {
    /// Embed the cursor in the video
    pub embed_cursor: bool,

    /// Which sources to captures
    pub source_types: BitFlags<SourceType>,

    /// Screen capture permission persistence
    pub persist_mode: PersistMode,

    /// Pipewire specific options
    pub pipewire: PipewireOptions,
}

impl Default for ScreenCaptureOptions {
    fn default() -> Self {
        Self {
            embed_cursor: true,
            source_types: SourceType::all(),
            persist_mode: PersistMode::DoNot,
            pipewire: PipewireOptions::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PipewireOptions {
    /// Maximum framerate to negotiate in the pipewire stream
    pub max_framerate: u32,

    /// Configure usage of DMA buffers
    pub dma_usage: Option<DmaUsageOptions>,
}

impl Default for PipewireOptions {
    fn default() -> Self {
        Self {
            max_framerate: 30,
            dma_usage: None,
        }
    }
}

/// Options for configuring usage of DMA Buffers
#[derive(Debug, Clone)]
pub struct DmaUsageOptions {
    /// Request sync objects for explicit DMA buffer synchronization
    pub request_sync_obj: bool,

    /// Number of buffers to allocate for the session
    ///
    /// This must be set to a high enough value to avoid deadlocking in certain scenarios
    ///
    /// E.g. if a H.264 encoder is used, `num_buffers` must be at least as large as the `ip_interval + 1`,
    /// as the encoder will hold onto these buffers until they can be encoded out of order, releasing them all at once.
    pub num_buffers: u32,

    /// Supported DRM modifiers
    pub supported_modifier: Vec<u64>,
}

#[derive(Debug)]
pub enum PixelFormat {
    /// 2 Plane YUV with 4:2:0 subsampling
    NV12,
    /// 3 Plane YUV with 4:2:0 subsampling
    I420,
    /// Any form of 4 component RGB
    RGBA(RgbaSwizzle),
}

#[derive(Debug)]
pub enum RgbaSwizzle {
    RGBA,
    BGRA,
    ARGB,
    ABGR,
}

#[derive(Debug)]
pub struct CapturedFrame {
    pub width: u32,
    pub height: u32,
    pub format: CapturedFrameFormat,
    pub buffer: CapturedFrameBuffer,
}

/// Defines the layout of the data inside a [`CapturedFrameBuffer`]
#[derive(Debug)]
pub enum CapturedFrameFormat {
    NV12 {
        offsets: [u32; 2],
        strides: [u32; 2],
    },
    I420 {
        offsets: [u32; 3],
        strides: [u32; 3],
    },
    RGBA {
        offset: u32,
        stride: u32,
        swizzle: RgbaSwizzle,
    },
}

/// Captured buffer type, contents are defined by [`CapturedFrameFormat`]
pub enum CapturedFrameBuffer {
    Vec(Vec<u8>),
    DmaBuf(CapturedDmaBuffer),
}

impl std::fmt::Debug for CapturedFrameBuffer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Vec(vec) => f.debug_tuple("Vec(len)").field(&vec.len()).finish(),
            Self::DmaBuf(buffer) => f.debug_tuple("DmaBuf").field(buffer).finish(),
        }
    }
}

#[derive(Debug)]
pub struct CapturedDmaBuffer {
    pub fd: OwnedFd,
    pub modifier: u64,
    pub sync: Option<CapturedDmaBufferSync>,
}

#[derive(Debug)]
pub struct CapturedDmaBufferSync {
    pub acquire_point: u64,
    pub release_point: u64,

    pub acquire_fd: OwnedFd,
    pub release_fd: OwnedFd,
}

#[derive(Debug, thiserror::Error)]
#[error("Stream has been closed")]
pub struct StreamClosedError;

#[derive(Clone)]
pub struct StreamHandle {
    sender: pipewire::channel::Sender<stream::Command>,
}

impl StreamHandle {
    pub fn play(&self) -> Result<(), StreamClosedError> {
        self.sender
            .send(stream::Command::Play)
            .map_err(|_| StreamClosedError)
    }

    pub fn pause(&self) -> Result<(), StreamClosedError> {
        self.sender
            .send(stream::Command::Pause)
            .map_err(|_| StreamClosedError)
    }

    pub fn close(&self) -> Result<(), StreamClosedError> {
        self.sender
            .send(stream::Command::Close)
            .map_err(|_| StreamClosedError)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum StartCaptureError {
    #[error(transparent)]
    DesktopPortal(#[from] ashpd::Error),
    #[error("no streams were selected")]
    NoStreamSelected,
    #[error("capture thread panicked while creating stream")]
    CaptureThreadPanicked,
    #[error("Failed to create pipewire stream: {0}")]
    Pipewire(#[from] pipewire::Error),
}

/// Start a screen capture thread with the given options
///
/// Calls `on_frame` until either the screen capture is cancelled or `on_frame` returns false
pub async fn start_screen_capture<F>(
    options: ScreenCaptureOptions,
    on_frame: F,
) -> Result<StreamHandle, StartCaptureError>
where
    F: FnMut(CapturedFrame) -> bool + Send + 'static,
{
    start_screen_capture_boxed(options, Box::new(on_frame)).await
}

async fn start_screen_capture_boxed(
    options: ScreenCaptureOptions,
    on_frame: Box<dyn FnMut(CapturedFrame) -> bool + Send>,
) -> Result<StreamHandle, StartCaptureError> {
    let proxy = Screencast::new().await?;

    let session = proxy.create_session().await?;

    let cursor_mode = if options.embed_cursor {
        CursorMode::Embedded
    } else {
        CursorMode::Hidden
    };

    proxy
        .select_sources(
            &session,
            cursor_mode,
            options.source_types,
            false,
            None,
            options.persist_mode,
        )
        .await?;

    let response = proxy.start(&session, None).await?.response()?;

    let stream = response
        .streams()
        .first()
        .ok_or(StartCaptureError::NoStreamSelected)?;

    let node_id = stream.pipe_wire_node_id();
    let fd = proxy.open_pipe_wire_remote(&session).await?;

    let (result_tx, result_rx) = oneshot::channel();

    thread::Builder::new()
        .name("pipewire-capture".into())
        .spawn(move || {
            stream::start(
                Some(node_id),
                fd,
                options.pipewire,
                "Screen",
                on_frame,
                result_tx,
            );
        })
        .expect("Thread creation ");

    let sender = result_rx
        .await
        .map_err(|_| StartCaptureError::CaptureThreadPanicked)??;

    Ok(StreamHandle { sender })
}
