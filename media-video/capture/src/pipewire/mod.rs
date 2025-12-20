use crate::pipewire::streams::StreamState;
use pipewire::{
    Error, channel,
    context::ContextRc,
    core::CoreRc,
    keys::{APP_NAME, MEDIA_CLASS, NODE_DESCRIPTION, NODE_NAME, NODE_NICK, OBJECT_SERIAL},
    main_loop::MainLoopRc,
    properties::properties,
    registry::{self, RegistryRc},
    spa::{
        pod::{Pod, Value, serialize::PodSerializer},
        utils::Direction,
    },
    stream::{StreamFlags, StreamListener, StreamRc},
    types::ObjectType,
};
use slotmap::{SlotMap, new_key_type};
use std::{cell::RefCell, io::Cursor, rc::Rc, sync::Arc, thread};
use tokio::sync::oneshot;

mod caps;
mod streams;

pub use caps::AudioCaps;
pub use pipewire::spa::param::audio::AudioFormat;

new_key_type! {
    pub struct StreamId;
}

pub trait NodeListener: Send + 'static {
    fn node_added(&mut self, info: NodeInfo);
    fn node_removed(&mut self, id: u32);
}

#[derive(Debug)]
pub struct NodeInfo {
    pub id: u32,
    pub object_serial: String,
    pub media_class: MediaClass,
    pub node_name: Option<String>,
    pub node_nick: Option<String>,
    pub node_description: Option<String>,
    pub app_name: Option<String>,
}

#[derive(Debug, Clone, Copy)]
pub enum MediaClass {
    /// Microphones
    AudioSource,
    /// Speakers
    AudioSink,
    /// Applications that produce audio
    AudioStreamOutput,
}

pub trait AudioConsumer: Send + 'static {
    fn set_format(&mut self, sample_rate: u32, channels: u32, format: AudioFormat);
    fn on_frame(&mut self, data: &[u8]) -> bool;
}

#[derive(Clone)]
pub struct PipeWireAudioCapture {
    sender: Arc<channel::Sender<Command>>,
}

impl Drop for PipeWireAudioCapture {
    fn drop(&mut self) {
        if Arc::strong_count(&self.sender) == 1 {
            let _ = self.sender.send(Command::Destroy);
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Pipewire thread is unexpectedly gone")]
pub struct PipeWireThreadGone;

#[derive(Debug, thiserror::Error)]
pub enum PipeWireConnectError {
    #[error(transparent)]
    Gone(#[from] PipeWireThreadGone),
    #[error(transparent)]
    PipeWire(#[from] Error),
}

impl PipeWireAudioCapture {
    pub async fn spawn() -> Option<PipeWireAudioCapture> {
        let (result_tx, result_rx) = oneshot::channel();
        let (sender, receiver) = channel::channel();

        let handle = PipeWireAudioCapture {
            sender: Arc::new(sender.clone()),
        };

        thread::spawn(move || PipeWireThread::run(sender, receiver, result_tx));

        result_rx.await.ok().map(|_| handle)
    }

    pub fn add_listener(&self, listener: impl NodeListener) -> Result<(), PipeWireThreadGone> {
        self.sender
            .send(Command::AddListener(Box::new(listener)))
            .map_err(|_| PipeWireThreadGone)
    }

    pub async fn connect(
        &self,
        target_object: Option<String>,
        consumer: impl AudioConsumer,
        audio_caps: AudioCaps,
        dont_reconnect: bool,
    ) -> Result<StreamId, PipeWireConnectError> {
        let (tx, rx) = oneshot::channel();

        self.sender
            .send(Command::Connect {
                target_object,
                consumer: Box::new(consumer),
                audio_caps,
                dont_reconnect,
                ret: tx,
            })
            .map_err(|_| PipeWireThreadGone)?;

        rx.await
            .map_err(|_| PipeWireThreadGone)?
            .map_err(|e| e.into())
    }

    pub fn update_caps(
        &self,
        stream_id: StreamId,
        audio_caps: AudioCaps,
    ) -> Result<(), PipeWireThreadGone> {
        self.sender
            .send(Command::UpdateCaps(stream_id, audio_caps))
            .map_err(|_| PipeWireThreadGone)
    }
}

#[allow(clippy::large_enum_variant)]
enum Command {
    AddListener(Box<dyn NodeListener>),
    Connect {
        target_object: Option<String>,
        consumer: Box<dyn AudioConsumer>,
        audio_caps: AudioCaps,
        dont_reconnect: bool,
        ret: oneshot::Sender<Result<StreamId, Error>>,
    },
    UpdateCaps(StreamId, AudioCaps),
    RemoveStream(StreamId),
    Destroy,
}

struct PipeWireThread {
    main_loop: MainLoopRc,
    core: CoreRc,
    registry: RegistryRc,

    sender: channel::Sender<Command>,

    registry_listener: Vec<registry::Listener>,
    streams: SlotMap<StreamId, (StreamRc, StreamListener<StreamState>)>,
}

impl PipeWireThread {
    fn create() -> Result<(MainLoopRc, CoreRc, RegistryRc), Error> {
        let main_loop = MainLoopRc::new(None)?;
        let context = ContextRc::new(&main_loop, None)?;
        let core = context.connect_rc(None)?;
        let registry = core.get_registry_rc()?;

        Ok((main_loop, core, registry))
    }

    fn run(
        sender: channel::Sender<Command>,
        receiver: channel::Receiver<Command>,
        result_tx: oneshot::Sender<Result<(), Error>>,
    ) {
        let (main_loop, core, registry) = match Self::create() {
            Ok(v) => {
                let _ = result_tx.send(Ok(()));
                v
            }
            Err(e) => {
                log::warn!("Failed to create pipewire thread {e}");
                let _ = result_tx.send(Err(e));
                return;
            }
        };

        let this = RefCell::new(PipeWireThread {
            main_loop: main_loop.clone(),
            core,
            registry,
            registry_listener: Vec::new(),
            streams: SlotMap::default(),
            sender,
        });

        let _attached = receiver.attach(main_loop.loop_(), move |command| match command {
            Command::AddListener(listener) => {
                this.borrow_mut().add_listener(listener);
            }
            Command::Connect {
                target_object,
                consumer,
                audio_caps,
                dont_reconnect,
                ret,
            } => {
                let result =
                    this.borrow_mut()
                        .connect(target_object, consumer, audio_caps, dont_reconnect);

                let _ = ret.send(result);
            }
            Command::UpdateCaps(key, audio_caps) => {
                if let Some((stream, _listener)) = this.borrow_mut().streams.get_mut(key) {
                    let params = audio_caps.into_object();
                    let params: Vec<u8> =
                        PodSerializer::serialize(Cursor::new(Vec::new()), &Value::Object(params))
                            .expect("PodSerializer into Cursor<Vec<u8>> must not fail")
                            .0
                            .into_inner();

                    let mut params = [Pod::from_bytes(&params)
                        .expect("Data is data produced by the PodSerializer")];

                    if let Err(e) = stream.set_active(false) {
                        log::error!("Failed to pause stream: {e}");
                    }

                    if let Err(e) = stream.update_params(&mut params) {
                        log::error!("Failed to update audio caps: {e}");
                    }

                    if let Err(e) = stream.set_active(true) {
                        log::error!("Failed to unpause stream: {e}");
                    }
                }
            }
            Command::RemoveStream(key) => {
                if let Some((stream, listener)) = this.borrow_mut().streams.remove(key) {
                    if let Err(e) = stream.set_active(false) {
                        log::warn!("Failed to set stream to inactive, {e}");
                    }
                    if let Err(e) = stream.disconnect() {
                        log::warn!("Failed to disconnect stream, {e}");
                    };

                    listener.unregister();
                }
            }
            Command::Destroy => {
                this.borrow_mut().main_loop.quit();
            }
        });

        main_loop.run();

        log::info!("PipeWireThread Main Loop stopped running, exiting thread");
    }

    fn add_listener(&mut self, listener: Box<dyn NodeListener>) {
        let listener = Rc::new(RefCell::new(listener));

        let mut builder = self.registry.add_listener_local();

        let l = listener.clone();
        builder = builder.global(move |obj| {
            if obj.type_ != ObjectType::Node {
                return;
            }

            let Some(props) = obj.props else { return };

            let Some(object_serial) = props.get(*OBJECT_SERIAL) else {
                return;
            };

            let media_class = match props.get(*MEDIA_CLASS) {
                Some("Stream/Output/Audio") => MediaClass::AudioStreamOutput,
                Some("Audio/Source") => MediaClass::AudioSource,
                Some("Audio/Sink") => MediaClass::AudioSink,
                _ => return,
            };

            let info = NodeInfo {
                id: obj.id,
                object_serial: object_serial.into(),
                media_class,
                node_name: props.get(*NODE_NAME).map(Into::into),
                node_nick: props.get(*NODE_NICK).map(Into::into),
                node_description: props.get(*NODE_DESCRIPTION).map(Into::into),
                app_name: props.get(*APP_NAME).map(Into::into),
            };

            l.borrow_mut().node_added(info);
        });

        builder = builder.global_remove(move |id| {
            listener.borrow_mut().node_removed(id);
        });

        self.registry_listener.push(builder.register());
    }

    fn connect(
        &mut self,
        target_object: Option<String>,
        consumer: Box<dyn AudioConsumer>,
        audio_caps: AudioCaps,
        dont_reconnect: bool,
    ) -> Result<StreamId, Error> {
        let mut stream_properties = properties! {
            *pipewire::keys::MEDIA_TYPE => "Audio",
            *pipewire::keys::MEDIA_CATEGORY => "Capture",
            *pipewire::keys::MEDIA_ROLE => "Communication",
        };

        if let Some(object_serial) = target_object {
            stream_properties.insert(*pipewire::keys::TARGET_OBJECT, object_serial);
        }

        let stream = StreamRc::new(self.core.clone(), "capture", stream_properties)?;

        let stream_id = self
            .streams
            .try_insert_with_key(|stream_id| -> Result<_, Error> {
                let listener = StreamState::new(&stream, stream_id, consumer, self.sender.clone())?;

                Ok((stream.clone(), listener))
            })?;

        let params = audio_caps.into_object();
        let params: Vec<u8> =
            PodSerializer::serialize(Cursor::new(Vec::new()), &Value::Object(params))
                .expect("PodSerializer into Cursor<Vec<u8>> must not fail")
                .0
                .into_inner();

        let mut params =
            [Pod::from_bytes(&params).expect("Data is data produced by the PodSerializer")];

        let mut flags =
            StreamFlags::MAP_BUFFERS | StreamFlags::RT_PROCESS | StreamFlags::AUTOCONNECT;

        if dont_reconnect {
            flags.insert(StreamFlags::DONT_RECONNECT);
        }

        stream.connect(Direction::Input, None, flags, &mut params)?;

        Ok(stream_id)
    }
}
