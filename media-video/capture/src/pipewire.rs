use pipewire::{
    Error, channel,
    context::ContextRc,
    core::CoreRc,
    keys::{APP_NAME, MEDIA_CLASS, NODE_DESCRIPTION, NODE_NAME, NODE_NICK},
    main_loop::MainLoopRc,
    properties::properties,
    registry::{self, RegistryRc},
    spa::{
        param::{
            ParamType,
            audio::AudioInfoRaw,
            format::{MediaSubtype, MediaType},
        },
        pod::{Object, Pod, Value, serialize::PodSerializer},
        utils::{Direction, SpaTypes},
    },
    stream::{Stream, StreamFlags, StreamListener, StreamRc},
    types::ObjectType,
};
use slotmap::{DefaultKey, SlotMap};
use std::{cell::RefCell, io::Cursor, rc::Rc, thread};

pub use pipewire::spa::param::audio::AudioFormat;

pub trait NodeListener: Send + 'static {
    fn node_added(&mut self, info: NodeInfo);
    fn node_removed(&mut self, id: u32);
}

#[derive(Debug)]
pub struct NodeInfo {
    pub id: u32,
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

pub struct PipeWireAudioCapture {
    sender: channel::Sender<Command>,
}

impl Drop for PipeWireAudioCapture {
    fn drop(&mut self) {
        let _ = self.sender.send(Command::Destroy);
    }
}

#[derive(Debug, thiserror::Error)]
#[error("Pipewire thread is unexpectedly gone")]
pub struct PipeWireThreadGone;

impl PipeWireAudioCapture {
    pub fn spawn() -> PipeWireAudioCapture {
        let (sender, receiver) = channel::channel();

        let handle = PipeWireAudioCapture {
            sender: sender.clone(),
        };

        thread::spawn(move || PipeWireThread::run(sender, receiver));

        handle
    }

    pub fn add_listener(&self, listener: impl NodeListener) -> Result<(), PipeWireThreadGone> {
        self.sender
            .send(Command::AddListener(Box::new(listener)))
            .map_err(|_| PipeWireThreadGone)
    }

    pub fn connect(
        &self,
        node_id: u32,
        consumer: impl AudioConsumer,
        sample_rate: u32,
        channels: u32,
        format: AudioFormat,
    ) -> Result<(), PipeWireThreadGone> {
        self.sender
            .send(Command::Connect {
                node_id,
                consumer: Box::new(consumer),
                sample_rate,
                channels,
                format,
            })
            .map_err(|_| PipeWireThreadGone)
    }
}

enum Command {
    AddListener(Box<dyn NodeListener>),
    Connect {
        node_id: u32,
        consumer: Box<dyn AudioConsumer>,
        sample_rate: u32,
        channels: u32,
        format: AudioFormat,
    },
    RemoveStream(DefaultKey),

    Destroy,
}

struct PipeWireThread {
    main_loop: MainLoopRc,
    core: CoreRc,
    registry: RegistryRc,

    sender: channel::Sender<Command>,

    registry_listener: Vec<registry::Listener>,
    streams: SlotMap<DefaultKey, (StreamRc, StreamListener<StreamState>)>,
}

impl PipeWireThread {
    fn run(
        sender: channel::Sender<Command>,
        receiver: channel::Receiver<Command>,
    ) -> Result<(), Error> {
        let main_loop = MainLoopRc::new(None)?;
        let context = ContextRc::new(&main_loop, None)?;
        let core = context.connect_rc(None)?;
        let registry = core.get_registry_rc()?;

        let this = RefCell::new(PipeWireThread {
            main_loop: main_loop.clone(),
            core,
            registry,
            registry_listener: Vec::new(),
            streams: SlotMap::new(),
            sender,
        });

        let _attached = receiver.attach(main_loop.loop_(), move |command| match command {
            Command::AddListener(listener) => {
                this.borrow_mut().add_listener(listener);
            }
            Command::Connect {
                node_id,
                consumer,
                sample_rate,
                channels,
                format,
            } => {
                if let Err(e) =
                    this.borrow_mut()
                        .connect(node_id, consumer, sample_rate, channels, format)
                {
                    log::error!("Failed to connect to node_id: {node_id}, {e}");
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

        Ok(())
    }

    fn add_listener(&mut self, listener: Box<dyn NodeListener>) {
        let listener = Rc::new(RefCell::new(listener));

        let mut builder = self.registry.add_listener_local();

        let l = listener.clone();
        builder = builder.global(move |o| {
            if o.type_ != ObjectType::Node {
                return;
            }

            let Some(props) = o.props else { return };

            let media_class = match props.get(*MEDIA_CLASS) {
                Some("Stream/Output/Audio") => MediaClass::AudioStreamOutput,
                Some("Audio/Source") => MediaClass::AudioSource,
                Some("Audio/Sink") => MediaClass::AudioSink,
                _ => return,
            };

            let info = NodeInfo {
                id: o.id,
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
        node_id: u32,
        consumer: Box<dyn AudioConsumer>,
        sample_rate: u32,
        channels: u32,
        format: AudioFormat,
    ) -> Result<(), Error> {
        let stream = StreamRc::new(
            self.core.clone(),
            "capture",
            properties! {
                *pipewire::keys::MEDIA_TYPE => "Audio",
                *pipewire::keys::MEDIA_CATEGORY => "Capture",
                *pipewire::keys::MEDIA_ROLE => "Communication",
            },
        )?;

        self.streams
            .try_insert_with_key(|key| -> Result<_, Error> {
                let user_data = StreamState {
                    key,
                    format: AudioInfoRaw::new(),
                    consumer,
                    sender: self.sender.clone(),
                };

                let listener = stream
                    .add_local_listener_with_user_data(user_data)
                    .state_changed(|_stream, _user_data, old, new| {
                        println!("State Changed: {old:?}, {new:?}");
                    })
                    .param_changed(|stream, user_data, id, param| {
                        user_data.handle_param_changed(stream, id, param);
                    })
                    .process(|stream, user_data| {
                        user_data.handle_process(stream);
                    })
                    .register()?;

                Ok((stream.clone(), listener))
            })?;

        let mut audio_info = AudioInfoRaw::new();
        audio_info.set_format(format);
        audio_info.set_channels(channels);
        audio_info.set_rate(sample_rate);

        let obj = Object {
            type_: SpaTypes::ObjectParamFormat.as_raw(),
            id: ParamType::EnumFormat.as_raw(),
            properties: audio_info.into(),
        };
        let values: Vec<u8> =
            PodSerializer::serialize(Cursor::new(Vec::new()), &Value::Object(obj))
                .expect("PodSerializer into Cursor<Vec<u8>> must not fail")
                .0
                .into_inner();

        let mut params =
            [Pod::from_bytes(&values).expect("Data is data produced by the PodSerializer")];

        stream.connect(
            Direction::Input,
            Some(node_id),
            StreamFlags::MAP_BUFFERS
                | StreamFlags::RT_PROCESS
                | StreamFlags::AUTOCONNECT
                | StreamFlags::DONT_RECONNECT,
            &mut params,
        )?;

        Ok(())
    }
}

struct StreamState {
    key: DefaultKey,
    format: AudioInfoRaw,
    consumer: Box<dyn AudioConsumer>,
    sender: channel::Sender<Command>,
}

impl StreamState {
    fn handle_param_changed(&mut self, _stream: &Stream, id: u32, param: Option<&Pod>) {
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

        if media_type != MediaType::Audio || media_subtype != MediaSubtype::Raw {
            return;
        }

        self.format
            .parse(param)
            .expect("Failed to parse param changed to AudioInfoRaw");

        self.consumer.set_format(
            self.format.rate(),
            self.format.channels(),
            self.format.format(),
        );
    }

    fn handle_process(&mut self, stream: &Stream) {
        while let Some(mut buffer) = stream.dequeue_buffer() {
            let data = &mut buffer.datas_mut()[0];

            let offset = data.chunk().offset() as usize;
            let size = data.chunk().size() as usize;

            let Some(data) = data.data() else {
                continue;
            };

            let run = self.consumer.on_frame(&data[offset..(offset + size)]);

            if !run {
                let _ = self.sender.send(Command::RemoveStream(self.key));
                break;
            }
        }
    }
}
