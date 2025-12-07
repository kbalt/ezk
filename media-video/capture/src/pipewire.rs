use pipewire::{
    context::ContextRc,
    core::CoreRc,
    keys::{APP_NAME, MEDIA_CLASS, NODE_DESCRIPTION, NODE_NAME, NODE_NICK},
    main_loop::MainLoopRc,
    properties::properties,
    registry::{self, RegistryRc},
    spa::{
        param::{
            ParamType,
            audio::{AudioFormat, AudioInfoRaw},
            format::{MediaSubtype, MediaType},
        },
        pod::{Object, Pod, Value, serialize::PodSerializer},
        utils::{Direction, SpaTypes},
    },
    stream::{self, Stream, StreamFlags, StreamRc},
    types::ObjectType,
};
use std::{cell::RefCell, io::Cursor, rc::Rc, thread};

#[derive(Debug, thiserror::Error)]
#[error("Pipewire thread is unexpectedly gone")]
pub struct PipeWireThreadGone;

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

pub trait NodeListener: Send + 'static {
    fn node_added(&mut self, info: NodeInfo);
    fn node_removed(&mut self, id: u32);
}

pub trait AudioConsumer: Send + 'static {
    fn set_format(&mut self, sample_rate: u32, channels: u32, format: AudioFormat);
    fn on_frame(&mut self, data: &[u8]) -> bool;
}

pub struct PipeWireAudioCapture {
    sender: pipewire::channel::Sender<Command>,
}

impl PipeWireAudioCapture {
    pub fn spawn() -> PipeWireAudioCapture {
        let (sender, receiver) = pipewire::channel::channel();

        thread::spawn(move || PipewireThread::run(receiver));

        PipeWireAudioCapture { sender }
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

impl Drop for PipeWireAudioCapture {
    fn drop(&mut self) {
        let _ = self.sender.send(Command::Destroy);
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
    Destroy,
}

struct PipewireThread {
    main_loop: MainLoopRc,
    context: ContextRc,
    core: CoreRc,
    registry: RegistryRc,

    registry_listener: Vec<registry::Listener>,
    stream_listener: Vec<stream::StreamListener<UserStreamState>>,
}

impl PipewireThread {
    fn run(receiver: pipewire::channel::Receiver<Command>) {
        let main_loop = MainLoopRc::new(None).unwrap();
        let context = ContextRc::new(&main_loop, None).unwrap();
        let core = context.connect_rc(None).unwrap();
        let registry = core.get_registry_rc().unwrap();

        let this = RefCell::new(PipewireThread {
            main_loop: main_loop.clone(),
            context,
            core,
            registry,
            registry_listener: Vec::new(),
            stream_listener: Vec::new(),
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
                this.borrow_mut()
                    .connect(node_id, consumer, sample_rate, channels, format);
            }
            Command::Destroy => {
                this.borrow_mut().main_loop.quit();
            }
        });

        main_loop.run();
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
    ) {
        let stream = StreamRc::new(
            self.core.clone(),
            "capture",
            properties! {
                *pipewire::keys::MEDIA_TYPE => "Audio",
                *pipewire::keys::MEDIA_CATEGORY => "Capture",
                *pipewire::keys::MEDIA_ROLE => "Communication",
            },
        )
        .unwrap();

        let user_data = UserStreamState {
            format: AudioInfoRaw::new(),
            stream: stream.clone(),
            consumer,
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
            .register()
            .unwrap();

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
                .unwrap()
                .0
                .into_inner();

        let mut params = [Pod::from_bytes(&values).unwrap()];

        stream
            .connect(
                Direction::Input,
                Some(node_id),
                StreamFlags::AUTOCONNECT | StreamFlags::MAP_BUFFERS | StreamFlags::RT_PROCESS,
                &mut params,
            )
            .unwrap();

        self.stream_listener.push(listener);
    }
}

struct UserStreamState {
    format: AudioInfoRaw,
    stream: StreamRc,

    consumer: Box<dyn AudioConsumer>,
}

impl UserStreamState {
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

            if let Some(data) = data.data() {
                self.consumer.on_frame(data);
            }
        }
    }
}

#[test]
fn capture() {
    use std::time::Duration;

    let mut c = PipeWireAudioCapture::spawn();

    struct L {}

    impl NodeListener for L {
        fn node_added(&mut self, info: NodeInfo) {
            println!("Info: {info:#?}");
        }

        fn node_removed(&mut self, id: u32) {}
    }

    struct C {}

    impl AudioConsumer for C {
        fn set_format(&mut self, sample_rate: u32, channels: u32, format: AudioFormat) {
            println!(
                "Set format sample_rate: {sample_rate}, channels: {channels}, format: {format:?}"
            );
        }

        fn on_frame(&mut self, data: &[u8]) -> bool {
            println!("GOt data: {}", data.len());
            true
        }
    }

    c.add_listener(L {}).unwrap();
    c.connect(135, C {}, 44100, 1, AudioFormat::S8).unwrap();

    thread::sleep(Duration::from_hours(100));
}
