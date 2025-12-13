use crate::pipewire::{AudioConsumer, Command, StreamId};
use pipewire::{
    Error, channel,
    spa::{
        param::{
            ParamType,
            audio::AudioInfoRaw,
            format::{MediaSubtype, MediaType},
        },
        pod::Pod,
    },
    stream::{Stream, StreamListener},
};

pub(super) struct StreamState {
    id: StreamId,
    format: AudioInfoRaw,
    consumer: Box<dyn AudioConsumer>,
    sender: channel::Sender<Command>,
}

impl StreamState {
    pub(super) fn new(
        stream: &Stream,
        key: StreamId,
        consumer: Box<dyn AudioConsumer>,
        sender: channel::Sender<Command>,
    ) -> Result<StreamListener<Self>, Error> {
        let user_data = StreamState {
            id: key,
            format: AudioInfoRaw::new(),
            consumer,
            sender,
        };

        let listener = stream
            .add_local_listener_with_user_data(user_data)
            .state_changed(|_stream, _user_data, old, new| {
                log::debug!("StreamState Changed: {:?} {old:?}, {new:?}", _user_data.id);
            })
            .param_changed(|stream, user_data, id, param| {
                user_data.handle_param_changed(stream, id, param);
            })
            .process(|stream, user_data| {
                user_data.handle_process(stream);
            })
            .register()?;

        Ok(listener)
    }

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
                let _ = self.sender.send(Command::RemoveStream(self.id));
                break;
            }
        }
    }
}
