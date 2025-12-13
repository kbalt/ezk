use pipewire::spa::{
    param::{ParamType, audio::AudioFormat},
    pod::{ChoiceValue, Object, Property, Value},
    sys,
    utils::{self, Choice, ChoiceEnum, ChoiceFlags, Id, SpaTypes},
};
use std::ops::RangeBounds;

#[derive(Debug, Default)]
pub struct AudioCaps {
    pub(super) format: Option<Property>,
    pub(super) rate: Option<Property>,
    pub(super) channels: Option<Property>,
}

unsafe impl Send for AudioCaps {}

impl AudioCaps {
    pub fn new() -> AudioCaps {
        AudioCaps::default()
    }

    pub fn format(mut self, format: AudioFormat) -> Self {
        self.format = Some(Property::new(
            sys::SPA_FORMAT_AUDIO_format,
            Value::Id(utils::Id(format.as_raw())),
        ));
        self
    }

    pub fn format_choice(mut self, formats: impl IntoIterator<Item = AudioFormat>) -> Self {
        let mut formats = formats.into_iter();

        self.format = Some(Property::new(
            sys::SPA_FORMAT_AUDIO_format,
            Value::Choice(ChoiceValue::Id(Choice(
                ChoiceFlags::empty(),
                ChoiceEnum::Enum {
                    default: Id(formats
                        .next()
                        .expect("must not pass empty iterator")
                        .as_raw()),
                    alternatives: formats.map(|f| Id(f.as_raw())).collect(),
                },
            ))),
        ));

        self
    }

    pub fn rate(mut self, rate: u32) -> Self {
        self.rate = Some(Property::new(
            sys::SPA_FORMAT_AUDIO_rate,
            Value::Int(rate as i32),
        ));

        self
    }

    pub fn rate_choice(mut self, rates: impl IntoIterator<Item = u32>) -> Self {
        let mut rates = rates.into_iter();

        self.rate = Some(Property::new(
            sys::SPA_FORMAT_AUDIO_rate,
            Value::Choice(ChoiceValue::Int(Choice(
                ChoiceFlags::empty(),
                ChoiceEnum::Enum {
                    default: rates.next().expect("must not pass empty iterator") as i32,
                    alternatives: rates.map(|rate| rate as i32).collect(),
                },
            ))),
        ));

        self
    }

    pub fn channels(mut self, channels: u32) -> Self {
        self.channels = Some(Property::new(
            sys::SPA_FORMAT_AUDIO_channels,
            Value::Int(channels as i32),
        ));

        self
    }

    pub fn channels_choice(mut self, channels: impl IntoIterator<Item = u32>) -> Self {
        let mut channels = channels.into_iter();

        self.channels = Some(Property::new(
            sys::SPA_FORMAT_AUDIO_channels,
            Value::Choice(ChoiceValue::Int(Choice(
                ChoiceFlags::empty(),
                ChoiceEnum::Enum {
                    default: channels.next().expect("must not pass empty iterator") as i32,
                    alternatives: channels.map(|channels| channels as i32).collect(),
                },
            ))),
        ));

        self
    }

    pub fn channels_range(mut self, range: impl RangeBounds<u32>) -> Self {
        let start = match range.start_bound() {
            std::ops::Bound::Included(v) => *v,
            std::ops::Bound::Excluded(v) => v.saturating_sub(1),
            std::ops::Bound::Unbounded => 1,
        }
        .max(1);

        let end = match range.end_bound() {
            std::ops::Bound::Included(v) => *v,
            std::ops::Bound::Excluded(v) => v.saturating_sub(1),
            std::ops::Bound::Unbounded => 1,
        }
        .max(start);

        self.channels = Some(Property::new(
            sys::SPA_FORMAT_AUDIO_channels,
            Value::Choice(ChoiceValue::Int(Choice(
                ChoiceFlags::empty(),
                ChoiceEnum::Range {
                    default: 0,
                    min: start as i32,
                    max: end as i32,
                },
            ))),
        ));

        self
    }

    pub(super) fn into_object(self) -> Object {
        let Self {
            format,
            rate,
            channels,
        } = self;

        let mut properties = vec![];

        properties.push(Property::new(
            sys::SPA_FORMAT_mediaType,
            Value::Id(utils::Id(sys::SPA_MEDIA_TYPE_audio)),
        ));
        properties.push(Property::new(
            sys::SPA_FORMAT_mediaSubtype,
            Value::Id(utils::Id(sys::SPA_MEDIA_SUBTYPE_raw)),
        ));

        if let Some(format) = format {
            properties.push(format);
        }

        if let Some(rate) = rate {
            properties.push(rate);
        }

        if let Some(channels) = channels {
            properties.push(channels);
        }

        Object {
            type_: SpaTypes::ObjectParamFormat.as_raw(),
            id: ParamType::EnumFormat.as_raw(),
            properties,
        }
    }
}
