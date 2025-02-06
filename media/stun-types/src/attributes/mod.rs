use crate::builder::MessageBuilder;
use crate::parse::{AttrSpan, Message};
use crate::{Error, NE};
use byteorder::ReadBytesExt;
use bytes::BufMut;
use std::convert::TryFrom;
use std::str::from_utf8;

mod addr;
mod error_code;
mod fingerprint;
mod ice;
mod integrity;
mod password_algs;
pub mod turn;
mod user_hash;

pub use addr::*;
pub use error_code::ErrorCode;
pub use fingerprint::Fingerprint;
pub use ice::*;
pub use integrity::*;
pub use password_algs::*;
pub use user_hash::*;

pub(crate) const ATTRIBUTE_HEADER_LEN: usize = 4;

pub trait Attribute<'s> {
    type Context;
    const TYPE: u16;

    fn decode(ctx: Self::Context, msg: &'s mut Message, attr: AttrSpan) -> Result<Self, Error>
    where
        Self: Sized;

    fn encode(&self, ctx: Self::Context, builder: &mut MessageBuilder);

    fn encode_len(&self) -> Result<u16, Error>;
}

pub struct StringAttribute<'s, const TYPE: u16>(pub &'s str);

impl<'s, const TYPE: u16> StringAttribute<'s, TYPE> {
    pub fn new(s: &'s str) -> Self {
        Self(s)
    }
}

impl<'s, const TYPE: u16> Attribute<'s> for StringAttribute<'s, TYPE> {
    type Context = ();
    const TYPE: u16 = TYPE;

    fn decode(_: Self::Context, msg: &'s mut Message, attr: AttrSpan) -> Result<Self, Error> {
        Ok(Self(from_utf8(attr.get_value(msg.buffer()))?))
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) {
        builder.buffer().extend_from_slice(self.0.as_ref());
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(u16::try_from(self.0.len())?)
    }
}

pub struct BytesAttribute<'s, const TYPE: u16>(pub &'s [u8]);

impl<'s, const TYPE: u16> BytesAttribute<'s, TYPE> {
    pub fn new(s: &'s [u8]) -> Self {
        Self(s)
    }
}

impl<'s, const TYPE: u16> Attribute<'s> for BytesAttribute<'s, TYPE> {
    type Context = ();
    const TYPE: u16 = TYPE;

    fn decode(_: Self::Context, msg: &'s mut Message, attr: AttrSpan) -> Result<Self, Error> {
        Ok(Self(attr.get_value(msg.buffer())))
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) {
        builder.buffer().extend_from_slice(self.0);
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(u16::try_from(self.0.len())?)
    }
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.3)
pub type Username<'s> = StringAttribute<'s, 0x0006>;

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.9)
pub type Realm<'s> = StringAttribute<'s, 0x0014>;

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.10)
pub type Nonce<'s> = BytesAttribute<'s, 0x0015>;

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.13)
pub struct UnknownAttributes(pub Vec<u16>);

impl Attribute<'_> for UnknownAttributes {
    type Context = ();
    const TYPE: u16 = 0x000A;

    fn decode(_: Self::Context, msg: &mut Message, attr: AttrSpan) -> Result<Self, Error> {
        let mut value = attr.get_value(msg.buffer());

        let mut attributes = vec![];

        while !value.is_empty() {
            attributes.push(value.read_u16::<NE>()?);
        }

        Ok(Self(attributes))
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) {
        for &attr in &self.0 {
            builder.buffer().put_u16(attr);
        }
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(u16::try_from(self.0.len() * 2)?)
    }
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.14)
pub type Software<'s> = StringAttribute<'s, 0x8022>;

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.15)
pub type AlternateDomain<'s> = BytesAttribute<'s, 0x8003>;
