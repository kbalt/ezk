use super::Attribute;
use crate::{
    builder::MessageBuilder,
    parse::{ParsedAttr, ParsedMessage},
    Error, NE,
};
use byteorder::ReadBytesExt;
use bytes::BufMut;

pub struct Priority(pub u32);

impl Attribute<'_> for Priority {
    type Context = ();
    const TYPE: u16 = 0x0024;

    fn decode(_: Self::Context, msg: &mut ParsedMessage, attr: ParsedAttr) -> Result<Self, Error> {
        let mut value = attr.get_value(msg.buffer());

        if value.len() != 4 {
            return Err(Error::InvalidData("priority value must be 4 bytes"));
        }

        Ok(Self(value.read_u32::<NE>()?))
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        let data = builder.buffer();

        data.put_u32(self.0);

        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(4)
    }
}

pub struct UseCandidate;

impl Attribute<'_> for UseCandidate {
    type Context = ();
    const TYPE: u16 = 0x0025;

    fn decode(
        _: Self::Context,
        _msg: &mut ParsedMessage,
        _attr: ParsedAttr,
    ) -> Result<Self, Error> {
        Ok(Self)
    }

    fn encode(&self, _: Self::Context, _builder: &mut MessageBuilder) -> Result<(), Error> {
        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(0)
    }
}

pub struct IceControlled(pub u64);

impl Attribute<'_> for IceControlled {
    type Context = ();
    const TYPE: u16 = 0x8029;

    fn decode(_: Self::Context, msg: &mut ParsedMessage, attr: ParsedAttr) -> Result<Self, Error> {
        let mut value = attr.get_value(msg.buffer());

        if value.len() != 8 {
            return Err(Error::InvalidData("ice-controlled value must be 8 bytes"));
        }

        Ok(Self(value.read_u64::<NE>()?))
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        let data = builder.buffer();

        data.put_u64(self.0);

        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(8)
    }
}

pub struct IceControlling(pub u64);

impl Attribute<'_> for IceControlling {
    type Context = ();
    const TYPE: u16 = 0x802A;

    fn decode(_: Self::Context, msg: &mut ParsedMessage, attr: ParsedAttr) -> Result<Self, Error> {
        let mut value = attr.get_value(msg.buffer());

        if value.len() != 8 {
            return Err(Error::InvalidData("ice-controlling value must be 8 bytes"));
        }

        Ok(Self(value.read_u64::<NE>()?))
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        let data = builder.buffer();

        data.put_u64(self.0);

        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(8)
    }
}
