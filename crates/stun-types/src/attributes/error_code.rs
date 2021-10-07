use super::Attribute;
use crate::builder::MessageBuilder;
use crate::parse::{ParsedAttr, ParsedMessage};
use crate::Error;
use bitfield::bitfield;
use bytes::BufMut;
use std::convert::TryFrom;
use std::str::from_utf8;

bitfield! {
    struct ErrorCodeHead(u32);
    number, set_number: 7, 0;
    class, set_class: 11, 8;
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.8)
pub struct ErrorCode<'s> {
    pub number: u32,
    pub reason: &'s str,
}

impl<'s> Attribute<'s> for ErrorCode<'s> {
    type Context = ();
    const TYPE: u16 = 0x0009;

    fn decode(
        _: Self::Context,
        msg: &'s mut ParsedMessage,
        attr: ParsedAttr,
    ) -> Result<Self, Error> {
        let value = attr.get_value(msg.buffer());

        if value.len() < 4 {
            return Err(Error::InvalidData("error code must be at least 4 bytes"));
        }

        let head = u32::from_ne_bytes([value[0], value[1], value[2], value[3]]);
        let head = ErrorCodeHead(head);

        let reason = if value.len() > 4 {
            from_utf8(&value[4..])?
        } else {
            ""
        };

        Ok(Self {
            number: head.class() * 100 + head.number(),
            reason,
        })
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        let class = self.number / 100;
        let number = self.number % 100;

        let mut head = ErrorCodeHead(0);

        head.set_class(class);
        head.set_number(number);

        builder.buffer().put_u32(head.0);
        builder.buffer().extend_from_slice(self.reason.as_ref());

        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(u16::try_from(4 + self.reason.len())?)
    }
}
