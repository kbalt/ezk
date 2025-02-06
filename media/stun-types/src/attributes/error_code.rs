use super::Attribute;
use crate::builder::MessageBuilder;
use crate::parse::{AttrSpan, Message};
use crate::{Error, NE};
use bitfield::bitfield;
use byteorder::ReadBytesExt;
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

    fn decode(_: Self::Context, msg: &'s mut Message, attr: AttrSpan) -> Result<Self, Error> {
        let mut value = attr.get_value(msg.buffer());

        if value.len() < 4 {
            return Err(Error::InvalidData("error code must be at least 4 bytes"));
        }

        let head = value.read_u32::<NE>().unwrap();
        let head = ErrorCodeHead(head);

        let reason = if !value.is_empty() {
            from_utf8(value)?
        } else {
            ""
        };

        Ok(Self {
            number: head.class() * 100 + head.number(),
            reason,
        })
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) {
        let class = self.number / 100;
        let number = self.number % 100;

        let mut head = ErrorCodeHead(0);

        head.set_class(class);
        head.set_number(number);

        builder.buffer().put_u32(head.0);
        builder.buffer().extend_from_slice(self.reason.as_ref());
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(u16::try_from(4 + self.reason.len())?)
    }
}

#[cfg(test)]
mod test {
    use crate::{
        builder::MessageBuilder,
        header::{Class, Method},
        parse::Message,
        TransactionId,
    };

    use super::ErrorCode;

    #[test]
    fn error_code() {
        let mut builder =
            MessageBuilder::new(Class::Error, Method::Binding, TransactionId::new([0; 12]));
        builder.add_attr(ErrorCode {
            number: 400,
            reason: "Bad Request",
        });

        let bytes = builder.finish();

        let mut parsed = Message::parse(bytes.to_vec()).unwrap();
        let err = parsed.attribute::<ErrorCode>().unwrap().unwrap();

        assert_eq!(err.number, 400);
        assert_eq!(err.reason, "Bad Request");
    }
}
