use super::Attribute;
use crate::builder::MessageBuilder;
use crate::parse::{ParsedAttr, ParsedMessage};
use crate::{padding_usize, Error, NE};
use byteorder::ReadBytesExt;
use bytes::{Buf, BufMut};
use std::convert::TryFrom;
use std::io::Cursor;

pub const ALGORITHM_MD5: u16 = 0x0001;
pub const ALGORITHM_SHA256: u16 = 0x0002;

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.11)
pub struct PasswordAlgorithms<'s> {
    algorithms: Vec<(u16, &'s [u8])>,
}

impl<'s> Attribute<'s> for PasswordAlgorithms<'s> {
    type Context = ();
    const TYPE: u16 = 0x8002;

    fn decode(
        _: Self::Context,
        msg: &'s mut ParsedMessage,
        attr: ParsedAttr,
    ) -> Result<Self, Error> {
        let value = attr.get_value(msg.buffer());

        let mut cursor = Cursor::new(value);

        let mut algorithms = vec![];

        while cursor.has_remaining() {
            let alg = cursor.read_u16::<NE>()?;
            let len = usize::from(cursor.read_u16::<NE>()?);

            let pos = usize::try_from(cursor.position())?;

            if value.len() < pos + len {
                return Err(Error::InvalidData("invalid algorithm len"));
            }

            let params = &value[pos..pos + len];

            algorithms.push((alg, params));
        }

        Ok(Self { algorithms })
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        for (alg, params) in &self.algorithms {
            let padding = padding_usize(params.len());

            builder.buffer().put_u16(*alg);
            builder.buffer().put_u16(u16::try_from(params.len())?);
            builder.buffer().extend_from_slice(params);
            builder.buffer().extend((0..padding).map(|_| 0));
        }

        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        let mut len = 0;

        for (_, params) in &self.algorithms {
            len += 4;
            len += params.len();
            len += padding_usize(params.len());
        }

        Ok(u16::try_from(len)?)
    }
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.12)
pub struct PasswordAlgorithm<'s> {
    algorithm: u16,
    params: &'s [u8],
}

impl<'s> Attribute<'s> for PasswordAlgorithm<'s> {
    type Context = ();
    const TYPE: u16 = 0x001D;

    fn decode(
        _: Self::Context,
        msg: &'s mut ParsedMessage,
        attr: ParsedAttr,
    ) -> Result<Self, Error> {
        let value = attr.get_value(msg.buffer());

        let mut cursor = Cursor::new(value);

        let alg = cursor.read_u16::<NE>()?;
        let len = usize::from(cursor.read_u16::<NE>()?);

        let pos = usize::try_from(cursor.position())?;

        if value.len() < pos + len {
            return Err(Error::InvalidData("invalid algorithm len"));
        }

        let params = &value[pos..pos + len];

        Ok(Self {
            algorithm: alg,
            params,
        })
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        let padding = padding_usize(self.params.len());

        builder.buffer().put_u16(self.algorithm);
        builder.buffer().put_u16(u16::try_from(self.params.len())?);
        builder.buffer().extend_from_slice(self.params);
        builder.buffer().extend((0..padding).map(|_| 0));

        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(u16::try_from(
            4 + self.params.len() + padding_usize(self.params.len()),
        )?)
    }
}
