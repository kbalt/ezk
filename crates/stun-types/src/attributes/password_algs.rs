use super::Attribute;
use crate::builder::MessageBuilder;
use crate::parse::{AttrSpan, Message};
use crate::{padding_usize, Error, NE};
use byteorder::ReadBytesExt;
use bytes::BufMut;
use std::convert::TryFrom;

pub const ALGORITHM_MD5: u16 = 0x0001;
pub const ALGORITHM_SHA256: u16 = 0x0002;

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.11)
pub struct PasswordAlgorithms<'s> {
    pub algorithms: Vec<(u16, &'s [u8])>,
}

impl<'s> Attribute<'s> for PasswordAlgorithms<'s> {
    type Context = ();
    const TYPE: u16 = 0x8002;

    fn decode(_: Self::Context, msg: &'s mut Message, attr: AttrSpan) -> Result<Self, Error> {
        let mut value = attr.get_value(msg.buffer());

        let mut algorithms = vec![];

        while !value.is_empty() {
            let alg = value.read_u16::<NE>()?;
            let len = usize::from(value.read_u16::<NE>()?);

            if value.len() < len {
                return Err(Error::InvalidData("invalid algorithm len"));
            }

            let params = &value[..len];

            algorithms.push((alg, params));
        }

        Ok(Self { algorithms })
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) {
        for (alg, params) in &self.algorithms {
            let padding = padding_usize(params.len());

            builder.buffer().put_u16(*alg);
            builder.buffer().put_u16(
                u16::try_from(params.len()).expect("params must be smaller than 65535 bytes"),
            );
            builder.buffer().extend_from_slice(params);
            builder.buffer().extend((0..padding).map(|_| 0));
        }
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
    pub algorithm: u16,
    pub params: &'s [u8],
}

impl<'s> Attribute<'s> for PasswordAlgorithm<'s> {
    type Context = ();
    const TYPE: u16 = 0x001D;

    fn decode(_: Self::Context, msg: &'s mut Message, attr: AttrSpan) -> Result<Self, Error> {
        let mut value = attr.get_value(msg.buffer());

        let alg = value.read_u16::<NE>()?;
        let len = usize::from(value.read_u16::<NE>()?);

        if value.len() < len {
            return Err(Error::InvalidData("invalid algorithm len"));
        }

        let params = &value[..len];

        Ok(Self {
            algorithm: alg,
            params,
        })
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) {
        let padding = padding_usize(self.params.len());

        builder.buffer().put_u16(self.algorithm);
        builder.buffer().put_u16(
            u16::try_from(self.params.len()).expect("params must be smaller than 65535 bytes"),
        );
        builder.buffer().extend_from_slice(self.params);
        builder.buffer().extend((0..padding).map(|_| 0));
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(u16::try_from(
            4 + self.params.len() + padding_usize(self.params.len()),
        )?)
    }
}
