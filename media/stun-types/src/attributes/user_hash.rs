use super::Attribute;
use crate::Error;
use crate::builder::MessageBuilder;
use crate::parse::{AttrSpan, Message};
use sha1::Digest;
use sha2::Sha256;
use std::convert::TryFrom;

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.4)
pub struct UserHash(pub [u8; 32]);

impl UserHash {
    pub fn new(username: &str, realm: &str) -> Self {
        let input = format!("{username}:{realm}");
        let output = Sha256::digest(input.as_bytes());

        Self(output.into())
    }
}

impl Attribute<'_> for UserHash {
    type Context = ();
    const TYPE: u16 = 0x001E;

    fn decode(_: Self::Context, msg: &mut Message, attr: AttrSpan) -> Result<Self, Error> {
        let value = attr.get_value(msg.buffer());

        if value.len() != 32 {
            return Err(Error::InvalidData("user hash buf must be 32 bytes"));
        }

        Ok(Self(<[u8; 32]>::try_from(value).unwrap()))
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) {
        builder.buffer().extend_from_slice(&self.0);
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(32)
    }
}
