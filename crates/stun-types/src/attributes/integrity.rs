use super::Attribute;
use crate::builder::MessageBuilder;
use crate::parse::{AttrSpan, Message};
use crate::Error;
use hmac::digest::core_api::BlockSizeUser;
use hmac::digest::{Digest, Update};
use hmac::{Mac, SimpleHmac};
use sha1::Sha1;
use sha2::Sha256;
use std::borrow::Cow;
use std::convert::TryFrom;
use std::marker::PhantomData;

pub struct MessageIntegrityKey<'s>(Cow<'s, [u8]>);

impl<'s> MessageIntegrityKey<'s> {
    pub fn new_long_term_md5(username: &str, realm: &str, password: &str) -> Self {
        let key = md5::compute(format!("{}:{}:{}", username, realm, password))
            .0
            .to_vec();

        Self(Cow::Owned(key))
    }

    pub fn new_long_term_sha256(username: &str, realm: &str, password: &str) -> Self {
        let key =
            Sha256::digest(format!("{}:{}:{}", username, realm, password).as_bytes()).to_vec();

        Self(Cow::Owned(key))
    }

    pub fn new_short_term(password: &'s str) -> Self {
        Self(Cow::Borrowed(password.as_bytes()))
    }

    pub fn new_raw(raw: Cow<'s, [u8]>) -> Self {
        Self(raw)
    }
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.5)
#[derive(Default)]
pub struct MessageIntegrity<'k>(PhantomData<&'k ()>);

impl<'k> Attribute<'_> for MessageIntegrity<'k> {
    type Context = &'k MessageIntegrityKey<'k>;
    const TYPE: u16 = 0x0008;

    fn decode(ctx: Self::Context, msg: &mut Message, attr: AttrSpan) -> Result<Self, Error> {
        let hmac: SimpleHmac<Sha1> = SimpleHmac::new_from_slice(&ctx.0)
            .map_err(|_| Error::InvalidData("invalid key length"))?;

        message_integrity_decode(hmac, msg, attr)?;

        Ok(Self(PhantomData))
    }

    fn encode(&self, ctx: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        let hmac: SimpleHmac<Sha1> = SimpleHmac::new_from_slice(&ctx.0)
            .map_err(|_| Error::InvalidData("invalid key length"))?;

        message_integrity_encode(hmac, builder);

        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(u16::try_from(Sha1::output_size())?)
    }
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.6)
#[derive(Default)]
pub struct MessageIntegritySha256<'k>(PhantomData<&'k ()>);

impl<'k> Attribute<'_> for MessageIntegritySha256<'k> {
    type Context = &'k MessageIntegrityKey<'k>;
    const TYPE: u16 = 0x001C;

    fn decode(ctx: Self::Context, msg: &mut Message, attr: AttrSpan) -> Result<Self, Error> {
        let hmac: SimpleHmac<Sha256> = SimpleHmac::new_from_slice(&ctx.0)
            .map_err(|_| Error::InvalidData("invalid key length"))?;

        message_integrity_decode(hmac, msg, attr)?;

        Ok(Self(PhantomData))
    }

    fn encode(&self, ctx: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        let hmac: SimpleHmac<Sha256> = SimpleHmac::new_from_slice(&ctx.0)
            .map_err(|_| Error::InvalidData("invalid key length"))?;

        message_integrity_encode(hmac, builder);

        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(u16::try_from(Sha256::output_size())?)
    }
}

fn message_integrity_decode<D>(
    mut hmac: SimpleHmac<D>,
    msg: &mut Message,
    attr: AttrSpan,
) -> Result<(), Error>
where
    D: Digest + BlockSizeUser,
{
    msg.with_msg_len(u16::try_from(attr.padding_end - 20)?, |msg| {
        let value = attr.get_value(msg.buffer());
        let message = &msg.buffer()[..attr.begin - 4];

        Update::update(&mut hmac, message);

        let result = hmac.finalize().into_bytes();

        if result.as_slice() != value {
            return Err(Error::InvalidData("failed to verify message integrity"));
        }

        Ok(())
    })
}

fn message_integrity_encode<D>(mut hmac: SimpleHmac<D>, builder: &mut MessageBuilder)
where
    D: Digest + BlockSizeUser,
{
    let data = builder.buffer();
    let data = &data[..data.len() - 4];

    Update::update(&mut hmac, data);

    let raw = hmac.finalize().into_bytes();

    builder.buffer().extend_from_slice(&raw);
}

#[cfg(test)]
mod test {
    use super::{MessageIntegrity, MessageIntegrityKey, MessageIntegritySha256};
    use crate::attributes::Software;
    use crate::builder::MessageBuilder;
    use crate::header::{Class, Method};
    use crate::parse::Message;

    #[test]
    fn selftest_sha1() {
        let password = "abc123";

        let mut message = MessageBuilder::new(Class::Request, Method::Binding, 123);

        message.add_attr(&Software::new("ezk-stun")).unwrap();
        message
            .add_attr_with(
                &MessageIntegrity::default(),
                &MessageIntegrityKey::new_short_term(password),
            )
            .unwrap();
        let bytes = message.finish();
        let bytes = Vec::from(&bytes[..]);

        let mut msg = Message::parse(bytes).unwrap();

        msg.attribute_with::<MessageIntegrity>(&MessageIntegrityKey::new_short_term(password))
            .unwrap()
            .unwrap();
    }

    #[test]
    fn selftest_sha256() {
        let password = "abc123";

        let mut message = MessageBuilder::new(Class::Request, Method::Binding, 123);

        message.add_attr(&Software::new("ezk-stun")).unwrap();
        message
            .add_attr_with(
                &MessageIntegritySha256::default(),
                &MessageIntegrityKey::new_short_term(password),
            )
            .unwrap();
        let bytes = message.finish();
        let bytes = Vec::from(&bytes[..]);

        let mut msg = Message::parse(bytes).unwrap();

        msg.attribute_with::<MessageIntegritySha256>(&MessageIntegrityKey::new_short_term(
            password,
        ))
        .unwrap()
        .unwrap();
    }
}
