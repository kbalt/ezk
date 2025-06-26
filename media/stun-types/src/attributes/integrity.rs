use super::{ATTRIBUTE_HEADER_LEN, Attribute};
use crate::Error;
use crate::builder::MessageBuilder;
use crate::header::STUN_HEADER_LENGTH;
use crate::parse::{AttrSpan, Message};
use hmac::digest::core_api::BlockSizeUser;
use hmac::digest::{Digest, Update};
use hmac::{Mac, SimpleHmac};
use sha1::Sha1;
use sha2::Sha256;
use std::convert::TryFrom;

pub fn long_term_password_md5(username: &str, realm: &str, password: &str) -> Vec<u8> {
    md5::compute(format!("{username}:{realm}:{password}").as_bytes()).to_vec()
}

pub fn long_term_password_sha256(username: &str, realm: &str, password: &str) -> Vec<u8> {
    Sha256::digest(format!("{username}:{realm}:{password}").as_bytes()).to_vec()
}

pub struct MessageIntegrityKey(SimpleHmac<Sha1>);

impl MessageIntegrityKey {
    pub fn new(key: impl AsRef<[u8]>) -> Self {
        Self(SimpleHmac::new_from_slice(key.as_ref()).expect("any key length is valid"))
    }
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.5)
pub struct MessageIntegrity;

impl Attribute<'_> for MessageIntegrity {
    type Context = MessageIntegrityKey;
    const TYPE: u16 = 0x0008;

    fn decode(ctx: Self::Context, msg: &mut Message, attr: AttrSpan) -> Result<Self, Error> {
        message_integrity_decode(ctx.0, msg, attr)?;

        Ok(Self)
    }

    fn encode(&self, ctx: Self::Context, builder: &mut MessageBuilder) {
        message_integrity_encode(ctx.0, builder)
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(u16::try_from(Sha1::output_size())?)
    }
}

pub struct MessageIntegritySha256Key(SimpleHmac<Sha256>);

impl MessageIntegritySha256Key {
    pub fn new(key: impl AsRef<[u8]>) -> Self {
        Self(SimpleHmac::new_from_slice(key.as_ref()).expect("any key length is valid"))
    }
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.6)
pub struct MessageIntegritySha256;

impl Attribute<'_> for MessageIntegritySha256 {
    type Context = MessageIntegritySha256Key;
    const TYPE: u16 = 0x001C;

    fn decode(ctx: Self::Context, msg: &mut Message, attr: AttrSpan) -> Result<Self, Error> {
        message_integrity_decode(ctx.0, msg, attr)?;

        Ok(Self)
    }

    fn encode(&self, ctx: Self::Context, builder: &mut MessageBuilder) {
        message_integrity_encode(ctx.0, builder)
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
    // The text used as input to HMAC is the STUN message, up to and
    // including the attribute preceding the MESSAGE-INTEGRITY attribute.
    // The Length field of the STUN message header is adjusted to point to
    // the end of the MESSAGE-INTEGRITY attribute.

    // The length of the message is temporarily set to the end of the previous attribute
    msg.with_msg_len(
        u16::try_from(attr.padding_end - STUN_HEADER_LENGTH)?,
        |msg| {
            // Get the digest from the received attribute
            let received_digest = attr.get_value(msg.buffer());

            // Get all bytes before the integrity attribute to calculate the hmac over
            let message = &msg.buffer()[..attr.begin - ATTRIBUTE_HEADER_LEN];

            // Calculate the expected digest,
            Update::update(&mut hmac, message);
            let calculated_digest = hmac.finalize().into_bytes();

            // Compare the received and calculated digest
            if calculated_digest.as_slice() != received_digest {
                return Err(Error::InvalidData("failed to verify message integrity"));
            }

            Ok(())
        },
    )
}

fn message_integrity_encode<D>(mut hmac: SimpleHmac<D>, builder: &mut MessageBuilder)
where
    D: Digest + BlockSizeUser,
{
    // 4 bytes containing type and length is already written into the buffer
    let message_length_with_integrity_attribute =
        (builder.buffer().len() + <D as Digest>::output_size()) - STUN_HEADER_LENGTH;

    builder.set_len(
        message_length_with_integrity_attribute
            .try_into()
            .expect("stun messages must fit withing 65535 bytes"),
    );

    // Calculate the digest of the message up until the previous attribute
    let data = builder.buffer();
    let data = &data[..data.len() - ATTRIBUTE_HEADER_LEN];
    Update::update(&mut hmac, data);
    let digest = hmac.finalize().into_bytes();

    builder.buffer().extend_from_slice(&digest);
}

#[cfg(test)]
mod test {
    use super::{
        MessageIntegrity, MessageIntegrityKey, MessageIntegritySha256, MessageIntegritySha256Key,
    };
    use crate::TransactionId;
    use crate::attributes::Software;
    use crate::builder::MessageBuilder;
    use crate::header::{Class, Method};
    use crate::parse::Message;

    #[test]
    fn selftest_sha1() {
        let password = "abc123";

        let mut message =
            MessageBuilder::new(Class::Request, Method::Binding, TransactionId::new([0; 12]));

        message.add_attr(Software::new("ezk-stun"));
        message.add_attr_with(MessageIntegrity, MessageIntegrityKey::new(password));

        let bytes = message.finish();
        let bytes = Vec::from(&bytes[..]);

        let mut msg = Message::parse(bytes).unwrap();

        msg.attribute_with::<MessageIntegrity>(MessageIntegrityKey::new(password))
            .unwrap()
            .unwrap();
    }

    #[test]
    fn selftest_sha256() {
        let password = "abc123";

        let mut message =
            MessageBuilder::new(Class::Request, Method::Binding, TransactionId::new([0; 12]));

        message.add_attr(Software::new("ezk-stun"));
        message.add_attr_with(
            MessageIntegritySha256,
            MessageIntegritySha256Key::new(password),
        );

        let bytes = message.finish();
        let bytes = Vec::from(&bytes[..]);

        let mut msg = Message::parse(bytes).unwrap();

        msg.attribute_with::<MessageIntegritySha256>(MessageIntegritySha256Key::new(password))
            .unwrap()
            .unwrap();
    }
}
