use super::{Attribute, BytesAttribute, XorMappedAddress};
use crate::builder::MessageBuilder;
use crate::parse::{ParsedAttr, ParsedMessage};
use crate::{Error, NE};
use byteorder::ReadBytesExt;
use bytes::BufMut;
use std::convert::TryInto;
use std::net::SocketAddr;

/// [RFC5766](https://datatracker.ietf.org/doc/html/rfc5766#section-14.1)
pub struct ChannelNumber(pub u16);

impl Attribute<'_> for ChannelNumber {
    type Context = ();
    const TYPE: u16 = 0x000C;

    fn decode(_: Self::Context, msg: &mut ParsedMessage, attr: ParsedAttr) -> Result<Self, Error> {
        Ok(Self(attr.get_value(msg.buffer()).read_u16::<NE>()?))
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        builder.buffer().put_u16(self.0);
        builder.buffer().put_u16(0);

        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(4)
    }
}

/// [RFC5766](https://datatracker.ietf.org/doc/html/rfc5766#section-14.2)
pub struct Lifetime(pub u32);

impl Attribute<'_> for Lifetime {
    type Context = ();
    const TYPE: u16 = 0x000D;

    fn decode(_: Self::Context, msg: &mut ParsedMessage, attr: ParsedAttr) -> Result<Self, Error> {
        Ok(Self(attr.get_value(msg.buffer()).read_u32::<NE>()?))
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        builder.buffer().put_u32(self.0);

        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(4)
    }
}

/// [RFC5766](https://datatracker.ietf.org/doc/html/rfc5766#section-14.3)
pub struct XorPeerAddress(pub SocketAddr);

impl Attribute<'_> for XorPeerAddress {
    type Context = ();
    const TYPE: u16 = 0x0012;

    fn decode(
        ctx: Self::Context,
        msg: &mut ParsedMessage,
        attr: ParsedAttr,
    ) -> Result<Self, Error> {
        XorMappedAddress::decode(ctx, msg, attr).map(|xma| Self(xma.0))
    }

    fn encode(&self, ctx: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        XorMappedAddress(self.0).encode(ctx, builder)
    }

    fn encode_len(&self) -> Result<u16, Error> {
        XorMappedAddress(self.0).encode_len()
    }
}

/// [RFC5766](https://datatracker.ietf.org/doc/html/rfc5766#section-14.4)
pub type Data<'s> = BytesAttribute<'s, 0x0013>;

/// [RFC5766](https://datatracker.ietf.org/doc/html/rfc5766#section-14.5)
pub struct XorRelayedAddress(pub SocketAddr);

impl Attribute<'_> for XorRelayedAddress {
    type Context = ();
    const TYPE: u16 = 0x0016;

    fn decode(
        ctx: Self::Context,
        msg: &mut ParsedMessage,
        attr: ParsedAttr,
    ) -> Result<Self, Error> {
        XorMappedAddress::decode(ctx, msg, attr).map(|xma| Self(xma.0))
    }

    fn encode(&self, ctx: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        XorMappedAddress(self.0).encode(ctx, builder)
    }

    fn encode_len(&self) -> Result<u16, Error> {
        XorMappedAddress(self.0).encode_len()
    }
}

/// [RFC5766](https://datatracker.ietf.org/doc/html/rfc5766#section-14.6)
pub struct EvenPort(pub bool);

impl Attribute<'_> for EvenPort {
    type Context = ();
    const TYPE: u16 = 0x0018;

    fn decode(_: Self::Context, msg: &mut ParsedMessage, attr: ParsedAttr) -> Result<Self, Error> {
        Ok(Self(attr.get_value(msg.buffer()).read_u8()? == 1))
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        builder.buffer().put_u8(if self.0 { 1 } else { 0 });

        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(1)
    }
}

/// [RFC5766](https://datatracker.ietf.org/doc/html/rfc5766#section-14.7)
pub struct RequestedTransport {
    // https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
    pub protocol_number: u8,
}

impl Attribute<'_> for RequestedTransport {
    type Context = ();
    const TYPE: u16 = 0x0019;

    fn decode(_: Self::Context, msg: &mut ParsedMessage, attr: ParsedAttr) -> Result<Self, Error> {
        Ok(Self {
            protocol_number: attr.get_value(msg.buffer()).read_u8()?,
        })
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        builder.buffer().put_u8(self.protocol_number);
        builder.buffer().put_u8(0);
        builder.buffer().put_u16(0);

        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(4)
    }
}

/// [RFC5766](https://datatracker.ietf.org/doc/html/rfc5766#section-14.8)
pub struct DontFragment;

impl Attribute<'_> for DontFragment {
    type Context = ();
    const TYPE: u16 = 0x001A;

    fn decode(_: Self::Context, _: &mut ParsedMessage, _: ParsedAttr) -> Result<Self, Error> {
        Ok(Self)
    }

    fn encode(&self, _: Self::Context, _: &mut MessageBuilder) -> Result<(), Error> {
        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(0)
    }
}

/// [RFC5766](https://datatracker.ietf.org/doc/html/rfc5766#section-14.9)
pub struct ReservationToken(pub [u8; 8]);

impl Attribute<'_> for ReservationToken {
    type Context = ();
    const TYPE: u16 = 0x0022;

    fn decode(_: Self::Context, msg: &mut ParsedMessage, attr: ParsedAttr) -> Result<Self, Error> {
        Ok(Self(attr.get_value(msg.buffer()).try_into().map_err(
            |_| Error::InvalidData("reservation token must be 8 bytes"),
        )?))
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        builder.buffer().extend_from_slice(&self.0[..]);

        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(8)
    }
}
