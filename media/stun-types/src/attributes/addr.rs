use super::Attribute;
use crate::builder::MessageBuilder;
use crate::parse::{AttrSpan, Message};
use crate::{COOKIE, Error, NE};
use byteorder::ReadBytesExt;
use bytes::BufMut;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

const XOR16: u16 = (COOKIE >> 16) as u16;

fn decode_addr(mut buf: &[u8], xor16: u16, xor32: u32, xor128: u128) -> Result<SocketAddr, Error> {
    if buf.read_u8()? != 0 {
        return Err(Error::InvalidData("first byte must be zero"));
    }

    let family = buf.read_u8()?;
    let port = buf.read_u16::<NE>()? ^ xor16;

    let addr = match family {
        1 => {
            let ip = buf.read_u32::<NE>()? ^ xor32;
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port))
        }
        2 => {
            let ip = buf.read_u128::<NE>()? ^ xor128;
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0))
        }
        _ => {
            return Err(Error::InvalidData("invalid address family"));
        }
    };

    Ok(addr)
}

fn encode_addr(addr: SocketAddr, buf: &mut Vec<u8>, xor16: u16, xor32: u32, xor128: u128) {
    buf.put_u8(0);

    match addr {
        SocketAddr::V4(addr) => {
            buf.put_u8(1);
            buf.put_u16(addr.port() ^ xor16);

            let ip = u32::from_be_bytes(addr.ip().octets());
            let ip = ip ^ xor32;

            buf.put_u32(ip);
        }
        SocketAddr::V6(addr) => {
            buf.put_u8(2);
            buf.put_u16(addr.port() ^ xor16);

            let ip = u128::from_be_bytes(addr.ip().octets());
            let ip = ip ^ xor128;

            buf.put_u128(ip);
        }
    }
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.1)
pub struct MappedAddress(pub SocketAddr);

impl Attribute<'_> for MappedAddress {
    type Context = ();

    const TYPE: u16 = 0x0001;

    fn decode(_: Self::Context, msg: &mut Message, attr: AttrSpan) -> Result<Self, Error> {
        decode_addr(attr.get_value(msg.buffer()), 0, 0, 0).map(Self)
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) {
        encode_addr(self.0, builder.buffer(), 0, 0, 0);
    }

    fn encode_len(&self) -> Result<u16, Error> {
        match self.0 {
            SocketAddr::V4(_) => Ok(8),
            SocketAddr::V6(_) => Ok(20),
        }
    }
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.2)
pub struct XorMappedAddress(pub SocketAddr);

impl Attribute<'_> for XorMappedAddress {
    type Context = ();
    const TYPE: u16 = 0x0020;

    fn decode(_: Self::Context, msg: &mut Message, attr: AttrSpan) -> Result<Self, Error> {
        let xor128 = msg.id();
        decode_addr(attr.get_value(msg.buffer()), XOR16, COOKIE, xor128).map(Self)
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) {
        let xor128 = builder.id();
        encode_addr(self.0, builder.buffer(), XOR16, COOKIE, xor128);
    }

    fn encode_len(&self) -> Result<u16, Error> {
        match self.0 {
            SocketAddr::V4(_) => Ok(8),
            SocketAddr::V6(_) => Ok(20),
        }
    }
}

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.15)
pub struct AlternateServer(pub SocketAddr);

impl Attribute<'_> for AlternateServer {
    type Context = ();
    const TYPE: u16 = 0x8023;

    fn decode(_: Self::Context, msg: &mut Message, attr: AttrSpan) -> Result<Self, Error> {
        decode_addr(attr.get_value(msg.buffer()), 0, 0, 0).map(Self)
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) {
        encode_addr(self.0, builder.buffer(), 0, 0, 0);
    }

    fn encode_len(&self) -> Result<u16, Error> {
        match self.0 {
            SocketAddr::V4(_) => Ok(8),
            SocketAddr::V6(_) => Ok(20),
        }
    }
}
