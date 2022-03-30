use super::{header::Header, DecodeError};
use bytes::{Buf, BufMut, Bytes};

/// RTP Packet decoded from input or created from parts
#[derive(Debug)]
pub struct Packet {
    /// Header of the packet
    pub header: Header,

    /// Payload of the RTP Packet
    pub payload: Bytes,
}

impl Packet {
    pub fn from_parts<P>(header: Header, payload: P) -> Self
    where
        P: Into<Bytes>,
    {
        Self {
            header,
            payload: payload.into(),
        }
    }

    pub fn encode<B>(&self, buf: &mut B)
    where
        B: BufMut,
    {
        self.header.encode(buf);
        buf.put(&self.payload[..])
    }

    pub fn decode<B>(mut buf: B) -> Result<Self, DecodeError>
    where
        B: Buf,
    {
        let header = Header::decode(&mut buf)?;

        Ok(Self {
            header,
            payload: buf.copy_to_bytes(buf.remaining()),
        })
    }
}
