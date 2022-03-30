use super::{DecodeError, Header};
use bytes::{Buf, BufMut, Bytes};

pub struct Bye {
    pub ssrc_csrc: Vec<u32>,
    pub reason: Option<Bytes>,
}

impl Bye {
    pub fn encode<B>(&self, dst: &mut B)
    where
        B: BufMut,
    {
        for &ssrc_csrc in &self.ssrc_csrc {
            dst.put_u32(ssrc_csrc);
        }

        if let Some(reason) = &self.reason {
            dst.put_u8(reason.len() as u8);
            dst.put(&reason[..]);
        }
    }

    pub fn decode<B>(mut buf: B, header: &Header) -> Result<Self, DecodeError>
    where
        B: Buf,
    {
        let sc = header.rc() as usize;

        if buf.remaining() < 4 * sc {
            return Err(DecodeError::Incomplete);
        }

        let ssrc_csrc = (0..sc).map(|_| buf.get_u32()).collect();

        let reason = if buf.remaining() > 0 {
            let length = buf.get_u8() as usize;

            if buf.remaining() < length {
                return Err(DecodeError::Incomplete);
            }

            Some(buf.copy_to_bytes(length))
        } else {
            None
        };

        Ok(Self { ssrc_csrc, reason })
    }
}
