use super::DecodeError;
use bytes::{Buf, BufMut, Bytes};

pub struct App {
    pub ssrc_csrc: u32,
    pub name: [u8; 4],
    /// 32bit aligned application data
    pub data: Bytes,
}

impl App {
    pub fn encode<B>(&self, dst: &mut B)
    where
        B: BufMut,
    {
        assert_eq!(self.data.len() % 4, 0);

        dst.put_u32(self.ssrc_csrc);
        dst.put(&self.name[..]);
        dst.put(&self.data[..]);
    }

    pub fn decode<B>(mut buf: B) -> Result<Self, DecodeError>
    where
        B: Buf,
    {
        if buf.remaining() < 8 {
            return Err(DecodeError::Incomplete);
        }

        let ssrc_csrc = buf.get_u32();
        let name = buf.get_u32().to_be_bytes();

        let remaining = buf.remaining();

        if remaining % 4 != 0 {
            return Err(DecodeError::InvalidAlignment);
        }

        let data = buf.copy_to_bytes(remaining);

        Ok(Self {
            ssrc_csrc,
            name,
            data,
        })
    }
}
