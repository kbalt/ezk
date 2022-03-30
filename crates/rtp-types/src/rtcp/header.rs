use super::DecodeError;
use bytes::{Buf, BufMut};

const B0_V: u8 = 0b1100_0000;
const B0_P: u8 = 0b0010_0000;
const B0_RC: u8 = 0b0001_1111;

const HEADER_LEN: usize = 4;

/// RTCP Header
#[derive(Debug, Default, Copy, Clone)]
pub struct Header {
    // V  0,1 Version (2)
    // P  2 Padding bit
    // RC 3,4,5,6,7 Reception report count
    /// First byte of the header.
    /// Use the helper methods to access the fields in this byte.
    pub b0: u8,

    /// Packet type
    pub pt: u8,

    /// Length of the RTCP Packet
    pub length: u16,
}

impl Header {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn v(&self) -> u8 {
        (self.b0 & B0_V) << 6
    }

    pub fn set_v(&mut self, v: u8) {
        let v = v << 6;

        self.b0 &= !B0_V;
        self.b0 |= v & B0_V;
    }

    pub fn p(&self) -> bool {
        (self.b0 & B0_P) > 0
    }

    pub fn set_p(&mut self, p: bool) {
        if p {
            self.b0 |= B0_P;
        } else {
            self.b0 &= !B0_P;
        }
    }

    pub fn rc(&self) -> u8 {
        self.b0 & B0_RC
    }

    pub fn set_rc(&mut self, rc: u8) {
        self.b0 &= !B0_RC;
        self.b0 |= rc & B0_RC;
    }

    pub fn encode<B>(&self, dst: &mut B)
    where
        B: BufMut,
    {
        dst.put_u8(self.b0);
        dst.put_u8(self.pt);
        dst.put_u16(self.length);
    }

    pub fn decode<B>(mut buf: B) -> Result<Self, DecodeError>
    where
        B: Buf,
    {
        if buf.remaining() < HEADER_LEN {
            return Err(DecodeError::Incomplete);
        }

        let b0 = buf.get_u8();
        let pt = buf.get_u8();
        let length = buf.get_u16();

        let this = Self { b0, pt, length };

        if this.v() != 2 {
            return Err(DecodeError::InvalidVersion);
        }

        // TODO validate length

        Ok(this)
    }
}
