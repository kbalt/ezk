use super::DecodeError;
use arrayvec::ArrayVec;
use bytes::{Buf, BufMut};

const B0_V: u8 = 0b1100_0000;
const B0_P: u8 = 0b0010_0000;
const B0_X: u8 = 0b0001_0000;
const B0_CC: u8 = 0b0000_1111;

const B1_M: u8 = 0b1000_0000;
const B1_PT: u8 = 0b0111_1111;

const FIXED_HEADER_LEN: usize = 12;

/// RTP Header
#[derive(Debug, Default)]
pub struct Header {
    // V  0,1 Version (2)
    // P  2 Padding bit
    // X  3 Extension bit
    // CC 4,5,6,7 CSRC Count
    /// First byte of the header.
    /// Use the helper methods to access the fields in this byte.
    pub b0: u8,

    // M  0   Marker bit
    // PT 1-7 Payload type
    /// Second byte of the header.
    /// Use the helper methods to access the fields in this byte.
    pub b1: u8,

    // Sequence number
    pub sequence_number: u16,

    /// Timestamp
    pub timestamp: u32,

    /// SSRC
    pub ssrc: u32,

    /// List of up to 15 CSRCs
    pub csrcs: ArrayVec<u32, 15>,

    /// Optional extension
    pub extension: Option<Extension>,
}

#[derive(Debug, Clone)]
pub struct Extension {
    pub defined_by_profile: u16,
    pub data: Vec<u32>,
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

    pub fn x(&self) -> bool {
        (self.b0 & B0_X) > 0
    }

    pub fn set_x(&mut self, x: bool) {
        if x {
            self.b0 |= B0_X;
        } else {
            self.b0 &= !B0_X;
        }
    }

    pub fn cc(&self) -> u8 {
        self.b0 & B0_CC
    }

    pub fn set_cc(&mut self, cc: u8) {
        self.b0 &= !B0_CC;
        self.b0 |= cc & B0_CC;
    }

    pub fn m(&self) -> bool {
        (self.b1 & B1_M) > 0
    }

    pub fn set_m(&mut self, m: bool) {
        if m {
            self.b0 |= B1_M;
        } else {
            self.b0 &= !B1_M;
        }
    }

    pub fn pt(&self) -> u8 {
        self.b1 & B1_PT
    }

    pub fn set_pt(&mut self, cc: u8) {
        self.b0 &= !B1_PT;
        self.b0 |= cc & B1_PT;
    }

    pub fn encode<B>(&self, dst: &mut B)
    where
        B: BufMut,
    {
        dst.put_u8(self.b0);
        dst.put_u8(self.b1);
        dst.put_u16(self.sequence_number);
        dst.put_u32(self.timestamp);
        dst.put_u32(self.ssrc);

        for &csrc in &self.csrcs {
            dst.put_u32(csrc);
        }

        if let Some(Extension {
            defined_by_profile: extension,
            data,
        }) = &self.extension
        {
            let max = u16::MAX as usize;

            dst.put_u16(*extension);
            dst.put_u16(data.len().min(max) as u16);
            for data in data.iter().take(max).copied() {
                dst.put_u32(data);
            }
        }
    }

    pub fn decode<B>(mut buf: B) -> Result<Self, DecodeError>
    where
        B: Buf,
    {
        if buf.remaining() < FIXED_HEADER_LEN {
            return Err(DecodeError::Incomplete);
        }

        let b0 = buf.get_u8();
        let b1 = buf.get_u8();

        let sequence_number = buf.get_u16();
        let timestamp = buf.get_u32();
        let ssrc = buf.get_u32();

        let mut this = Header {
            b0,
            b1,
            sequence_number,
            timestamp,
            ssrc,
            csrcs: ArrayVec::new(),
            extension: None,
        };

        let cc = this.cc() as usize;

        if buf.remaining() < (cc * 4) {
            return Err(DecodeError::Incomplete);
        }

        for _ in 0..cc {
            this.csrcs.push(buf.get_u32());
        }

        if this.x() {
            if buf.remaining() < 4 {
                return Err(DecodeError::Incomplete);
            }

            // TODO: https://datatracker.ietf.org/doc/html/rfc8285

            let defined_by_profile = buf.get_u16();
            let length = buf.get_u16();

            if buf.remaining() < ((length as usize) * 4) {
                return Err(DecodeError::Incomplete);
            }

            let data = (0..length).into_iter().map(|_| buf.get_u32()).collect();

            this.extension = Some(Extension {
                defined_by_profile,
                data,
            });
        }

        Ok(this)
    }
}
