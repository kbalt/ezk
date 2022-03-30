use super::DecodeError;
use bytes::{Buf, BufMut};
use bytesstr::BytesStr;

pub const CNAME: u8 = 1;
pub const NAME: u8 = 2;
pub const EMAIL: u8 = 3;
pub const PHONE: u8 = 4;
pub const LOC: u8 = 5;
pub const TOOL: u8 = 6;
pub const NOTE: u8 = 7;
pub const PRIV: u8 = 8;

#[derive(Debug)]
pub struct SourceDescription {
    pub chunks: Vec<SourceDescriptionChunk>,
}

impl SourceDescription {
    pub fn encode<B>(&self, dst: &mut B)
    where
        B: BufMut,
    {
        for chunk in &self.chunks {
            chunk.encode(dst);
        }
    }

    pub fn decode<B>(mut buf: B) -> Result<Self, DecodeError>
    where
        B: Buf,
    {
        let mut chunks = vec![];

        while buf.remaining() > 0 {
            chunks.push(SourceDescriptionChunk::decode(&mut buf)?);
        }

        Ok(Self { chunks })
    }
}

#[derive(Debug)]
pub struct SourceDescriptionChunk {
    pub ssrc_or_csrc: u32,
    pub items: Vec<SourceDescriptionChunkItem>,
}

#[derive(Debug)]
pub struct SourceDescriptionChunkItem {
    pub tag: u8,
    pub value: BytesStr,
}

impl SourceDescriptionChunk {
    pub fn encode<B>(&self, dst: &mut B)
    where
        B: BufMut,
    {
        dst.put_u32(self.ssrc_or_csrc);

        // track amount of bytes add to add alignment bytes later
        let mut chunk_len = 0;

        for item in &self.items {
            dst.put_u8(item.tag);
            dst.put_u8(item.value.len() as u8);
            dst.put(item.value.as_bytes());

            chunk_len += 2 + item.value.len();
        }

        dst.put_u8(0);
        chunk_len += 1;

        // add padding to achieve alignment
        dst.put_bytes(0, chunk_len % 4);
    }

    pub fn decode<B>(mut buf: B) -> Result<Self, DecodeError>
    where
        B: Buf,
    {
        if buf.remaining() < 5 {
            return Err(DecodeError::Incomplete);
        }

        let ssrc_or_csrc = buf.get_u32();

        let mut items = vec![];

        // track the chunk size to add alignment bytes at the end
        let mut chunk_len = 0;

        loop {
            if !buf.has_remaining() {
                return Err(DecodeError::Incomplete);
            }

            let tag = buf.get_u8();
            chunk_len += 1;

            if tag == 0 {
                buf.advance(chunk_len % 4);
                break;
            }

            let length = buf.get_u8() as usize;
            chunk_len += 1 + length;

            if buf.remaining() < length {
                return Err(DecodeError::Incomplete);
            }

            let value = BytesStr::from_utf8_bytes(buf.copy_to_bytes(length))?;

            items.push(SourceDescriptionChunkItem { tag, value });
        }

        Ok(Self {
            ssrc_or_csrc,
            items,
        })
    }
}
