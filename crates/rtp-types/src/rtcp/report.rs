use super::DecodeError;
use super::Header;
use bytes::{Buf, BufMut, Bytes};

pub struct SenderReport {
    pub ssrc: u32,
    pub sender_info: SenderInfo,
    pub report_blocks: Vec<ReportBlock>,
    pub extensions: Bytes,
}

impl SenderReport {
    pub fn encode<B>(&self, dst: &mut B)
    where
        B: BufMut,
    {
        dst.put_u32(self.ssrc);

        self.sender_info.encode(dst);

        for report_block in &self.report_blocks {
            report_block.encode(dst);
        }

        dst.put(&self.extensions[..]);
    }

    pub fn decode<B>(mut buf: B, header: &Header) -> Result<Self, DecodeError>
    where
        B: Buf,
    {
        let rc = header.rc() as usize;

        if buf.remaining() < 24 + (rc * 36) {
            return Err(DecodeError::Incomplete);
        }

        let ssrc = buf.get_u32();
        let sender_info = SenderInfo::decode(&mut buf)?;

        let mut report_blocks = Vec::with_capacity(0);

        for _ in 0..rc {
            report_blocks.push(ReportBlock::decode(&mut buf)?);
        }

        let extensions = buf.copy_to_bytes(buf.remaining());

        Ok(Self {
            ssrc,
            sender_info,
            report_blocks,
            extensions,
        })
    }
}

pub struct SenderInfo {
    pub ntp_timestamp: u64,
    pub rtp_timestamp: u32,
    pub sender_pkg_count: u32,
    pub sender_octet_count: u32,
}

impl SenderInfo {
    pub fn encode<B>(&self, dst: &mut B)
    where
        B: BufMut,
    {
        dst.put_u64(self.ntp_timestamp);
        dst.put_u32(self.rtp_timestamp);
        dst.put_u32(self.sender_pkg_count);
        dst.put_u32(self.sender_octet_count);
    }

    pub fn decode<B>(mut buf: B) -> Result<Self, DecodeError>
    where
        B: Buf,
    {
        if buf.remaining() < 20 {
            return Err(DecodeError::Incomplete);
        }

        let ntp_timestamp = buf.get_u64();
        let rtp_timestamp = buf.get_u32();
        let sender_pkg_count = buf.get_u32();
        let sender_octet_count = buf.get_u32();

        Ok(Self {
            ntp_timestamp,
            rtp_timestamp,
            sender_pkg_count,
            sender_octet_count,
        })
    }
}

pub struct ReceiverReport {
    pub ssrc: u32,
    pub report_blocks: Vec<ReportBlock>,
    pub extensions: Bytes,
}

impl ReceiverReport {
    pub fn encode<B>(&self, dst: &mut B)
    where
        B: BufMut,
    {
        dst.put_u32(self.ssrc);

        for report_block in &self.report_blocks {
            report_block.encode(dst);
        }

        dst.put(&self.extensions[..]);
    }

    pub fn decode<B>(mut buf: B, header: &Header) -> Result<Self, DecodeError>
    where
        B: Buf,
    {
        let rc = header.rc() as usize;

        if buf.remaining() < 4 + (rc * 36) {
            return Err(DecodeError::Incomplete);
        }

        let ssrc = buf.get_u32();

        let mut report_blocks = Vec::with_capacity(0);

        for _ in 0..rc {
            report_blocks.push(ReportBlock::decode(&mut buf)?);
        }

        let extensions = buf.copy_to_bytes(buf.remaining());

        Ok(Self {
            ssrc,
            report_blocks,
            extensions,
        })
    }
}

pub struct ReportBlock {
    pub ssrc: u32,
    /// fraction lost and cumulative number of packets lost
    pub lost: u32,
    pub last_seq_num: u32,
    pub jitter: u32,
    pub last_sr: u32,
    pub delay: u32,
}

impl ReportBlock {
    pub fn fraction_lost(&self) -> u8 {
        ((self.lost & 0xFF_00_00_00) >> 24) as u8
    }

    pub fn total_lost(&self) -> u32 {
        self.lost & 0xFF_FF_FF
    }

    pub fn encode<B>(&self, dst: &mut B)
    where
        B: BufMut,
    {
        dst.put_u32(self.ssrc);
        dst.put_u32(self.lost);
        dst.put_u32(self.last_seq_num);
        dst.put_u32(self.jitter);
        dst.put_u32(self.last_sr);
        dst.put_u32(self.delay);
    }

    pub fn decode<B>(mut buf: B) -> Result<Self, DecodeError>
    where
        B: Buf,
    {
        if buf.remaining() < 36 {
            return Err(DecodeError::Incomplete);
        }

        let ssrc = buf.get_u32();
        let lost = buf.get_u32();
        let last_seq_num = buf.get_u32();
        let jitter = buf.get_u32();
        let last_sr = buf.get_u32();
        let delay = buf.get_u32();

        Ok(Self {
            ssrc,
            lost,
            last_seq_num,
            jitter,
            last_sr,
            delay,
        })
    }
}
