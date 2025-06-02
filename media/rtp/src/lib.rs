use bytes::Bytes;

mod extensions;
mod rtp_packet;

pub use extensions::{parse_extensions, RtpExtensionsWriter};
pub use rtp_packet::{RtpExtensionIds, RtpExtensions, RtpPacket};

pub use rtcp_types;
pub use rtp_types;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ssrc(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SequenceNumber(pub u16);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExtendedSequenceNumber(pub u64);

impl ExtendedSequenceNumber {
    pub fn increase_one(&mut self) -> SequenceNumber {
        self.0 += 1;
        SequenceNumber((self.0 & u16::MAX as u64) as u16)
    }

    pub fn rollover_count(&self) -> u64 {
        self.0 >> 16
    }

    pub fn guess_extended(&self, seq: SequenceNumber) -> ExtendedSequenceNumber {
        ExtendedSequenceNumber(wrapping_counter_to_u64_counter(
            self.0,
            u64::from(seq.0),
            u64::from(u16::MAX),
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RtpTimestamp(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExtendedRtpTimestamp(pub u64);

impl ExtendedRtpTimestamp {
    pub fn truncated(&self) -> RtpTimestamp {
        RtpTimestamp(self.0 as u32)
    }

    pub fn rollover_count(&self) -> u64 {
        self.0 >> 32
    }

    pub fn guess_extended(&self, seq: RtpTimestamp) -> ExtendedRtpTimestamp {
        ExtendedRtpTimestamp(wrapping_counter_to_u64_counter(
            self.0,
            u64::from(seq.0),
            u64::from(u32::MAX),
        ))
    }
}

fn wrapping_counter_to_u64_counter(reference: u64, got: u64, max: u64) -> u64 {
    let mul = (reference / max).saturating_sub(1);

    let low = mul * max + got;
    let high = (mul + 1) * max + got;

    if low.abs_diff(reference) < high.abs_diff(reference) {
        low
    } else {
        high
    }
}

/// Create RTP payload from media data
pub trait Payloader: Send + 'static {
    /// Payload a given frame
    fn payload(&mut self, frame: &Bytes, max_size: usize) -> impl Iterator<Item = Bytes> + '_;
}

pub trait DePayloader: Send + 'static {
    fn depayload(&mut self, payload: &Bytes) -> Option<Bytes>;
}
