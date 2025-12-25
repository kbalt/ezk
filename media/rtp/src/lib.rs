use bytes::Bytes;

mod extensions;
mod rtp_packet;

pub use extensions::{RtpExtensionsWriter, parse_extensions};
pub use rtp_packet::{RtpAudioLevelExt, RtpExtensionIds, RtpExtensions, RtpPacket};

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
        self.truncated()
    }

    pub fn truncated(&self) -> SequenceNumber {
        SequenceNumber(self.0 as u16)
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
    let base = (reference & !max) | got;

    let below = base.wrapping_sub(1u64 << max.count_ones());
    let above = base.wrapping_add(1u64 << max.count_ones());

    let dist_base = reference.abs_diff(base);
    let dist_below = reference.abs_diff(below);
    let dist_above = reference.abs_diff(above);

    if dist_below < dist_base && dist_below <= dist_above {
        below
    } else if dist_above < dist_base && dist_above < dist_below {
        above
    } else {
        base
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

#[test]
fn rollover() {
    let reference = ExtendedSequenceNumber(65535);
    assert_eq!(
        reference.guess_extended(SequenceNumber(65534)),
        ExtendedSequenceNumber(65534)
    );
    assert_eq!(
        reference.guess_extended(SequenceNumber(65535)),
        ExtendedSequenceNumber(65535)
    );
    assert_eq!(
        reference.guess_extended(SequenceNumber(0)),
        ExtendedSequenceNumber(65536)
    );
    assert_eq!(
        reference.guess_extended(SequenceNumber(1)),
        ExtendedSequenceNumber(65537)
    );

    let reference = ExtendedSequenceNumber(131071);
    assert_eq!(
        reference.guess_extended(SequenceNumber(65533)),
        ExtendedSequenceNumber(131069)
    );
    assert_eq!(
        reference.guess_extended(SequenceNumber(65534)),
        ExtendedSequenceNumber(131070)
    );
    assert_eq!(
        reference.guess_extended(SequenceNumber(65535)),
        ExtendedSequenceNumber(131071)
    );
    assert_eq!(
        reference.guess_extended(SequenceNumber(0)),
        ExtendedSequenceNumber(131072)
    );
    assert_eq!(
        reference.guess_extended(SequenceNumber(1)),
        ExtendedSequenceNumber(131073)
    );

    let reference = ExtendedSequenceNumber(196607);

    assert_eq!(
        reference.guess_extended(SequenceNumber(65533)),
        ExtendedSequenceNumber(196605)
    );
    assert_eq!(
        reference.guess_extended(SequenceNumber(65534)),
        ExtendedSequenceNumber(196606)
    );
    assert_eq!(
        reference.guess_extended(SequenceNumber(65535)),
        ExtendedSequenceNumber(196607)
    );
    assert_eq!(
        reference.guess_extended(SequenceNumber(0)),
        ExtendedSequenceNumber(196608)
    );
}
