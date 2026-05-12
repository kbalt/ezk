//! See // Reference https://aomediacodec.github.io/av1-rtp-spec/v1.0.0.html

use std::{cmp, mem::take};

use bytes::Bytes;
use smallvec::{SmallVec, smallvec};

mod leb128;

const MAX_OBU_SIZE: usize = 100_000_000;
const MIN_PAYLOAD_MAX_SIZE: usize = 3;

const OBU_SEQUENCE_HEADER: u8 = 1;
const OBU_TEMPORAL_DELIMITER: u8 = 2;
// const OBU_FRAME_HEADER: u8 = 3;
// const OBU_TILE_GROUP: u8 = 4;
// const OBU_METADATA: u8 = 5;
// const OBU_FRAME: u8 = 6;
// const OBU_REDUNDANT_FRAME_HEADER: u8 = 7;
const OBU_TILE_LIST: u8 = 8;

#[derive(Debug)]
struct ObuHeaderAndSize {
    type_: u8,
    extension: Option<u8>,
    content_offset: usize,
    size: usize,
}

impl ObuHeaderAndSize {
    fn parse(bytes: &[u8]) -> Option<ObuHeaderAndSize> {
        let mut bytes = bytes.iter();

        let header = bytes.next()?;

        let type_ = header >> 3 & 0x0F;
        let has_extension = header & 0b100 != 0;
        let has_size = header & 0b10 != 0;
        if !has_size {
            return None;
        }

        let extension = if has_extension {
            Some(*bytes.next()?)
        } else {
            None
        };

        let bytes = bytes.as_slice();

        let (size_length, size) = leb128::read_leb128(bytes)?;

        let content_offset = 1 + (has_extension as usize) + size_length;

        Some(ObuHeaderAndSize {
            type_,
            extension,
            content_offset,
            size: content_offset + size as usize,
        })
    }

    fn header(&self) -> u8 {
        (self.type_ << 3) | ((self.extension.is_some() as u8) << 2)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AV1PayloadError {
    #[error("max_size is too small to fit any OBU data (must be >= {MIN_PAYLOAD_MAX_SIZE})")]
    MaxSizeTooSmall,
    #[error("Input contains an OBU without an obu_size field, or is truncated")]
    InvalidObu,
}

pub struct AV1Payloader {
    _priv: (),
}

impl AV1Payloader {
    pub fn new() -> AV1Payloader {
        AV1Payloader { _priv: () }
    }

    /// Packetize a sequence of AV1 OBUs into RTP payloads of at most `max_size`
    /// bytes each.
    ///
    /// Input must be a low-overhead bitstream where each OBU has
    /// `obu_has_size_field = 1` (per the AV1 RTP packetization spec the
    /// payloader strips this field on the wire).
    pub fn payload(
        &mut self,
        mut to_payload: Bytes,
        max_size: usize,
    ) -> Result<Vec<Vec<u8>>, AV1PayloadError> {
        if max_size < MIN_PAYLOAD_MAX_SIZE {
            return Err(AV1PayloadError::MaxSizeTooSmall);
        }

        let mut payloads = Vec::new();

        let mut current_payload = Vec::with_capacity(max_size);
        current_payload.push(0); // Aggregation header

        while !to_payload.is_empty() {
            let header_and_size =
                ObuHeaderAndSize::parse(&to_payload).ok_or(AV1PayloadError::InvalidObu)?;

            if to_payload.len() < header_and_size.size {
                return Err(AV1PayloadError::InvalidObu);
            }

            let mut full_obu = to_payload.split_to(header_and_size.size);

            if matches!(
                header_and_size.type_,
                OBU_TEMPORAL_DELIMITER | OBU_TILE_LIST
            ) {
                continue;
            }

            let _ = full_obu.split_to(header_and_size.content_offset);
            let payload_bytes = full_obu;

            let mut wire_obu = Vec::with_capacity(
                1 + header_and_size.extension.is_some() as usize + payload_bytes.len(),
            );
            wire_obu.push(header_and_size.header());
            if let Some(ext) = header_and_size.extension {
                wire_obu.push(ext);
            }
            wire_obu.extend_from_slice(&payload_bytes);

            if matches!(header_and_size.type_, OBU_SEQUENCE_HEADER) {
                // packet that begins a coded video sequence, set N=1
                current_payload[0] |= 1 << 3;
            }

            let mut to_send = wire_obu.as_slice();
            let total_len = to_send.len();

            while !to_send.is_empty() {
                let remaining_space = max_size - current_payload.len();

                let leb_size_upper =
                    leb128::expected_size(remaining_space.min(u32::MAX as usize) as u32);

                let usable = remaining_space.saturating_sub(leb_size_upper);
                let fragment_size = cmp::min(usable, to_send.len());

                if fragment_size == 0 {
                    let already_started = to_send.len() < total_len;
                    if already_started {
                        // Y: this OBU continues into the next packet.
                        current_payload[0] |= 1 << 6;
                    }

                    if current_payload.len() == 1 {
                        // We just opened a fresh packet and still can't fit a
                        // single byte: max_size must be too small.
                        return Err(AV1PayloadError::MaxSizeTooSmall);
                    }

                    payloads.push(take(&mut current_payload));
                    current_payload = Vec::with_capacity(max_size);
                    // Z: the next packet starts with a continuation iff we'd
                    // already started writing this OBU.
                    current_payload.push((already_started as u8) << 7);

                    continue;
                }

                leb128::write_leb128(&mut current_payload, fragment_size as u32);
                current_payload.extend_from_slice(&to_send[..fragment_size]);
                to_send = &to_send[fragment_size..];

                if !to_send.is_empty() {
                    // Y: this OBU continues into the next packet.
                    current_payload[0] |= 1 << 6;
                    payloads.push(take(&mut current_payload));
                    current_payload = Vec::with_capacity(max_size);
                    // Z=1: the next packet starts with the continuation.
                    current_payload.push(1 << 7);
                }
            }
        }

        if current_payload.len() > 1 {
            payloads.push(current_payload);
        }

        Ok(payloads)
    }
}

impl Default for AV1Payloader {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AV1DePayloadError {
    #[error("Unexpected end of packet")]
    UnexpectedEndOfPacket,
    #[error("Got 0 length for OBU packet")]
    ZeroLengthOBU,
    #[error("Received OBU exceeded maximum allowed size")]
    FragmentedObuTooLarge,
    #[error("Received OBU is malformed")]
    MalformedObu,
}

pub struct AV1DePayloader {
    current_obu: Vec<u8>,
}

impl AV1DePayloader {
    pub fn new() -> AV1DePayloader {
        AV1DePayloader {
            current_obu: Vec::new(),
        }
    }

    pub fn depayload(
        &mut self,
        mut packet: &[u8],
    ) -> Result<SmallVec<[Vec<u8>; 3]>, AV1DePayloadError> {
        if packet.is_empty() {
            return Ok(smallvec![]);
        }

        let mut obus = smallvec![];

        let aggregation_header = packet[0];
        packet = &packet[1..];

        let mut continues_fragment = (aggregation_header & 1 << 7) != 0;
        let contains_fragment = (aggregation_header & 1 << 6) != 0;
        let num_remaining_obus = (aggregation_header >> 4) & 0x3;
        let mut num_remaining_obus = (num_remaining_obus > 0).then_some(num_remaining_obus);

        while !packet.is_empty() {
            // If a count is present in the aggregation header, the last OBU
            // element has no length prefix; otherwise every element does.
            let has_length = if let Some(remaining_obu) = &mut num_remaining_obus {
                *remaining_obu -= 1;
                *remaining_obu > 0
            } else {
                true
            };

            let (consumed, len) = if has_length {
                let (consumed, len) =
                    leb128::read_leb128(packet).ok_or(AV1DePayloadError::UnexpectedEndOfPacket)?;
                (consumed, len as usize)
            } else {
                (0, packet.len())
            };

            if len == 0 {
                return Err(AV1DePayloadError::ZeroLengthOBU);
            }

            let (obu_bytes, remaining) = packet[consumed..]
                .split_at_checked(len)
                .ok_or(AV1DePayloadError::UnexpectedEndOfPacket)?;

            packet = remaining;

            if continues_fragment {
                continues_fragment = false;

                if self.current_obu.is_empty() {
                    // Continuation but nothing buffered (likely packet loss); drop it.
                    continue;
                }

                if self.current_obu.len().saturating_add(obu_bytes.len()) > MAX_OBU_SIZE {
                    self.current_obu.clear();
                    return Err(AV1DePayloadError::FragmentedObuTooLarge);
                }

                self.current_obu.extend_from_slice(obu_bytes);

                // The continuation is complete unless it is also the last OBU
                // element in this packet and Y=1.
                if !packet.is_empty() || !contains_fragment {
                    let assembled = take(&mut self.current_obu);
                    obus.push(reconstruct_obu_with_size(&assembled)?);
                }
            } else if packet.is_empty() && contains_fragment {
                // Start of a new fragmented OBU. Drop any stale buffered fragment.
                self.current_obu.clear();
                if obu_bytes.len() > MAX_OBU_SIZE {
                    return Err(AV1DePayloadError::FragmentedObuTooLarge);
                }
                self.current_obu.extend_from_slice(obu_bytes);
            } else {
                obus.push(reconstruct_obu_with_size(obu_bytes)?);
            }
        }

        Ok(obus)
    }

    /// Reset the payload to the initial state
    ///
    /// Must be called when encountering packet loss to avoid aggregating broken OBUs
    pub fn reset(&mut self) {
        self.current_obu.clear();
    }
}

impl Default for AV1DePayloader {
    fn default() -> Self {
        Self::new()
    }
}

/// Take a wire-form OBU (no `obu_size` field) and produce the corresponding
/// OBU with `obu_has_size_field = 1` and a leb128 `obu_size` written.
fn reconstruct_obu_with_size(stripped: &[u8]) -> Result<Vec<u8>, AV1DePayloadError> {
    if stripped.is_empty() {
        return Err(AV1DePayloadError::ZeroLengthOBU);
    }
    let header = stripped[0];
    let has_extension = (header & 0b100) != 0;
    let header_len = 1 + has_extension as usize;
    if stripped.len() < header_len {
        return Err(AV1DePayloadError::MalformedObu);
    }
    let payload = &stripped[header_len..];

    let mut out = Vec::with_capacity(stripped.len() + leb128::expected_size(payload.len() as u32));
    out.push(header | 0b10); // set obu_has_size_field
    if has_extension {
        out.push(stripped[1]);
    }
    leb128::write_leb128(&mut out, payload.len() as u32);
    out.extend_from_slice(payload);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build an OBU in low-overhead-bitstream form (with `obu_has_size_field = 1`).
    fn make_obu(type_: u8, extension: Option<u8>, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        let header = (type_ << 3) | ((extension.is_some() as u8) << 2) | 0b10;
        out.push(header);
        if let Some(ext) = extension {
            out.push(ext);
        }
        leb128::write_leb128(&mut out, payload.len() as u32);
        out.extend_from_slice(payload);
        out
    }

    fn agg_header(packet: &[u8]) -> u8 {
        packet[0]
    }
    fn z_bit(packet: &[u8]) -> bool {
        agg_header(packet) & (1 << 7) != 0
    }
    fn y_bit(packet: &[u8]) -> bool {
        agg_header(packet) & (1 << 6) != 0
    }
    fn n_bit(packet: &[u8]) -> bool {
        agg_header(packet) & (1 << 3) != 0
    }

    // ==== Payloader ====

    #[test]
    fn payload_empty_input_returns_no_packets() {
        let mut p = AV1Payloader::new();
        let out = p.payload(Bytes::new(), 1500).unwrap();
        assert!(out.is_empty());
    }

    #[test]
    fn payload_rejects_too_small_max_size() {
        let mut p = AV1Payloader::new();
        let obu = make_obu(6, None, &[0xAA]);
        assert!(matches!(
            p.payload(Bytes::from(obu), 2),
            Err(AV1PayloadError::MaxSizeTooSmall)
        ));
    }

    #[test]
    fn payload_rejects_obu_without_size_field() {
        let mut p = AV1Payloader::new();
        // OBU header with no obu_has_size_field set.
        let bad = vec![6u8 << 3, 0x00];
        assert!(matches!(
            p.payload(Bytes::from(bad), 1500),
            Err(AV1PayloadError::InvalidObu)
        ));
    }

    #[test]
    fn payload_rejects_truncated_obu() {
        let mut p = AV1Payloader::new();
        // Header says payload length 100 but only one byte follows.
        let mut bad = Vec::new();
        bad.push((6u8 << 3) | 0b10); // type=6, has_size=1
        leb128::write_leb128(&mut bad, 100);
        bad.push(0xAA);
        assert!(matches!(
            p.payload(Bytes::from(bad), 1500),
            Err(AV1PayloadError::InvalidObu)
        ));
    }

    #[test]
    fn payload_drops_temporal_delimiter_and_tile_list() {
        let mut p = AV1Payloader::new();
        let mut input = Vec::new();
        input.extend_from_slice(&make_obu(OBU_TEMPORAL_DELIMITER, None, &[]));
        input.extend_from_slice(&make_obu(OBU_TILE_LIST, None, &[0; 10]));
        let packets = p.payload(Bytes::from(input), 1500).unwrap();
        assert!(packets.is_empty());
    }

    #[test]
    fn payload_sets_n_bit_for_sequence_header() {
        let mut p = AV1Payloader::new();
        let input = make_obu(OBU_SEQUENCE_HEADER, None, &[0x01, 0x02, 0x03]);
        let packets = p.payload(Bytes::from(input), 1500).unwrap();
        assert_eq!(packets.len(), 1);
        assert!(n_bit(&packets[0]));
        assert!(!z_bit(&packets[0]));
        assert!(!y_bit(&packets[0]));
    }

    #[test]
    fn payload_strips_obu_size_field_in_single_packet() {
        let mut p = AV1Payloader::new();
        let payload = b"hello";
        let input = make_obu(6, None, payload);
        let packets = p.payload(Bytes::from(input), 1500).unwrap();
        assert_eq!(packets.len(), 1);
        let pkt = &packets[0];

        // Layout: agg_header, leb128(len), header_byte (no has_size), payload
        assert_eq!(pkt[0], 0); // no flags set
        let (consumed, len) = leb128::read_leb128(&pkt[1..]).unwrap();
        let body = &pkt[1 + consumed..];
        assert_eq!(len as usize, body.len());
        assert_eq!(body.len(), 1 + payload.len()); // header + payload, no size leb128
        // has_size bit must be cleared in the wire OBU header
        assert_eq!(body[0] & 0b10, 0);
        assert_eq!((body[0] >> 3) & 0xF, 6); // type preserved
        assert_eq!(&body[1..], payload);
    }

    #[test]
    fn payload_preserves_extension_byte() {
        let mut p = AV1Payloader::new();
        let payload = b"data";
        let input = make_obu(6, Some(0b1011_0000), payload);
        let packets = p.payload(Bytes::from(input), 1500).unwrap();
        assert_eq!(packets.len(), 1);
        let pkt = &packets[0];
        let (consumed, len) = leb128::read_leb128(&pkt[1..]).unwrap();
        let body = &pkt[1 + consumed..];
        assert_eq!(len as usize, body.len());
        assert_eq!(body[0] & 0b100, 0b100); // extension flag preserved
        assert_eq!(body[0] & 0b10, 0); // has_size cleared
        assert_eq!(body[1], 0b1011_0000); // extension byte preserved
        assert_eq!(&body[2..], payload);
    }

    #[test]
    fn payload_fragments_large_obu_across_packets() {
        let mut p = AV1Payloader::new();
        let big_payload: Vec<u8> = (0..500u32).map(|i| (i & 0xFF) as u8).collect();
        let input = make_obu(6, None, &big_payload);
        let packets = p.payload(Bytes::from(input), 100).unwrap();
        assert!(packets.len() > 1);
        // First packet: Z=0, Y=1
        assert!(!z_bit(&packets[0]));
        assert!(y_bit(&packets[0]));
        // Middle packets: Z=1, Y=1
        for pkt in &packets[1..packets.len() - 1] {
            assert!(z_bit(pkt));
            assert!(y_bit(pkt));
        }
        // Last packet: Z=1, Y=0
        let last = packets.last().unwrap();
        assert!(z_bit(last));
        assert!(!y_bit(last));
        // Each packet must be within max_size.
        for pkt in &packets {
            assert!(pkt.len() <= 100);
        }
    }

    // ==== Depayloader ====

    #[test]
    fn depayload_empty_packet_returns_nothing() {
        let mut d = AV1DePayloader::new();
        assert!(d.depayload(&[]).unwrap().is_empty());
    }

    #[test]
    fn depayload_continuation_without_buffer_is_dropped() {
        let mut d = AV1DePayloader::new();
        // Z=1 packet but receiver has no buffered fragment.
        let mut pkt = vec![1 << 7];
        leb128::write_leb128(&mut pkt, 3);
        pkt.extend_from_slice(&[0x30, 0xAA, 0xBB]);
        let obus = d.depayload(&pkt).unwrap();
        assert!(obus.is_empty());
    }

    #[test]
    fn depayload_zero_length_obu_is_error() {
        let mut d = AV1DePayloader::new();
        let pkt = vec![0u8, 0u8]; // agg header, leb128 length=0
        assert!(matches!(
            d.depayload(&pkt),
            Err(AV1DePayloadError::ZeroLengthOBU)
        ));
    }

    #[test]
    fn depayload_truncated_length_is_error() {
        let mut d = AV1DePayloader::new();
        let mut pkt = vec![0u8];
        leb128::write_leb128(&mut pkt, 50);
        pkt.extend_from_slice(&[0x30, 0xAA]);
        assert!(matches!(
            d.depayload(&pkt),
            Err(AV1DePayloadError::UnexpectedEndOfPacket)
        ));
    }

    #[test]
    fn depayload_w1_uses_no_length_prefix_for_single_obu() {
        let mut d = AV1DePayloader::new();
        // W=1 -> bit 4 set
        let agg = 1u8 << 4;
        let mut pkt = vec![agg];
        // Wire OBU: header (type=6, no ext, no size flag) + 3 payload bytes.
        pkt.push(6u8 << 3);
        pkt.extend_from_slice(&[0x11, 0x22, 0x33]);
        let obus = d.depayload(&pkt).unwrap();
        assert_eq!(obus.len(), 1);
        // Reconstructed OBU should have has_size=1 and a leb128 length.
        let obu = &obus[0];
        assert_eq!(obu[0] & 0b10, 0b10);
        let (consumed, len) = leb128::read_leb128(&obu[1..]).unwrap();
        assert_eq!(len, 3);
        assert_eq!(&obu[1 + consumed..], &[0x11, 0x22, 0x33]);
    }

    #[test]
    fn depayload_w2_skips_length_only_on_last_obu() {
        let mut d = AV1DePayloader::new();
        let agg = 2u8 << 4; // W=2
        let mut pkt = vec![agg];
        // First OBU: with length prefix
        leb128::write_leb128(&mut pkt, 3);
        pkt.push(6u8 << 3);
        pkt.extend_from_slice(&[0xAA, 0xBB]);
        // Second OBU: no length prefix, fills to end
        pkt.push(6u8 << 3);
        pkt.extend_from_slice(&[0xCC, 0xDD, 0xEE]);

        let obus = d.depayload(&pkt).unwrap();
        assert_eq!(obus.len(), 2);
        // Validate payloads were preserved.
        let unwrap_payload = |obu: &Vec<u8>| -> Vec<u8> {
            let has_ext = obu[0] & 0b100 != 0;
            let header_len = 1 + has_ext as usize;
            let (consumed, _len) = leb128::read_leb128(&obu[header_len..]).unwrap();
            obu[header_len + consumed..].to_vec()
        };
        assert_eq!(unwrap_payload(&obus[0]), vec![0xAA, 0xBB]);
        assert_eq!(unwrap_payload(&obus[1]), vec![0xCC, 0xDD, 0xEE]);
    }

    #[test]
    fn depayload_assembles_fragments_across_packets() {
        let mut d = AV1DePayloader::new();
        // packet 1: Z=0, Y=1, contains OBU header + first half
        let mut p1 = vec![1 << 6];
        let frag1 = [6u8 << 3, 0x11, 0x22];
        leb128::write_leb128(&mut p1, frag1.len() as u32);
        p1.extend_from_slice(&frag1);
        assert!(d.depayload(&p1).unwrap().is_empty());

        // packet 2: Z=1, Y=1, middle
        let mut p2 = vec![(1 << 7) | (1 << 6)];
        let frag2 = [0x33u8, 0x44];
        leb128::write_leb128(&mut p2, frag2.len() as u32);
        p2.extend_from_slice(&frag2);
        assert!(d.depayload(&p2).unwrap().is_empty());

        // packet 3: Z=1, Y=0, end
        let mut p3 = vec![1 << 7];
        let frag3 = [0x55u8];
        leb128::write_leb128(&mut p3, frag3.len() as u32);
        p3.extend_from_slice(&frag3);
        let obus = d.depayload(&p3).unwrap();
        assert_eq!(obus.len(), 1);

        let obu = &obus[0];
        assert_eq!(obu[0] & 0b10, 0b10); // has_size restored
        let (c, len) = leb128::read_leb128(&obu[1..]).unwrap();
        // 5 payload bytes total (0x11, 0x22, 0x33, 0x44, 0x55).
        assert_eq!(len, 5);
        assert_eq!(&obu[1 + c..], &[0x11, 0x22, 0x33, 0x44, 0x55]);
    }

    #[test]
    fn depayload_continuation_followed_by_more_obus_completes_first() {
        // Regression for the multi-OBU continuation bug.
        let mut d = AV1DePayloader::new();

        // Set up state: packet with Z=0, Y=1 buffering a fragment.
        let mut p1 = vec![1 << 6];
        let frag1 = [6u8 << 3, 0x11];
        leb128::write_leb128(&mut p1, frag1.len() as u32);
        p1.extend_from_slice(&frag1);
        assert!(d.depayload(&p1).unwrap().is_empty());

        // Next packet: Z=1, Y=0, with a continuation followed by another full OBU.
        let mut p2 = vec![1 << 7];
        let frag2 = [0x22u8];
        leb128::write_leb128(&mut p2, frag2.len() as u32);
        p2.extend_from_slice(&frag2);
        let obu2 = [6u8 << 3, 0xAA, 0xBB];
        leb128::write_leb128(&mut p2, obu2.len() as u32);
        p2.extend_from_slice(&obu2);

        let obus = d.depayload(&p2).unwrap();
        assert_eq!(obus.len(), 2);
        // First should be the assembled fragment (header + 0x11 + 0x22).
        let first = &obus[0];
        let (c, len) = leb128::read_leb128(&first[1..]).unwrap();
        assert_eq!(len, 2);
        assert_eq!(&first[1 + c..], &[0x11, 0x22]);
    }

    #[test]
    fn depayload_stale_fragment_is_cleared_on_new_fragment_start() {
        let mut d = AV1DePayloader::new();

        // Buffer some stale data.
        let mut p1 = vec![1 << 6];
        let frag1 = [6u8 << 3, 0x11];
        leb128::write_leb128(&mut p1, frag1.len() as u32);
        p1.extend_from_slice(&frag1);
        assert!(d.depayload(&p1).unwrap().is_empty());

        // Now a packet that itself starts a new fragment (Z=0, Y=1) without
        // continuing the previous one.
        let mut p2 = vec![1 << 6];
        let frag2 = [6u8 << 3, 0xAA];
        leb128::write_leb128(&mut p2, frag2.len() as u32);
        p2.extend_from_slice(&frag2);
        assert!(d.depayload(&p2).unwrap().is_empty());

        // Finish it.
        let mut p3 = vec![1 << 7];
        let frag3 = [0xBBu8];
        leb128::write_leb128(&mut p3, frag3.len() as u32);
        p3.extend_from_slice(&frag3);
        let obus = d.depayload(&p3).unwrap();
        assert_eq!(obus.len(), 1);
        let (c, len) = leb128::read_leb128(&obus[0][1..]).unwrap();
        assert_eq!(len, 2);
        // Stale 0x11 must NOT appear; payload must be just the new fragment.
        assert_eq!(&obus[0][1 + c..], &[0xAA, 0xBB]);
    }

    // -------- Round-trip --------

    fn roundtrip(input_obus: &[Vec<u8>], max_size: usize) -> Vec<Vec<u8>> {
        let mut p = AV1Payloader::new();
        let mut d = AV1DePayloader::new();
        let mut joined = Vec::new();
        for o in input_obus {
            joined.extend_from_slice(o);
        }
        let packets = p.payload(Bytes::from(joined), max_size).unwrap();
        let mut out = Vec::new();
        for pkt in &packets {
            for obu in d.depayload(pkt).unwrap() {
                out.push(obu);
            }
        }
        out
    }

    #[test]
    fn roundtrip_single_small_obu() {
        let obu = make_obu(6, None, &[0x10, 0x20, 0x30]);
        let out = roundtrip(&[obu.clone()], 1500);
        assert_eq!(out, vec![obu]);
    }

    #[test]
    fn roundtrip_obu_with_extension() {
        let obu = make_obu(6, Some(0b001_01_000), &[0x10, 0x20]);
        let out = roundtrip(&[obu.clone()], 1500);
        assert_eq!(out, vec![obu]);
    }

    #[test]
    fn roundtrip_seq_header_then_frame() {
        let seq = make_obu(OBU_SEQUENCE_HEADER, None, &[0x01, 0x02]);
        let frame = make_obu(6, None, &[0xAA; 50]);
        let out = roundtrip(&[seq.clone(), frame.clone()], 1500);
        assert_eq!(out, vec![seq, frame]);
    }

    #[test]
    fn roundtrip_drops_temporal_delimiter_and_tile_list() {
        let td = make_obu(OBU_TEMPORAL_DELIMITER, None, &[]);
        let tl = make_obu(OBU_TILE_LIST, None, &[0; 4]);
        let frame = make_obu(6, None, &[0xAA; 10]);
        let out = roundtrip(&[td, frame.clone(), tl], 1500);
        assert_eq!(out, vec![frame]);
    }

    #[test]
    fn roundtrip_large_obu_forces_fragmentation() {
        let payload: Vec<u8> = (0..2000u32).map(|i| (i & 0xFF) as u8).collect();
        let obu = make_obu(6, None, &payload);
        let out = roundtrip(&[obu.clone()], 100);
        assert_eq!(out, vec![obu]);
    }

    #[test]
    fn roundtrip_many_obus() {
        let mut obus = Vec::new();
        for i in 0..5u8 {
            obus.push(make_obu(6, None, &[i; 30]));
        }
        let out = roundtrip(&obus, 200);
        assert_eq!(out, obus);
    }

    #[test]
    fn roundtrip_large_obu_with_extension() {
        let payload: Vec<u8> = (0..1000u32).map(|i| (i & 0xFF) as u8).collect();
        let obu = make_obu(6, Some(0xAB), &payload);
        let out = roundtrip(&[obu.clone()], 80);
        assert_eq!(out, vec![obu]);
    }

    #[test]
    fn roundtrip_minimum_max_size() {
        let obu = make_obu(6, None, &[0x42]);
        let out = roundtrip(&[obu.clone()], MIN_PAYLOAD_MAX_SIZE);
        assert_eq!(out, vec![obu]);
    }
}
