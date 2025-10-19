use crate::H264PacketizationMode;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::{iter::from_fn, mem::take};

const NAL_UNIT_HEADER_NRI_MASK: u8 = 0b01100000;
const NAL_UNIT_HEADER_TYPE_MASK: u8 = 0b00011111;

const NAL_UNIT_IDR: u8 = 5;
const NAL_UNIT_SPS: u8 = 7;
const NAL_UNIT_PPS: u8 = 8;

// Access Unit Delimiter, discarding
const NAL_UNIT_AUD: u8 = 9;
// Supplemental Enhancement Information, discarding
const NAL_UNIT_SEI: u8 = 12;

/// Aggregation packet types
const NAL_UNIT_STAP_A: u8 = 24;

/// Fragmentation packet types
const NAL_UNIT_FU_A: u8 = 28;

const FUA_HEADER_LEN: usize = 2;
const FUA_END_BIT: u8 = 1 << 6;
const FUA_START_BIT: u8 = 1 << 7;

/// Convert H.264 NAL unit as received from encoders or found in media formats to RTP payload format
pub struct H264Payloader {
    mode: H264PacketizationMode,
    sps: Option<Bytes>,
    pps: Option<Bytes>,
}

impl H264Payloader {
    pub fn new(mode: H264PacketizationMode) -> Self {
        Self {
            mode,
            sps: None,
            pps: None,
        }
    }

    pub fn payload(&mut self, bytes: Bytes, max_size: usize) -> Vec<Bytes> {
        if bytes.is_empty() {
            return vec![];
        }

        if self.mode == H264PacketizationMode::SingleNAL {
            return nal_units(bytes).collect();
        }

        let mut ret = vec![];

        for nal_unit in nal_units(bytes) {
            self.payload_nal_unit(nal_unit, max_size, &mut ret);
        }

        ret
    }

    fn payload_nal_unit(&mut self, mut nal_unit: Bytes, max_size: usize, ret: &mut Vec<Bytes>) {
        if nal_unit.is_empty() || max_size == 0 {
            return;
        }

        let nal_unit_type = nal_unit[0] & NAL_UNIT_HEADER_TYPE_MASK;
        let nal_unit_ref_idc = nal_unit[0] & NAL_UNIT_HEADER_NRI_MASK;

        match nal_unit_type {
            NAL_UNIT_AUD | NAL_UNIT_SEI => {
                // These are just additional information - nice to have, not required for playback
                // discarding to save on bandwidth
                return;
            }
            NAL_UNIT_SPS => {
                // Store for later so it can be combined into a STAP-A package together with PPS
                self.sps = Some(nal_unit);
                return;
            }
            NAL_UNIT_PPS => {
                // Store for later so it can be combined into a STAP-A package together with SPS
                self.pps = Some(nal_unit);
                return;
            }
            _ => {}
        }

        if let (Some(sps), Some(pps)) = (&self.sps, &self.pps) {
            // Got bot a SPS and PPS NAL unit. Sent it out inside a STAP-A package.
            let stap_a_len = 1 + 2 + sps.len() + 2 + pps.len();

            if stap_a_len <= max_size {
                let mut stap_a: Vec<u8> = Vec::with_capacity(stap_a_len);
                stap_a.push(0x78); // STAP-A header

                stap_a.put_u16(sps.len() as u16);
                stap_a.put_slice(sps);

                stap_a.put_u16(pps.len() as u16);
                stap_a.put_slice(pps);

                ret.push(stap_a.into());
            } else {
                ret.push(sps.clone());
                ret.push(pps.clone());
            }

            self.pps = None;
            self.sps = None;
        }

        if nal_unit.len() <= max_size {
            ret.push(nal_unit);
            return;
        }

        // NAL unit too large, use fragmentation unit FU-A
        let max_size = max_size.max(3); // FU-A requires at least 3 bytes

        // Discard first byte
        nal_unit.advance(1);

        let chunk_size = max_size - FUA_HEADER_LEN;
        let mut chunks = nal_unit[..].chunks(chunk_size).enumerate().peekable();
        while let Some((i, chunk)) = chunks.next() {
            let mut fua = Vec::with_capacity(chunk.len() + FUA_HEADER_LEN);

            fua.push(NAL_UNIT_FU_A | nal_unit_ref_idc);

            if i == 0 {
                fua.push(nal_unit_type | FUA_START_BIT)
            } else if chunks.peek().is_none() {
                fua.push(nal_unit_type | FUA_END_BIT)
            } else {
                fua.push(nal_unit_type);
            }

            fua.put_slice(chunk);
            ret.push(fua.into());
        }
    }
}

fn next_nal_prefix(nal_unit: &[u8]) -> Option<(usize, usize)> {
    let mut zero_count = 0;
    for (index, byte) in nal_unit.iter().enumerate() {
        if *byte == 0 {
            zero_count += 1;
        } else if *byte == 1 && zero_count >= 2 {
            let prefix_length = zero_count + 1;
            let nal_unit_end = index - zero_count;

            return Some((prefix_length, nal_unit_end));
        } else {
            zero_count = 0;
        }
    }

    None
}

fn nal_units(mut bytes: Bytes) -> impl Iterator<Item = Bytes> {
    from_fn(move || {
        while !bytes.is_empty() {
            let (prefix_length, nal_unit_end) = match next_nal_prefix(&bytes) {
                Some(v) => v,
                None => return Some(take(&mut bytes)),
            };

            let ret = bytes.split_to(nal_unit_end);
            bytes.advance(prefix_length);

            if !ret.is_empty() {
                return Some(ret);
            }
        }

        None
    })
}

/// Convert RTP packet payload back to H.264 NAL units to be consumed by decoders or other media formats
pub struct H264DePayloader {
    format: H264DePayloaderOutputFormat,
    fua: Option<BytesMut>,
}

/// Output format for the [`H264DePayloader`]
#[derive(Debug, Default)]
pub enum H264DePayloaderOutputFormat {
    /// Prefix NAL units with the Annex B start code (0x00, 0x00, 0x00, 0x01)
    #[default]
    AnnexB,
    /// Prefix NAL units with the length of the NAL unit (4 bytes)
    Avc,
}

impl H264DePayloaderOutputFormat {
    fn write_prefix(&self, packet_len: usize, out: &mut impl BufMut) {
        const ANNEXB_NAL_UNIT_START_CODE: [u8; 4] = [0, 0, 0, 1];

        match self {
            H264DePayloaderOutputFormat::AnnexB => out.put_slice(&ANNEXB_NAL_UNIT_START_CODE),
            H264DePayloaderOutputFormat::Avc => out.put_u32(packet_len as u32),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum H264DePayloadError {
    #[error("packet is empty")]
    EmptyPacket,
    #[error("STAP-A packet contained invalid length")]
    InvalidStapALength,
    #[error("FU-A packet contained invalid length")]
    InvalidFuALength,
    #[error("got unexpected NAL unit type {0}")]
    UnknownNalUnitType(u8),
}

impl H264DePayloader {
    pub fn new(format: H264DePayloaderOutputFormat) -> Self {
        Self { format, fua: None }
    }

    pub fn reset(&mut self) {
        self.fua = None;
    }

    pub fn depayload(
        &mut self,
        packet: &[u8],
        mut out: impl BufMut,
        mut is_keyframe: Option<&mut bool>,
    ) -> Result<(), H264DePayloadError> {
        if packet.is_empty() {
            return Err(H264DePayloadError::EmptyPacket);
        }

        let b0 = packet[0];
        let nal_unit_type = b0 & NAL_UNIT_HEADER_TYPE_MASK;

        match nal_unit_type {
            1..=23 => {
                if let Some(is_keyframe) = is_keyframe {
                    *is_keyframe |= nal_unit_type == NAL_UNIT_IDR
                };

                self.format.write_prefix(packet.len(), &mut out);
                out.put_slice(packet);
                Ok(())
            }
            NAL_UNIT_STAP_A => {
                let mut stap_a_payload = &packet[1..];

                while stap_a_payload.len() > 2 {
                    let len = usize::from(stap_a_payload.get_u16());
                    if stap_a_payload.len() < len {
                        return Err(H264DePayloadError::InvalidStapALength);
                    }

                    let (packet, remaining) = stap_a_payload.split_at(len);
                    stap_a_payload = remaining;

                    let b0 = packet[0];
                    if let Some(is_keyframe) = is_keyframe.take() {
                        let nal_unit_type = b0 & NAL_UNIT_HEADER_TYPE_MASK;
                        *is_keyframe |= nal_unit_type == NAL_UNIT_IDR
                    };
                    self.format.write_prefix(packet.len(), &mut out);
                    out.put_slice(packet);
                }

                Ok(())
            }
            NAL_UNIT_FU_A => {
                if packet.len() < FUA_HEADER_LEN {
                    return Err(H264DePayloadError::InvalidFuALength);
                }

                let fua = self.fua.get_or_insert_with(BytesMut::new);

                let b1 = packet[1];

                // Check if this is the first FU-A package
                if b1 & FUA_START_BIT != 0 {
                    fua.clear();
                }

                // Append the received package to the FU-A buffer
                fua.extend_from_slice(&packet[FUA_HEADER_LEN..]);

                // Check if this is the last FU-A package
                if b1 & FUA_END_BIT == 0 {
                    return Ok(());
                }

                let nal_unit_ref_idc = b0 & NAL_UNIT_HEADER_NRI_MASK;
                let fragmented_nal_unit_type = b1 & NAL_UNIT_HEADER_TYPE_MASK;

                if let Some(is_keyframe) = is_keyframe {
                    *is_keyframe |= fragmented_nal_unit_type == NAL_UNIT_IDR
                };

                let fua = self.fua.take().expect("just set the FU-A buffer");
                self.format.write_prefix(fua.len() + 1, &mut out);
                out.put_u8(nal_unit_ref_idc | fragmented_nal_unit_type);
                out.put(fua);

                Ok(())
            }
            _ => Err(H264DePayloadError::UnknownNalUnitType(nal_unit_type)),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    // Test adapted from https://github.com/algesten/str0m/blob/59f693258559eeee6b35dc42afc151ef1ea41907/src/packet/h264.rs#L350

    #[test]
    fn test_h264_payload() {
        let empty = Bytes::from_static(&[]);
        let small_payload = Bytes::from_static(&[0x90, 0x90, 0x90]);
        let multiple_payload =
            Bytes::from_static(&[0x00, 0x00, 0x01, 0x90, 0x00, 0x00, 0x01, 0x90]);
        let large_payload = Bytes::from_static(&[
            0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15,
        ]);
        let large_payload_packetized: Vec<&[u8]> = vec![
            &[0x1c, 0x80, 0x01, 0x02, 0x03],
            &[0x1c, 0x00, 0x04, 0x05, 0x06],
            &[0x1c, 0x00, 0x07, 0x08, 0x09],
            &[0x1c, 0x00, 0x10, 0x11, 0x12],
            &[0x1c, 0x40, 0x13, 0x14, 0x15],
        ];

        let mut pck = H264Payloader::new(H264PacketizationMode::NonInterleavedMode);

        // Positive MTU, empty payload
        let result = pck.payload(empty, 1);
        assert!(result.is_empty(), "Generated payload should be empty");

        // 0 MTU, small payload
        let result = pck.payload(small_payload.clone(), 0);
        assert_eq!(result.len(), 0, "Generated payload should be empty");

        // Positive MTU, small payload
        let result = pck.payload(small_payload.clone(), 5);
        assert_eq!(result.len(), 1, "Generated payload should be the 1");
        assert_eq!(
            result[0].len(),
            small_payload.len(),
            "Generated payload should be the same size as original payload size"
        );

        // Multiple NAL units in a single payload
        let result = pck.payload(multiple_payload, 5);
        assert_eq!(result.len(), 2, "2 nal units should be broken out");
        for (i, p) in result.into_iter().enumerate() {
            assert_eq!(p.len(), 1, "Payload {} of 2 is packed incorrectly", i + 1,);
        }

        // Large Payload split across multiple RTP Packets
        let result = pck.payload(large_payload, 5);
        assert_eq!(
            result.iter().map(|e| &e[..]).collect::<Vec<_>>(),
            large_payload_packetized,
            "FU-A packetization failed"
        );

        // Test that AUD(type=9) and SEI(type=12) are discarded
        let small_payload2 = Bytes::from_static(&[0x09, 0x00, 0x00]);
        let result = pck.payload(small_payload2, 5);
        assert_eq!(result.len(), 0, "Generated payload should be empty");
    }

    #[test]
    fn single_payload() {
        let mut pkt = H264DePayloader::new(H264DePayloaderOutputFormat::AnnexB);
        let mut out: Vec<u8> = Vec::new();
        let single_payload = &[0x90, 0x90, 0x90];
        pkt.depayload(single_payload, &mut out, None).unwrap();
        let single_payload_unmarshaled = &[0x00, 0x00, 0x00, 0x01, 0x90, 0x90, 0x90];
        assert_eq!(
            out, single_payload_unmarshaled,
            "depayloading a single payload shouldn't modify the payload"
        );
    }

    #[test]
    fn single_payload_avc() {
        let mut pkt = H264DePayloader::new(H264DePayloaderOutputFormat::Avc);
        let mut out: Vec<u8> = Vec::new();
        let single_payload = &[0x90, 0x90, 0x90];
        pkt.depayload(single_payload, &mut out, None).unwrap();
        let single_payload_unmarshaled_avc = &[0x00, 0x00, 0x00, 0x03, 0x90, 0x90, 0x90];
        assert_eq!(
            out, single_payload_unmarshaled_avc,
            "depayloading a single payload into avc stream shouldn't modify the payload"
        );
    }

    #[test]
    fn h264_large_out() {
        let large_payload_packetized = vec![
            &[0x1c, 0x80, 0x01, 0x02, 0x03],
            &[0x1c, 0x00, 0x04, 0x05, 0x06],
            &[0x1c, 0x00, 0x07, 0x08, 0x09],
            &[0x1c, 0x00, 0x10, 0x11, 0x12],
            &[0x1c, 0x40, 0x13, 0x14, 0x15],
        ];

        let large_payload = &[
            0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        ];

        let mut pkt = H264DePayloader::new(H264DePayloaderOutputFormat::AnnexB);

        let mut large_out = Vec::new();
        for p in &large_payload_packetized {
            pkt.depayload(*p, &mut large_out, None).unwrap();
        }
        assert_eq!(
            large_out, large_payload,
            "Failed to depayload a large payload"
        );
    }

    #[test]
    fn h264_large_out_avc() {
        let large_payload_packetized = vec![
            &[0x1c, 0x80, 0x01, 0x02, 0x03],
            &[0x1c, 0x00, 0x04, 0x05, 0x06],
            &[0x1c, 0x00, 0x07, 0x08, 0x09],
            &[0x1c, 0x00, 0x10, 0x11, 0x12],
            &[0x1c, 0x40, 0x13, 0x14, 0x15],
        ];

        let large_payload_avc = &[
            0x00, 0x00, 0x00, 0x10, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
        ];

        let mut avc_pkt = H264DePayloader::new(H264DePayloaderOutputFormat::Avc);

        let mut large_out_avc = Vec::new();
        for p in &large_payload_packetized {
            avc_pkt.depayload(*p, &mut large_out_avc, None).unwrap();
        }
        assert_eq!(
            large_out_avc, large_payload_avc,
            "Failed to depayload a large payload into avc stream"
        );
    }

    #[test]
    fn single_payload_multi_nalu() {
        let single_payload_multi_nalu = &[
            0x78, 0x00, 0x0f, 0x67, 0x42, 0xc0, 0x1f, 0x1a, 0x32, 0x35, 0x01, 0x40, 0x7a, 0x40,
            0x3c, 0x22, 0x11, 0xa8, 0x00, 0x05, 0x68, 0x1a, 0x34, 0xe3, 0xc8, 0x00,
        ];
        let single_payload_multi_nalu_unmarshaled = &[
            0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0xc0, 0x1f, 0x1a, 0x32, 0x35, 0x01, 0x40, 0x7a,
            0x40, 0x3c, 0x22, 0x11, 0xa8, 0x00, 0x00, 0x00, 0x01, 0x68, 0x1a, 0x34, 0xe3, 0xc8,
        ];

        let mut pkt = H264DePayloader::new(H264DePayloaderOutputFormat::AnnexB);

        let mut out = Vec::new();
        pkt.depayload(single_payload_multi_nalu, &mut out, None)
            .unwrap();
        assert_eq!(
            out, single_payload_multi_nalu_unmarshaled,
            "Failed to unmarshal a single packet with multiple NALUs"
        );
    }

    #[test]
    fn single_payload_multi_nalu_avc() {
        let single_payload_multi_nalu = &[
            0x78, 0x00, 0x0f, 0x67, 0x42, 0xc0, 0x1f, 0x1a, 0x32, 0x35, 0x01, 0x40, 0x7a, 0x40,
            0x3c, 0x22, 0x11, 0xa8, 0x00, 0x05, 0x68, 0x1a, 0x34, 0xe3, 0xc8, 0x00,
        ];
        let single_payload_multi_nalu_unmarshaled_avc = &[
            0x00, 0x00, 0x00, 0x0f, 0x67, 0x42, 0xc0, 0x1f, 0x1a, 0x32, 0x35, 0x01, 0x40, 0x7a,
            0x40, 0x3c, 0x22, 0x11, 0xa8, 0x00, 0x00, 0x00, 0x05, 0x68, 0x1a, 0x34, 0xe3, 0xc8,
        ];

        let mut pkt = H264DePayloader::new(H264DePayloaderOutputFormat::Avc);

        let mut out = Vec::new();
        pkt.depayload(single_payload_multi_nalu, &mut out, None)
            .unwrap();
        assert_eq!(
            out, single_payload_multi_nalu_unmarshaled_avc,
            "Failed to unmarshal a single packet with multiple NALUs into avc stream"
        );
    }

    #[test]
    fn test_h264_packetizer_payload_sps_and_pps_handling() {
        let mut pck = H264Payloader::new(H264PacketizationMode::NonInterleavedMode);
        let expected: Vec<&[u8]> = vec![
            &[
                0x78, 0x00, 0x03, 0x07, 0x00, 0x01, 0x00, 0x03, 0x08, 0x02, 0x03,
            ],
            &[0x05, 0x04, 0x05],
        ];

        // When packetizing SPS and PPS are emitted with following NALU
        let res = pck.payload(Bytes::from_static(&[0x07, 0x00, 0x01]), 1500);
        assert!(res.is_empty(), "Generated payload should be empty");

        let res = pck.payload(Bytes::from_static(&[0x08, 0x02, 0x03]), 1500);
        assert!(res.is_empty(), "Generated payload should be empty");

        let actual = pck.payload(Bytes::from_static(&[0x05, 0x04, 0x05]), 1500);
        assert_eq!(
            actual.iter().map(|e| &e[..]).collect::<Vec<_>>(),
            expected,
            "SPS and PPS aren't packed together"
        );
    }

    #[test]
    fn parse_first_packet() {
        #[allow(clippy::zero_prefixed_literal)]
        const PACKET: &[u8] = &[
            120, 000, 015, 103, 066, 192, 021, 140, 141, 064, 160, 203, 207, 000, 240, 136, 070,
            160, 000, 004, 104, 206, 060, 128, 000, 204, 101, 184, 000, 004, 000, 000, 005, 057,
            049, 064, 000, 064, 222, 078, 078, 078, 078, 078, 078, 078, 078, 078, 078, 078, 078,
            078, 078, 078, 078, 078, 078, 078, 186, 235, 174, 186, 235, 174, 186, 235, 174, 186,
            235, 174, 186, 235, 174, 186, 235, 174, 186, 235, 174, 186, 235, 174, 186, 235, 174,
            186, 235, 174, 186, 235, 174, 186, 235, 174, 186, 235, 173, 223, 039, 125, 247, 223,
            125, 245, 215, 093, 117, 215, 093, 117, 214, 239, 174, 187, 235, 174, 186, 235, 174,
            186, 235, 174, 186, 235, 174, 186, 235, 174, 186, 235, 174, 186, 235, 174, 186, 235,
            174, 186, 235, 174, 183, 093, 117, 215, 093, 117, 215, 093, 117, 215, 093, 117, 215,
            093, 117, 215, 093, 117, 215, 092, 189, 117, 215, 093, 117, 215, 093, 117, 215, 093,
            117, 215, 093, 117, 215, 093, 117, 215, 093, 117, 214, 239, 190, 251, 239, 190, 186,
            235, 174, 186, 235, 174, 186, 235, 174, 186, 235, 174, 186, 235, 174, 186, 235, 174,
            186, 235, 174, 186, 235, 175, 227, 255, 240, 247, 021, 223, 125, 247, 223, 125, 247,
            223, 125, 247, 223, 125, 247, 223, 125, 248,
        ];

        let mut pck = H264DePayloader::new(H264DePayloaderOutputFormat::AnnexB);
        let mut out = vec![];
        pck.depayload(PACKET, &mut out, None).unwrap();
    }
}
