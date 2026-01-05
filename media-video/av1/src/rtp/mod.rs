use std::{cmp, mem::take};

use bytes::Bytes;
use smallvec::{SmallVec, smallvec};

mod leb128;

const OBU_SEQUENCE_HEADER: u8 = 1;
const OBU_TEMPORAL_DELIMITER: u8 = 2;
// const OBU_FRAME_HEADER: u8 = 3;
// const OBU_TILE_GROUP: u8 = 4;
// const OBU_METADATA: u8 = 5;
// const OBU_FRAME: u8 = 6;
// const OBU_REDUNDANT_FRAME_HEADER: u8 = 7;
const OBU_TILE_LIST: u8 = 8;

// Reference https://aomediacodec.github.io/av1-rtp-spec/v1.0.0.html

// AV1 Aggregation Header
//  0 1 2 3 4 5 6 7
// +-+-+-+-+-+-+-+-+
// |Z|Y| W |N|-|-|-|
// +-+-+-+-+-+-+-+-+
// Z: MUST be set to 1 if the first OBU element is an OBU fragment that is a continuation of an OBU fragment from the previous packet,
//    and MUST be set to 0 otherwise.
// Y: MUST be set to 1 if the last OBU element is an OBU fragment that will continue in the next packet, and MUST be set to 0 otherwise.
// W: two bit field that describes the number of OBU elements in the packet.
//    This field MUST be set equal to 0 or equal to the number of OBU elements contained in the packet.
//    If set to 0, each OBU element MUST be preceded by a length field.
//    If not set to 0 (i.e., W = 1, 2 or 3) the last OBU element MUST NOT be preceded by a length field.
//    Instead, the length of the last OBU element contained in the packet can be calculated as follows:

//  open_bitstream_unit( sz ) {
//      obu_header()
//      if ( obu_has_size_field ) {
//          obu_sizeobu_size                        leb128()
//      } else {
//          obu_size = sz - 1 - obu_extension_flag
//      }
//   ...

// obu_header() {
//  obu_forbidden_bit   f(1)
//  obu_type            f(4)
//  obu_extension_flag  f(1)
//  obu_has_size_field  f(1)
//  obu_reserved_1bit   f(1)
//  if ( obu_extension_flag == 1 )
//      obu_extension_header()
// }

// obu_extension_header() {
//  temporal_id                     f(3)
//  spatial_id                      f(2)
//  extension_header_reserved_3bits f(3)
// }

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

pub struct AV1Payloader {
    _priv: (),
}

impl AV1Payloader {
    pub fn new() -> AV1Payloader {
        AV1Payloader { _priv: () }
    }

    pub fn payload(&mut self, mut to_payload: Bytes, max_size: usize) -> Vec<Vec<u8>> {
        let mut payloads = Vec::new();

        let mut current_payload = Vec::with_capacity(max_size);
        current_payload.push(0); // Aggregation header

        while !to_payload.is_empty() {
            let header_and_size = ObuHeaderAndSize::parse(&to_payload).unwrap();
            let mut obu_bytes = to_payload.split_to(header_and_size.size);

            if matches!(
                header_and_size.type_,
                OBU_TEMPORAL_DELIMITER | OBU_TILE_LIST
            ) {
                // drop
                continue;
            }

            if matches!(header_and_size.type_, OBU_SEQUENCE_HEADER) {
                // TODO: this is probably wrong. Currently always setting the N bit when encountering a SEQ header
                current_payload[0] |= 1 << 3;
            }

            // TODO: remove obu_size field from OBU
            // let new_header_len = 1 + header_and_size.extension.is_some() as usize;
            // let new_obu_len = (obu_bytes.len() - header_and_size.content_offset) + new_header_len;

            // let is_last_obu_in_packet = new_obu_len >= remaining_space;

            // packet.push(header_and_size.header());
            // if let Some(extension) = header_and_size.extension {
            //     packet.push(extension);
            // }

            while !obu_bytes.is_empty() {
                let remaining_space = max_size - current_payload.len();

                let obu_fragment_size = cmp::min(
                    remaining_space.saturating_sub(leb128::expected_size(remaining_space as u32)),
                    obu_bytes.len(),
                );

                if obu_fragment_size == 0 {
                    // mark fragment if the current obu is already partially in the current_payload
                    current_payload[0] |= ((obu_bytes.len() < header_and_size.size) as u8) << 6;

                    payloads.push(current_payload);

                    current_payload = Vec::with_capacity(max_size);
                    // the first OBU element is an OBU fragment that is a continuation of an OBU fragment from the previous packet
                    current_payload.push(1 << 7);

                    continue;
                }

                let to_write = obu_bytes.split_to(obu_fragment_size);
                leb128::write_leb128(&mut current_payload, to_write.len() as u32);

                current_payload.extend_from_slice(&to_write);

                if !obu_bytes.is_empty() {
                    // last OBU element is an OBU fragment that will continue in the next packet
                    current_payload[0] |= 1 << 6;

                    payloads.push(current_payload);

                    current_payload = Vec::with_capacity(max_size);
                    // the first OBU element is an OBU fragment that is a continuation of an OBU fragment from the previous packet
                    current_payload.push(1 << 7);
                }
            }
        }

        if current_payload.len() > 1 {
            payloads.push(current_payload);
        }

        payloads
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
            // Check if the OBU has a length prefix
            // If there's a obu count in the header then the last OBU has no length prefix
            let has_length = if let Some(remaining_obu) = &mut num_remaining_obus {
                *remaining_obu -= 1;
                *remaining_obu > 0
            } else {
                // No count specified, always a length prefix
                true
            };

            let (consumed, len) = if has_length {
                leb128::read_leb128(packet).ok_or(AV1DePayloadError::UnexpectedEndOfPacket)?
            } else {
                (0, packet.len() as u32)
            };

            if len == 0 {
                return Err(AV1DePayloadError::ZeroLengthOBU);
            }

            let (obu_bytes, remaining) = packet[consumed..]
                .split_at_checked(len as usize)
                .ok_or(AV1DePayloadError::UnexpectedEndOfPacket)?;

            packet = remaining;

            if continues_fragment {
                continues_fragment = false;

                if self.current_obu.is_empty() {
                    // Continued fragment but there isn't anything in current_obu, probably packet loss, ignore it
                    continue;
                }

                self.current_obu.extend_from_slice(obu_bytes);

                // When contains_fragment is set for the packet is set and `packet` contains no more bytes to consume, consider this fragmented OBU as complete
                if !contains_fragment && packet.is_empty() {
                    obus.push(take(&mut self.current_obu));
                }
            } else if packet.is_empty() && contains_fragment {
                self.current_obu.extend_from_slice(obu_bytes);
            } else {
                obus.push(obu_bytes.to_vec());
            }

            // Cap the maximum OBU size somewhere to avoid allocating infinite memory
            if self.current_obu.len() > 100_000_000 {
                self.current_obu = Vec::new();
                return Err(AV1DePayloadError::FragmentedObuTooLarge);
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
