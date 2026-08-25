use crate::SrtpError;

/// Length of the fixed RTP header (RFC 3550 section 5.1)
pub(crate) const RTP_HEADER_LEN: usize = 12;

/// Length of the fixed RTCP header up to and including the sender SSRC, which is the part
/// SRTCP leaves in the clear (RFC 3711 section 3.4)
pub(crate) const RTCP_HEADER_LEN: usize = 8;

/// The parts of an RTP header that SRTP needs
pub(crate) struct RtpHeader {
    /// Length of the header including CSRC list and header extension, i.e. the start of
    /// the encrypted portion and the length of the AEAD associated data
    pub(crate) payload_offset: usize,
    pub(crate) seq: u16,
    pub(crate) ssrc: u32,
}

pub(crate) fn parse_rtp(pkt: &[u8]) -> Result<RtpHeader, SrtpError> {
    if pkt.len() < RTP_HEADER_LEN {
        return Err(SrtpError::PacketTooShort);
    }

    let csrc_count = usize::from(pkt[0] & 0x0f);
    let has_extension = pkt[0] & 0x10 != 0;

    let seq = u16::from_be_bytes([pkt[2], pkt[3]]);
    let ssrc = u32::from_be_bytes([pkt[8], pkt[9], pkt[10], pkt[11]]);

    let mut payload_offset = RTP_HEADER_LEN + csrc_count * 4;

    if has_extension {
        // 16 bit profile identifier, 16 bit length in 32 bit words, then the extension
        let header_end = payload_offset
            .checked_add(4)
            .ok_or(SrtpError::MalformedPacket)?;

        if pkt.len() < header_end {
            return Err(SrtpError::MalformedPacket);
        }

        let words = usize::from(u16::from_be_bytes([
            pkt[payload_offset + 2],
            pkt[payload_offset + 3],
        ]));

        payload_offset = header_end
            .checked_add(words * 4)
            .ok_or(SrtpError::MalformedPacket)?;
    }

    if pkt.len() < payload_offset {
        return Err(SrtpError::MalformedPacket);
    }

    Ok(RtpHeader {
        payload_offset,
        seq,
        ssrc,
    })
}

pub(crate) fn parse_rtcp_ssrc(pkt: &[u8]) -> Result<u32, SrtpError> {
    if pkt.len() < RTCP_HEADER_LEN {
        return Err(SrtpError::PacketTooShort);
    }

    Ok(u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]))
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn plain_header() {
        let pkt = [
            0x80, 0x60, 0x12, 0x34, 0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef, 1, 2, 3,
        ];
        let hdr = parse_rtp(&pkt).unwrap();

        assert_eq!(hdr.payload_offset, 12);
        assert_eq!(hdr.seq, 0x1234);
        assert_eq!(hdr.ssrc, 0xdeadbeef);
    }

    #[test]
    fn csrc_list_and_extension_are_part_of_the_header() {
        // 2 CSRCs and a one word header extension
        let mut pkt = vec![0x92, 0x60, 0x00, 0x01];
        pkt.extend_from_slice(&[0; 4]); // timestamp
        pkt.extend_from_slice(&[0; 4]); // ssrc
        pkt.extend_from_slice(&[0; 8]); // 2 CSRCs
        pkt.extend_from_slice(&[0xbe, 0xde, 0x00, 0x01]); // extension header, 1 word
        pkt.extend_from_slice(&[0; 4]); // extension body
        pkt.extend_from_slice(&[1, 2, 3]); // payload

        let hdr = parse_rtp(&pkt).unwrap();
        assert_eq!(hdr.payload_offset, 12 + 8 + 4 + 4);
    }

    #[test]
    fn rejects_short_and_lying_headers() {
        assert_eq!(
            parse_rtp(&[0x80; 11]).err(),
            Some(SrtpError::PacketTooShort)
        );

        // Claims 4 CSRCs but only carries the fixed header
        assert_eq!(
            parse_rtp(&[0x84, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).err(),
            Some(SrtpError::MalformedPacket)
        );

        // Extension bit set but no room for the extension header
        assert_eq!(
            parse_rtp(&[0x90, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).err(),
            Some(SrtpError::MalformedPacket)
        );

        // Extension header claims 100 words that are not there
        assert_eq!(
            parse_rtp(&[0x90, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xbe, 0xde, 0, 100]).err(),
            Some(SrtpError::MalformedPacket)
        );
    }

    #[test]
    fn rtcp_ssrc() {
        assert_eq!(
            parse_rtcp_ssrc(&[0x81, 0xc8, 0, 1, 0xde, 0xad, 0xbe, 0xef]),
            Ok(0xdeadbeef)
        );
        assert_eq!(
            parse_rtcp_ssrc(&[0x81, 0xc8, 0, 1]).err(),
            Some(SrtpError::PacketTooShort)
        );
    }
}
