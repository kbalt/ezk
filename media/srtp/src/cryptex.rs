//! [RFC 9335]: https://www.rfc-editor.org/rfc/rfc9335

use crate::SrtpError;
use crate::packet::{RTP_EXT_HEADER_LEN, RTP_HEADER_LEN, RtpHeader};

const ONE_BYTE_PROFILE: u16 = 0xbede;
const TWO_BYTE_PROFILE: u16 = 0x1000;

const CRYPTEX_ONE_BYTE_PROFILE: u16 = 0xc0de;
const CRYPTEX_TWO_BYTE_PROFILE: u16 = 0xc2de;

/// Start of the encrypted portion in cipher order
pub(crate) const ENC_START: usize = RTP_HEADER_LEN + RTP_EXT_HEADER_LEN;

pub(crate) fn profile_to_cryptex_profile(header: &RtpHeader) -> Result<Option<u16>, SrtpError> {
    let Some(profile) = header.extension_profile else {
        // TODO: if theres CSRC entries but no extension an empty extension must be added
        if header.csrc_count > 0 {
            return Err(SrtpError::CryptexNeedsExtension);
        }

        return Ok(None);
    };

    match profile {
        ONE_BYTE_PROFILE => Ok(Some(CRYPTEX_ONE_BYTE_PROFILE)),
        TWO_BYTE_PROFILE => Ok(Some(CRYPTEX_TWO_BYTE_PROFILE)),
        _ => Err(SrtpError::CryptexUnsupportedExtension),
    }
}

pub(crate) fn cryptex_profile_to_profile(
    header: &RtpHeader,
    required: bool,
) -> Result<Option<u16>, SrtpError> {
    match header.extension_profile {
        Some(CRYPTEX_ONE_BYTE_PROFILE) => Ok(Some(ONE_BYTE_PROFILE)),
        Some(CRYPTEX_TWO_BYTE_PROFILE) => Ok(Some(TWO_BYTE_PROFILE)),
        Some(_) if required => Err(SrtpError::CryptexRequired),
        Some(_) => Ok(None),
        None if required && header.csrc_count > 0 => Err(SrtpError::CryptexRequired),
        None => Ok(None),
    }
}

/// Overwrite the "defined by profile" field
///
/// Call before [`to_cipher_order`] or after [`to_wire_order`]
pub(crate) fn set_extension_profile(buf: &mut [u8], csrc_count: usize, profile: u16) {
    let at = RTP_HEADER_LEN + csrc_count * 4;
    buf[at..at + 2].copy_from_slice(&profile.to_be_bytes());
}

/// Move the extension header in front of the CSRC list
///
/// Produces the intermediate form of RFC 9335 section 6.2 figure 2, where the associated
/// data and the plaintext are contiguous and the latter starts at [`ENC_START`].
///
/// # Panics
///
/// As [`set_extension_profile`].
pub(crate) fn to_cipher_order(buf: &mut [u8], csrc_count: usize) {
    if csrc_count == 0 {
        return;
    }

    let csrc_at = RTP_HEADER_LEN;
    let ext_at = csrc_at + csrc_count * 4;

    let mut ext_header = [0u8; RTP_EXT_HEADER_LEN];
    ext_header.copy_from_slice(&buf[ext_at..ext_at + RTP_EXT_HEADER_LEN]);
    buf.copy_within(csrc_at..ext_at, csrc_at + RTP_EXT_HEADER_LEN);
    buf[csrc_at..csrc_at + RTP_EXT_HEADER_LEN].copy_from_slice(&ext_header);
}

/// Undo [`to_cipher_order`]
pub(crate) fn to_wire_order(buf: &mut [u8], csrc_count: usize) {
    if csrc_count == 0 {
        return;
    }

    let csrc_at = RTP_HEADER_LEN;
    let ext_at = csrc_at + csrc_count * 4;

    let mut ext_header = [0u8; RTP_EXT_HEADER_LEN];
    ext_header.copy_from_slice(&buf[csrc_at..csrc_at + RTP_EXT_HEADER_LEN]);
    buf.copy_within(
        csrc_at + RTP_EXT_HEADER_LEN..ext_at + RTP_EXT_HEADER_LEN,
        csrc_at,
    );
    buf[ext_at..ext_at + RTP_EXT_HEADER_LEN].copy_from_slice(&ext_header);
}

#[cfg(test)]
mod test {
    use super::*;

    fn packet(cc: usize, profile: u16) -> Vec<u8> {
        let mut pkt = vec![0x90 | cc as u8, 0x60, 0x12, 0x34];
        pkt.extend_from_slice(&[0; 4]); // timestamp
        pkt.extend_from_slice(&[0; 4]); // ssrc
        for i in 0..cc {
            pkt.extend_from_slice(&[0xc0 | i as u8; 4]);
        }
        pkt.extend_from_slice(&profile.to_be_bytes());
        pkt.extend_from_slice(&[0x00, 0x01]); // one word of extension data
        pkt.extend_from_slice(&[0xe0, 0xe1, 0xe2, 0xe3]);
        pkt.extend_from_slice(&[0xaa; 4]);
        pkt
    }

    fn header(pkt: &[u8]) -> RtpHeader {
        crate::packet::parse_rtp(pkt).unwrap()
    }

    #[test]
    fn the_swap_round_trips_for_every_csrc_count() {
        for cc in 0..=15 {
            let original = packet(cc, ONE_BYTE_PROFILE);

            let mut buf = original.clone();
            to_cipher_order(&mut buf, cc);
            if cc > 0 {
                assert_ne!(buf, original, "{cc} csrcs, swap did nothing");
            }

            to_wire_order(&mut buf, cc);
            assert_eq!(buf, original, "{cc} csrcs");
        }
    }

    #[test]
    fn cipher_order_puts_the_extension_header_after_the_fixed_header() {
        let mut buf = packet(2, ONE_BYTE_PROFILE);
        to_cipher_order(&mut buf, 2);

        assert_eq!(
            &buf[..RTP_HEADER_LEN],
            &packet(2, ONE_BYTE_PROFILE)[..RTP_HEADER_LEN]
        );
        assert_eq!(&buf[12..16], &[0xbe, 0xde, 0x00, 0x01]);
        assert_eq!(&buf[16..20], &[0xc0; 4]);
        assert_eq!(&buf[20..24], &[0xc1; 4]);
    }

    #[test]
    fn only_the_two_rfc8285_forms_have_a_cryptex_counterpart() {
        let one = packet(0, ONE_BYTE_PROFILE);
        assert_eq!(
            profile_to_cryptex_profile(&header(&one)),
            Ok(Some(CRYPTEX_ONE_BYTE_PROFILE))
        );

        let two = packet(0, TWO_BYTE_PROFILE);
        assert_eq!(
            profile_to_cryptex_profile(&header(&two)),
            Ok(Some(CRYPTEX_TWO_BYTE_PROFILE))
        );

        for appbits in 1..=0xF {
            let pkt = packet(0, TWO_BYTE_PROFILE | appbits);
            assert_eq!(
                profile_to_cryptex_profile(&header(&pkt)),
                Err(SrtpError::CryptexUnsupportedExtension),
                "appbits {appbits:#x}"
            );
        }

        let other = packet(0, 0xabcd);
        assert_eq!(
            profile_to_cryptex_profile(&header(&other)),
            Err(SrtpError::CryptexUnsupportedExtension)
        );
    }

    #[test]
    fn a_sender_refuses_csrcs_without_a_header_extension() {
        // 2 csrcs, X clear
        let pkt = vec![
            0x82, 0x60, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 0xaa,
        ];

        assert_eq!(
            profile_to_cryptex_profile(&header(&pkt)),
            Err(SrtpError::CryptexNeedsExtension)
        );
    }

    #[test]
    fn a_bare_packet_is_sent_as_plain_srtp() {
        let pkt = vec![0x80, 0x60, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa];
        assert_eq!(profile_to_cryptex_profile(&header(&pkt)), Ok(None));
    }

    #[test]
    fn a_receiver_detects_cryptex_from_the_tag_alone() {
        let one = packet(2, CRYPTEX_ONE_BYTE_PROFILE);
        assert_eq!(
            cryptex_profile_to_profile(&header(&one), false),
            Ok(Some(ONE_BYTE_PROFILE))
        );

        let two = packet(2, CRYPTEX_TWO_BYTE_PROFILE);
        assert_eq!(
            cryptex_profile_to_profile(&header(&two), false),
            Ok(Some(TWO_BYTE_PROFILE))
        );

        let plain = packet(2, ONE_BYTE_PROFILE);
        assert_eq!(cryptex_profile_to_profile(&header(&plain), false), Ok(None));
    }

    #[test]
    fn strict_mode_rejects_plain_extensions_and_bare_csrcs() {
        let plain = packet(0, ONE_BYTE_PROFILE);
        assert_eq!(
            cryptex_profile_to_profile(&header(&plain), true),
            Err(SrtpError::CryptexRequired)
        );

        let csrcs = vec![
            0x82, 0x60, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 0xaa,
        ];
        assert_eq!(
            cryptex_profile_to_profile(&header(&csrcs), true),
            Err(SrtpError::CryptexRequired)
        );

        // Nothing to protect, still accepted
        let bare = vec![0x80, 0x60, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0, 0, 0xaa];
        assert_eq!(cryptex_profile_to_profile(&header(&bare), true), Ok(None));

        let cryptex = packet(2, CRYPTEX_ONE_BYTE_PROFILE);
        assert_eq!(
            cryptex_profile_to_profile(&header(&cryptex), true),
            Ok(Some(ONE_BYTE_PROFILE))
        );
    }

    #[test]
    fn the_extension_profile_is_rewritten_in_place() {
        let mut buf = packet(2, ONE_BYTE_PROFILE);
        set_extension_profile(&mut buf, 2, CRYPTEX_ONE_BYTE_PROFILE);

        assert_eq!(&buf[20..24], &[0xc0, 0xde, 0x00, 0x01]);
    }
}
