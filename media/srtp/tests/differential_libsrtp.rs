//! Differential tests against libsrtp, the reference implementation.
//!
//! These assert that `ezk-srtp` produces byte identical output to `ezk-libsrtp` for every
//! supported profile, and that each implementation can unprotect what the other
//! protected. Together with the round trip tests this is the strongest correctness signal
//! available short of a formal proof: libsrtp is what essentially every peer on the other
//! end of a WebRTC or SIP call runs.

use ezk_srtp::{SrtpKeys, SrtpProfile, SrtpProtector, SrtpUnprotector};
use libsrtp::{CryptoPolicy, SrtpPolicy, SrtpSession, Ssrc};
use std::borrow::Cow;

const SSRC: u32 = 0xcafe_d00d;

/// Map a profile to the pair of libsrtp crypto policies it corresponds to.
///
/// Note the asymmetry for the `_32` suites: RFC 4568 section 6.2.1 and RFC 6188 sections
/// 2.2 and 3.2 truncate the tag to 32 bits for RTP only, RTCP keeps the full 80 bits.
/// libsrtp leaves that to the caller, so the RTCP policy here is the `_80` variant.
fn libsrtp_policies(profile: SrtpProfile) -> (CryptoPolicy, CryptoPolicy) {
    match profile {
        SrtpProfile::AES_CM_128_HMAC_SHA1_80 => (
            CryptoPolicy::aes_cm_128_hmac_sha1_80(),
            CryptoPolicy::aes_cm_128_hmac_sha1_80(),
        ),
        SrtpProfile::AES_CM_128_HMAC_SHA1_32 => (
            CryptoPolicy::aes_cm_128_hmac_sha1_32(),
            CryptoPolicy::aes_cm_128_hmac_sha1_80(),
        ),
        SrtpProfile::AES_CM_192_HMAC_SHA1_80 => (
            CryptoPolicy::aes_cm_192_hmac_sha1_80(),
            CryptoPolicy::aes_cm_192_hmac_sha1_80(),
        ),
        SrtpProfile::AES_CM_192_HMAC_SHA1_32 => (
            CryptoPolicy::aes_cm_192_hmac_sha1_32(),
            CryptoPolicy::aes_cm_192_hmac_sha1_80(),
        ),
        SrtpProfile::AES_CM_256_HMAC_SHA1_80 => (
            CryptoPolicy::aes_cm_256_hmac_sha1_80(),
            CryptoPolicy::aes_cm_256_hmac_sha1_80(),
        ),
        SrtpProfile::AES_CM_256_HMAC_SHA1_32 => (
            CryptoPolicy::aes_cm_256_hmac_sha1_32(),
            CryptoPolicy::aes_cm_256_hmac_sha1_80(),
        ),
        SrtpProfile::AEAD_AES_128_GCM => (
            CryptoPolicy::aes_gcm_128_16_auth(),
            CryptoPolicy::aes_gcm_128_16_auth(),
        ),
        SrtpProfile::AEAD_AES_256_GCM => (
            CryptoPolicy::aes_gcm_256_16_auth(),
            CryptoPolicy::aes_gcm_256_16_auth(),
        ),
        other => panic!("unhandled profile {other:?}"),
    }
}

/// Deterministic key material of the length the profile needs
fn key_and_salt(profile: SrtpProfile) -> Vec<u8> {
    (0..profile.key_and_salt_len())
        .map(|i| (i as u8).wrapping_mul(7).wrapping_add(0x2b))
        .collect()
}

fn libsrtp_session(profile: SrtpProfile, ssrc: Ssrc) -> SrtpSession {
    let (rtp, rtcp) = libsrtp_policies(profile);
    let key = key_and_salt(profile);

    SrtpSession::new(vec![
        SrtpPolicy::new(rtp, rtcp, Cow::Owned(key), ssrc).expect("valid policy"),
    ])
    .expect("valid session")
}

fn ours(profile: SrtpProfile) -> (SrtpProtector, SrtpUnprotector) {
    let keys = SrtpKeys::from_concatenated(profile, &key_and_salt(profile)).expect("valid keys");
    (SrtpProtector::new(keys.clone()), SrtpUnprotector::new(keys))
}

fn rtp_packet(seq: u16, payload_len: usize) -> Vec<u8> {
    let mut pkt = vec![0x80, 0x60];
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&(u32::from(seq) * 960).to_be_bytes());
    pkt.extend_from_slice(&SSRC.to_be_bytes());
    pkt.extend((0..payload_len).map(|i| (i as u8) ^ 0x5a));
    pkt
}

/// An RTP packet with a CSRC list and a one word header extension, which must end up in
/// the clear for the counter mode profiles and in the AAD for the AEAD profiles
fn rtp_packet_with_extension(seq: u16, payload_len: usize) -> Vec<u8> {
    let mut pkt = vec![0x92, 0x60];
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&(u32::from(seq) * 960).to_be_bytes());
    pkt.extend_from_slice(&SSRC.to_be_bytes());
    pkt.extend_from_slice(&0x1111_1111u32.to_be_bytes());
    pkt.extend_from_slice(&0x2222_2222u32.to_be_bytes());
    pkt.extend_from_slice(&[0xbe, 0xde, 0x00, 0x01]);
    pkt.extend_from_slice(&[0x10, 0xaa, 0x00, 0x00]);
    pkt.extend((0..payload_len).map(|i| (i as u8) ^ 0x5a));
    pkt
}

/// A receiver report with `blocks` report blocks, so the length field stays valid
fn rtcp_packet(blocks: usize) -> Vec<u8> {
    let words = 1 + 6 * blocks;
    let mut pkt = vec![0x80 | (blocks as u8), 0xc9];
    pkt.extend_from_slice(&(words as u16).to_be_bytes());
    pkt.extend_from_slice(&SSRC.to_be_bytes());
    pkt.extend((0..blocks * 24).map(|i| (i as u8) ^ 0x33));
    pkt
}

const PAYLOAD_LENS: [usize; 7] = [0, 1, 12, 13, 20, 172, 1200];

#[test]
fn protect_rtp_matches_libsrtp_byte_for_byte() {
    for &profile in SrtpProfile::ALL {
        for build in [
            rtp_packet as fn(u16, usize) -> Vec<u8>,
            rtp_packet_with_extension,
        ] {
            let mut theirs = libsrtp_session(profile, Ssrc::AnyOutbound);
            let (mut mine, _) = ours(profile);

            for (i, &len) in PAYLOAD_LENS.iter().enumerate() {
                let seq = 1000 + i as u16;
                let rtp = build(seq, len);

                let mut expected = rtp.clone();
                theirs.protect_rtp(&mut expected).expect("libsrtp protect");

                let mut actual = Vec::new();
                mine.protect_rtp(&rtp, &mut actual).expect("protect");

                assert_eq!(
                    hex(&actual),
                    hex(&expected),
                    "{profile:?} seq {seq} payload {len}"
                );
            }
        }
    }
}

#[test]
fn protect_rtcp_matches_libsrtp_byte_for_byte() {
    for &profile in SrtpProfile::ALL {
        let mut theirs = libsrtp_session(profile, Ssrc::AnyOutbound);
        let (mut mine, _) = ours(profile);

        for blocks in [0, 1, 3] {
            let rtcp = rtcp_packet(blocks);

            let mut expected = rtcp.clone();
            theirs.protect_rtcp(&mut expected).expect("libsrtp protect");

            let mut actual = Vec::new();
            mine.protect_rtcp(&rtcp, &mut actual).expect("protect");

            assert_eq!(
                hex(&actual),
                hex(&expected),
                "{profile:?} with {blocks} report blocks"
            );
        }
    }
}

#[test]
fn libsrtp_unprotects_what_we_protect() {
    for &profile in SrtpProfile::ALL {
        let mut theirs = libsrtp_session(profile, Ssrc::AnyInbound);
        let (mut mine, _) = ours(profile);

        for (i, &len) in PAYLOAD_LENS.iter().enumerate() {
            let rtp = rtp_packet(2000 + i as u16, len);

            let mut protected = Vec::new();
            mine.protect_rtp(&rtp, &mut protected).expect("protect");

            theirs
                .unprotect_rtp(&mut protected)
                .expect("libsrtp unprotect");
            assert_eq!(hex(&protected), hex(&rtp), "{profile:?} payload {len}");
        }
    }
}

#[test]
fn we_unprotect_what_libsrtp_protects() {
    for &profile in SrtpProfile::ALL {
        let mut theirs = libsrtp_session(profile, Ssrc::AnyOutbound);
        let (_, mut mine) = ours(profile);

        for (i, &len) in PAYLOAD_LENS.iter().enumerate() {
            let rtp = rtp_packet(3000 + i as u16, len);

            let mut protected = rtp.clone();
            theirs.protect_rtp(&mut protected).expect("libsrtp protect");

            let mut plain = Vec::new();
            mine.unprotect_rtp(&protected, &mut plain)
                .expect("unprotect");
            assert_eq!(hex(&plain), hex(&rtp), "{profile:?} payload {len}");
        }
    }
}

#[test]
fn rtcp_interoperates_in_both_directions() {
    for &profile in SrtpProfile::ALL {
        // ours -> libsrtp
        let mut theirs = libsrtp_session(profile, Ssrc::AnyInbound);
        let (mut mine, _) = ours(profile);

        for blocks in [0, 1, 3] {
            let rtcp = rtcp_packet(blocks);

            let mut protected = Vec::new();
            mine.protect_rtcp(&rtcp, &mut protected).expect("protect");
            theirs
                .unprotect_rtcp(&mut protected)
                .expect("libsrtp unprotect");
            assert_eq!(hex(&protected), hex(&rtcp), "{profile:?} ours -> libsrtp");
        }

        // libsrtp -> ours
        let mut theirs = libsrtp_session(profile, Ssrc::AnyOutbound);
        let (_, mut mine) = ours(profile);

        for blocks in [0, 1, 3] {
            let rtcp = rtcp_packet(blocks);

            let mut protected = rtcp.clone();
            theirs
                .protect_rtcp(&mut protected)
                .expect("libsrtp protect");

            let mut plain = Vec::new();
            mine.unprotect_rtcp(&protected, &mut plain)
                .expect("unprotect");
            assert_eq!(hex(&plain), hex(&rtcp), "{profile:?} libsrtp -> ours");
        }
    }
}

#[test]
fn sequence_number_rollover_matches_libsrtp() {
    for &profile in SrtpProfile::ALL {
        let mut theirs = libsrtp_session(profile, Ssrc::AnyOutbound);
        let (mut mine, _) = ours(profile);

        // Crossing 65535 must increment the rollover counter on both sides, which changes
        // the initialization vector and, for the counter mode profiles, the authenticated
        // portion. A mismatch here means the index estimation is wrong.
        for seq in [65530u16, 65534, 65535, 0, 1, 2, 100] {
            let rtp = rtp_packet(seq, 40);

            let mut expected = rtp.clone();
            theirs.protect_rtp(&mut expected).expect("libsrtp protect");

            let mut actual = Vec::new();
            mine.protect_rtp(&rtp, &mut actual).expect("protect");

            assert_eq!(hex(&actual), hex(&expected), "{profile:?} seq {seq}");
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
