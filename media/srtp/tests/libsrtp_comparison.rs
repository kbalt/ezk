use ezk_srtp::{SrtpKeys, SrtpProfile, SrtpProtector, SrtpUnprotector};
use libsrtp::{CryptoPolicy, SrtpPolicy, SrtpSession, Ssrc};
use rand::{RngExt, SeedableRng, rngs::Xoshiro256PlusPlus};
use std::borrow::Cow;

const SSRC: u32 = 0xcafe_d00d;

/// Map a profile to the pair of libsrtp crypto policies it corresponds to
///
/// The `_32` suites truncate the tag to 32 bits for RTP only, RTCP keeps the full 80 bits
/// (RFC 4568 section 6.2.1, RFC 6188 sections 2.2 and 3.2), so the RTCP policy here is the
/// `_80` variant.
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
    }
}

fn key_and_salt(profile: SrtpProfile) -> Vec<u8> {
    (0..profile.key_and_salt_len())
        .map(|i| (i as u8).wrapping_mul(7).wrapping_add(0x2b))
        .collect()
}

fn libsrtp_session(profile: SrtpProfile, ssrc: Ssrc) -> SrtpSession {
    let (rtp, rtcp) = libsrtp_policies(profile);
    let key = key_and_salt(profile);

    SrtpSession::new(vec![
        SrtpPolicy::new(rtp, rtcp, Cow::Owned(key), ssrc).unwrap(),
    ])
    .unwrap()
}

fn ezk_session(profile: SrtpProfile) -> (SrtpProtector, SrtpUnprotector) {
    let keys = SrtpKeys::from_concatenated(profile, &key_and_salt(profile)).unwrap();
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
            let mut libsrtp = libsrtp_session(profile, Ssrc::AnyOutbound);
            let (mut ezk, _) = ezk_session(profile);

            for (i, &len) in PAYLOAD_LENS.iter().enumerate() {
                let seq = 1000 + i as u16;
                let rtp = build(seq, len);

                let mut expected = rtp.clone();
                libsrtp.protect_rtp(&mut expected).unwrap();

                let mut actual = rtp;
                ezk.protect_rtp(&mut actual).unwrap();

                assert_eq!(
                    to_hex(&actual),
                    to_hex(&expected),
                    "{profile:?} seq {seq} payload {len}"
                );
            }
        }
    }
}

#[test]
fn protect_rtcp_matches_libsrtp_byte_for_byte() {
    for &profile in SrtpProfile::ALL {
        let mut libsrtp = libsrtp_session(profile, Ssrc::AnyOutbound);
        let (mut ezk, _) = ezk_session(profile);

        for blocks in [0, 1, 3] {
            let rtcp = rtcp_packet(blocks);

            let mut expected = rtcp.clone();
            libsrtp.protect_rtcp(&mut expected).unwrap();

            let mut actual = rtcp;
            ezk.protect_rtcp(&mut actual).unwrap();

            assert_eq!(
                to_hex(&actual),
                to_hex(&expected),
                "{profile:?} with {blocks} report blocks"
            );
        }
    }
}

#[test]
fn libsrtp_unprotects_what_ezk_protects() {
    for &profile in SrtpProfile::ALL {
        let mut libsrtp = libsrtp_session(profile, Ssrc::AnyInbound);
        let (mut ezk, _) = ezk_session(profile);

        for (i, &len) in PAYLOAD_LENS.iter().enumerate() {
            let rtp = rtp_packet(2000 + i as u16, len);

            let mut protected = rtp.clone();
            ezk.protect_rtp(&mut protected).unwrap();
            libsrtp.unprotect_rtp(&mut protected).unwrap();
            assert_eq!(
                to_hex(&protected),
                to_hex(&rtp),
                "{profile:?} payload {len}"
            );
        }
    }
}

#[test]
fn ez_unprotects_what_libsrtp_protects() {
    for &profile in SrtpProfile::ALL {
        let mut libsrtp = libsrtp_session(profile, Ssrc::AnyOutbound);
        let (_, mut ezk) = ezk_session(profile);

        for (i, &len) in PAYLOAD_LENS.iter().enumerate() {
            let rtp = rtp_packet(3000 + i as u16, len);

            let mut plain = rtp.clone();
            libsrtp.protect_rtp(&mut plain).unwrap();

            ezk.unprotect_rtp(&mut plain).unwrap();
            assert_eq!(to_hex(&plain), to_hex(&rtp), "{profile:?} payload {len}");
        }
    }
}

#[test]
fn rtcp_interoperates_in_both_directions() {
    for &profile in SrtpProfile::ALL {
        // ezk -> libsrtp
        let mut libsrtp = libsrtp_session(profile, Ssrc::AnyInbound);
        let (mut ezk, _) = ezk_session(profile);

        for blocks in [0, 1, 3] {
            let rtcp = rtcp_packet(blocks);

            let mut protected = rtcp.clone();
            ezk.protect_rtcp(&mut protected).unwrap();
            libsrtp.unprotect_rtcp(&mut protected).unwrap();
            assert_eq!(to_hex(&protected), to_hex(&rtcp), "{profile:?}");
        }

        // libsrtp -> ezk
        let mut libsrtp = libsrtp_session(profile, Ssrc::AnyOutbound);
        let (_, mut ezk) = ezk_session(profile);

        for blocks in [0, 1, 3] {
            let rtcp = rtcp_packet(blocks);

            let mut plain = rtcp.clone();
            libsrtp.protect_rtcp(&mut plain).unwrap();

            ezk.unprotect_rtcp(&mut plain).unwrap();
            assert_eq!(to_hex(&plain), to_hex(&rtcp), "{profile:?}");
        }
    }
}

#[test]
fn sequence_number_rollover_matches_libsrtp() {
    for &profile in SrtpProfile::ALL {
        let mut libsrtp = libsrtp_session(profile, Ssrc::AnyOutbound);
        let (mut ezk, _) = ezk_session(profile);

        // Crossing 65535 must increment the rollover counter on both sides, which changes
        // the initialization vector and, for the counter mode profiles, the authenticated
        // portion
        for seq in [65530u16, 65534, 65535, 0, 1, 2, 100] {
            let rtp = rtp_packet(seq, 40);

            let mut expected = rtp.clone();
            libsrtp.protect_rtp(&mut expected).unwrap();

            let mut actual = rtp;
            ezk.protect_rtp(&mut actual).unwrap();

            assert_eq!(to_hex(&actual), to_hex(&expected), "{profile:?} seq {seq}");
        }
    }
}

/// While the stored index is still below half the sequence number space, the rollover
/// counter is anchored at zero rather than borrowed from, because the RFC 3711 appendix A
/// estimation would otherwise guess 0xffffffff. A stream that starts low and then jumps
/// forward past the pivot has to produce the same packets on both sides.
#[test]
fn low_index_forward_jump_matches_libsrtp() {
    for &profile in SrtpProfile::ALL {
        let mut libsrtp = libsrtp_session(profile, Ssrc::AnyOutbound);
        let (mut ezk, _) = ezk_session(profile);

        // 40000 - 1000 is more than 32768, which tips the estimation over
        for seq in [1000u16, 40000, 40001, 40002] {
            let rtp = rtp_packet(seq, 40);

            let mut expected = rtp.clone();
            libsrtp.protect_rtp(&mut expected).unwrap();

            let mut actual = rtp;
            ezk.protect_rtp(&mut actual)
                .unwrap_or_else(|e| panic!("{profile:?} seq {seq}: {e}"));

            assert_eq!(to_hex(&actual), to_hex(&expected), "{profile:?} seq {seq}");
        }
    }
}

#[test]
fn ez_unprotects_a_low_index_forward_jump_from_libsrtp() {
    for &profile in SrtpProfile::ALL {
        let mut libsrtp = libsrtp_session(profile, Ssrc::AnyOutbound);
        let (_, mut ezk) = ezk_session(profile);

        for seq in [1000u16, 40000, 40001] {
            let rtp = rtp_packet(seq, 40);

            let mut plain = rtp.clone();
            libsrtp.protect_rtp(&mut plain).unwrap();

            ezk.unprotect_rtp(&mut plain)
                .unwrap_or_else(|e| panic!("{profile:?} seq {seq}: {e}"));
            assert_eq!(to_hex(&plain), to_hex(&rtp), "{profile:?} seq {seq}");
        }
    }
}

/// Both implementations default to a 128 packet replay window, so they have to draw the
/// line between "reordered" and "too old" in the same place
#[test]
fn replay_window_width_matches_libsrtp() {
    let profile = SrtpProfile::AES_CM_128_HMAC_SHA1_80;

    // Deltas either side of the 128 packet boundary
    for delta in [1u16, 64, 126, 127, 128, 129, 200] {
        let mut libsrtp = libsrtp_session(profile, Ssrc::AnyInbound);
        let (_, mut ezk) = ezk_session(profile);

        let base = 40000u16;

        // Protect the old packet first, then wind a second sender up to `base`
        let mut old = rtp_packet(base - delta, 40);
        libsrtp_session(profile, Ssrc::AnyOutbound)
            .protect_rtp(&mut old)
            .unwrap();

        let mut newest = rtp_packet(base, 40);
        libsrtp_session(profile, Ssrc::AnyOutbound)
            .protect_rtp(&mut newest)
            .unwrap();

        // Deliver the newest packet to both receivers
        libsrtp.unprotect_rtp(&mut newest.clone()).unwrap();
        ezk.unprotect_rtp(&mut newest.clone()).unwrap();

        // Then the held back one
        let libsrtp_result = libsrtp.unprotect_rtp(&mut old.clone()).is_ok();
        let ezk_result = ezk.unprotect_rtp(&mut old.clone()).is_ok();

        assert_eq!(
            ezk_result, libsrtp_result,
            "delta {delta}: libsrtp accepted={libsrtp_result}, we accepted={ezk_result}"
        );
    }
}

/// Sequence numbers do not always arrive in a tidy order: a relay may rewrite them, a
/// source may restart, a stream may jump. Whatever the pattern, the index estimation and
/// the send side replay window have to reach the same verdict as libsrtp, and produce the
/// same bytes when they both accept.
#[test]
fn random_sequence_patterns_match_libsrtp() {
    let mut rng = Xoshiro256PlusPlus::seed_from_u64(0xdeadbeef);

    for &profile in SrtpProfile::ALL {
        for n in 0..40 {
            let mut libsrtp = libsrtp_session(profile, Ssrc::AnyOutbound);
            let (mut ezk, _) = ezk_session(profile);

            let mut seq: u16 = rng.random();

            for step in 0..60 {
                seq = match rng.random_range(0..8u32) {
                    0..=4 => seq.wrapping_add(1),
                    5 => seq.wrapping_sub(rng.random_range(0..8)),
                    6 => seq.wrapping_add(rng.random_range(0..40000)),
                    _ => rng.random(),
                };

                let rtp = rtp_packet(seq, 32);

                let mut expected = rtp.clone();
                let libsrtp_ok = libsrtp.protect_rtp(&mut expected).is_ok();

                let mut actual = rtp.clone();
                let ezk_result = ezk.protect_rtp(&mut actual);

                let where_ = format!("{profile:?} n {n} step {step} seq {seq}");

                assert_eq!(
                    ezk_result.is_ok(),
                    libsrtp_ok,
                    "{where_}: libsrtp accepted={libsrtp_ok}, ezk returned {ezk_result:?}"
                );

                if libsrtp_ok {
                    assert_eq!(to_hex(&actual), to_hex(&expected), "{where_}");
                } else {
                    assert!(expected.is_empty());
                    assert!(actual.is_empty());
                }
            }
        }
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The one-byte and two-byte framings of RFC 8285, and the empty block RFC 9335 section 5.1
/// asks for
#[derive(Debug, Clone, Copy)]
enum Ext {
    One,
    Two,
    EmptyOne,
    EmptyTwo,
}

impl Ext {
    const ALL: &'static [Ext] = &[Ext::One, Ext::Two, Ext::EmptyOne, Ext::EmptyTwo];

    fn block(self) -> (u16, &'static [u8]) {
        match self {
            Ext::One => (0xbede, &[0x51, 0x00, 0x02, 0x00]),
            Ext::Two => (0x1000, &[0x05, 0x02, 0x00, 0x02]),
            Ext::EmptyOne => (0xbede, &[]),
            Ext::EmptyTwo => (0x1000, &[]),
        }
    }
}

fn cryptex_packet(seq: u16, csrcs: usize, ext: Ext, payload_len: usize) -> Vec<u8> {
    let mut pkt = vec![0x90 | csrcs as u8, 0x60];
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&(u32::from(seq) * 960).to_be_bytes());
    pkt.extend_from_slice(&SSRC.to_be_bytes());

    for i in 0..csrcs {
        pkt.extend_from_slice(&(0x1111_1111u32 * (i as u32 + 1)).to_be_bytes());
    }

    let (profile, data) = ext.block();
    pkt.extend_from_slice(&profile.to_be_bytes());
    pkt.extend_from_slice(&((data.len() / 4) as u16).to_be_bytes());
    pkt.extend_from_slice(data);

    pkt.extend((0..payload_len).map(|i| (i as u8) ^ 0x5a));
    pkt
}

fn libsrtp_cryptex_session(profile: SrtpProfile, ssrc: Ssrc) -> SrtpSession {
    let mut session = libsrtp_session(profile, ssrc);
    session
        .set_stream_use_cryptex(ssrc, true)
        .expect("enable cryptex");
    session
}

fn ezk_cryptex_session(profile: SrtpProfile) -> (SrtpProtector, SrtpUnprotector) {
    let (protector, unprotector) = ezk_session(profile);
    (protector.cryptex(true), unprotector)
}

#[test]
fn cryptex_protect_rtp_matches_libsrtp() {
    for &profile in SrtpProfile::ALL {
        for &ext in Ext::ALL {
            for csrcs in [0usize, 1, 2, 15] {
                for len in PAYLOAD_LENS {
                    let mut libsrtp = libsrtp_cryptex_session(profile, Ssrc::AnyOutbound);
                    let (mut ezk, _) = ezk_cryptex_session(profile);

                    let packet = cryptex_packet(700, csrcs, ext, len);

                    let mut expected = packet.clone();
                    libsrtp.protect_rtp(&mut expected).expect("libsrtp protect");

                    let mut actual = packet;
                    ezk.protect_rtp(&mut actual).expect("ezk protect");

                    assert_eq!(
                        to_hex(&actual),
                        to_hex(&expected),
                        "{profile:?} {ext:?} {csrcs} csrcs payload {len}"
                    );
                }
            }
        }
    }
}

#[test]
fn libsrtp_unprotects_what_ezk_protects_with_cryptex() {
    for &profile in SrtpProfile::ALL {
        for &ext in Ext::ALL {
            for csrcs in [0usize, 2, 15] {
                let mut libsrtp = libsrtp_cryptex_session(profile, Ssrc::AnyInbound);
                let (mut ezk, _) = ezk_cryptex_session(profile);

                let packet = cryptex_packet(800, csrcs, ext, 40);
                let mut buf = packet.clone();
                ezk.protect_rtp(&mut buf).expect("ezk protect");
                libsrtp.unprotect_rtp(&mut buf).expect("libsrtp unprotect");

                assert_eq!(
                    to_hex(&buf),
                    to_hex(&packet),
                    "{profile:?} {ext:?} {csrcs} csrcs"
                );
            }
        }
    }
}

#[test]
fn ezk_unprotects_libsrtp_with_cryptex() {
    for &profile in SrtpProfile::ALL {
        for &ext in Ext::ALL {
            for csrcs in [0usize, 2, 15] {
                let mut libsrtp = libsrtp_cryptex_session(profile, Ssrc::AnyOutbound);
                let (_, mut ezk) = ezk_cryptex_session(profile);

                let packet = cryptex_packet(900, csrcs, ext, 40);
                let mut buf = packet.clone();
                libsrtp.protect_rtp(&mut buf).expect("libsrtp protect");
                ezk.unprotect_rtp(&mut buf).expect("ezk unprotect");

                assert_eq!(
                    to_hex(&buf),
                    to_hex(&packet),
                    "{profile:?} {ext:?} {csrcs} csrcs"
                );
            }
        }
    }
}

#[test]
fn mixing_cryptex_and_plain_packets_matches_libsrtp() {
    for &profile in SrtpProfile::ALL {
        let mut libsrtp_sender = libsrtp_session(profile, Ssrc::AnyOutbound);
        let mut libsrtp_receiver = libsrtp_cryptex_session(profile, Ssrc::AnyInbound);
        let (mut ezk_sender, mut ezk_receiver) = ezk_session(profile);

        for seq in 0..8u16 {
            let enable_cryptex = seq % 2 == 0;

            libsrtp_sender
                .set_stream_use_cryptex(Ssrc::AnyOutbound, enable_cryptex)
                .expect("toggle cryptex");
            ezk_sender.set_cryptex(enable_cryptex);

            let packet = cryptex_packet(seq, 2, Ext::One, 40);

            let mut expected = packet.clone();
            libsrtp_sender
                .protect_rtp(&mut expected)
                .expect("libsrtp protect");

            let mut actual = packet.clone();
            ezk_sender.protect_rtp(&mut actual).expect("ezk protect");

            assert_eq!(to_hex(&actual), to_hex(&expected), "{profile:?} seq {seq}");

            let mut buf = actual.clone();
            libsrtp_receiver
                .unprotect_rtp(&mut buf)
                .expect("libsrtp unprotect");
            assert_eq!(to_hex(&buf), to_hex(&packet), "{profile:?} seq {seq}");

            let mut buf = actual;
            ezk_receiver.unprotect_rtp(&mut buf).expect("ezk unprotect");
            assert_eq!(to_hex(&buf), to_hex(&packet), "{profile:?} seq {seq}");
        }
    }
}

#[test]
fn the_sender_side_refusal_matches_libsrtp() {
    for &profile in SrtpProfile::ALL {
        let mut libsrtp = libsrtp_cryptex_session(profile, Ssrc::AnyOutbound);
        let (mut ezk, _) = ezk_cryptex_session(profile);

        let mut packet = vec![0x82, 0x60, 0x00, 0x05];
        packet.extend_from_slice(&[0; 4]);
        packet.extend_from_slice(&SSRC.to_be_bytes());
        packet.extend_from_slice(&[0x11; 8]);
        packet.extend_from_slice(&[0xab; 16]);

        assert!(
            libsrtp.protect_rtp(&mut packet.clone()).is_err(),
            "{profile:?} libsrtp accepted it"
        );
        assert!(
            ezk.protect_rtp(&mut packet).is_err(),
            "{profile:?} ezk accepted it"
        );
    }
}

#[test]
fn random_cryptex_sequence_patterns_match_libsrtp() {
    let mut rng = Xoshiro256PlusPlus::seed_from_u64(0x9335_9335);

    for &profile in SrtpProfile::ALL {
        for _ in 0..20 {
            let mut libsrtp = libsrtp_cryptex_session(profile, Ssrc::AnyOutbound);
            let (mut ezk, _) = ezk_cryptex_session(profile);

            let mut seq: u16 = rng.random();

            for _ in 0..30 {
                let csrcs = rng.random_range(0..16usize);
                let ext = Ext::ALL[rng.random_range(0..Ext::ALL.len())];
                let len = rng.random_range(0..200usize);

                let packet = cryptex_packet(seq, csrcs, ext, len);

                let mut expected = packet.clone();
                let libsrtp_result = libsrtp.protect_rtp(&mut expected);

                let mut actual = packet;
                let ezk_result = ezk.protect_rtp(&mut actual);

                assert_eq!(
                    libsrtp_result.is_ok(),
                    ezk_result.is_ok(),
                    "{profile:?} seq {seq} {csrcs} csrcs {ext:?} disagreed on acceptance"
                );

                if ezk_result.is_ok() {
                    assert_eq!(
                        to_hex(&actual),
                        to_hex(&expected),
                        "{profile:?} seq {seq} {csrcs} csrcs {ext:?}"
                    );
                }

                seq = seq.wrapping_add(rng.random_range(1..4));
            }
        }
    }
}
