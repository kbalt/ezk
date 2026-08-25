//! Self contained round trip, rollover, replay and rejection tests.
//!
//! Unlike the differential tests these need no native toolchain, so they can be run on
//! their own with `cargo test -p ezk-srtp --test roundtrip`.

use ezk_srtp::{SrtpError, SrtpKeys, SrtpProfile, SrtpProtector, SrtpUnprotector};

const SSRC: u32 = 0x1234_5678;

fn keys(profile: SrtpProfile, seed: u8) -> SrtpKeys {
    let material: Vec<u8> = (0..profile.key_and_salt_len())
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect();

    SrtpKeys::from_concatenated(profile, &material).expect("valid keys")
}

fn pair(profile: SrtpProfile) -> (SrtpProtector, SrtpUnprotector) {
    let k = keys(profile, 0x11);
    (SrtpProtector::new(k.clone()), SrtpUnprotector::new(k))
}

fn rtp(seq: u16, payload_len: usize) -> Vec<u8> {
    let mut pkt = vec![0x80, 0x60];
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&(u32::from(seq) * 160).to_be_bytes());
    pkt.extend_from_slice(&SSRC.to_be_bytes());
    pkt.extend((0..payload_len).map(|i| (i as u8) ^ 0xa5));
    pkt
}

fn rtcp(blocks: usize) -> Vec<u8> {
    let mut pkt = vec![0x80 | (blocks as u8), 0xc9];
    pkt.extend_from_slice(&((1 + 6 * blocks) as u16).to_be_bytes());
    pkt.extend_from_slice(&SSRC.to_be_bytes());
    pkt.extend((0..blocks * 24).map(|i| (i as u8) ^ 0x77));
    pkt
}

#[test]
fn rtp_round_trip_for_every_profile_and_size() {
    for &profile in SrtpProfile::ALL {
        for (i, len) in [0usize, 1, 12, 13, 20, 172, 1200].into_iter().enumerate() {
            let (mut sender, mut receiver) = pair(profile);
            let packet = rtp(100 + i as u16, len);

            let mut protected = Vec::new();
            sender
                .protect_rtp(&packet, &mut protected)
                .expect("protect");

            assert_eq!(
                protected.len(),
                packet.len() + profile.rtp_overhead(),
                "{profile:?} overhead for payload {len}"
            );
            // The header must stay in the clear, the payload must not
            assert_eq!(&protected[..12], &packet[..12], "{profile:?} header");
            if len > 0 {
                assert_ne!(
                    &protected[12..12 + len],
                    &packet[12..],
                    "{profile:?} payload"
                );
            }

            let mut plain = Vec::new();
            receiver
                .unprotect_rtp(&protected, &mut plain)
                .expect("unprotect");
            assert_eq!(plain, packet, "{profile:?} payload {len}");
        }
    }
}

#[test]
fn rtcp_round_trip_for_every_profile_and_size() {
    for &profile in SrtpProfile::ALL {
        for blocks in [0usize, 1, 3] {
            let (mut sender, mut receiver) = pair(profile);
            let packet = rtcp(blocks);

            let mut protected = Vec::new();
            sender
                .protect_rtcp(&packet, &mut protected)
                .expect("protect");

            assert_eq!(
                protected.len(),
                packet.len() + profile.rtcp_overhead(),
                "{profile:?} overhead for {blocks} blocks"
            );

            let mut plain = Vec::new();
            receiver
                .unprotect_rtcp(&protected, &mut plain)
                .expect("unprotect");
            assert_eq!(plain, packet, "{profile:?} {blocks} blocks");
        }
    }
}

#[test]
fn sequence_number_rollover_round_trips() {
    for &profile in SrtpProfile::ALL {
        let (mut sender, mut receiver) = pair(profile);

        for seq in [65533u16, 65534, 65535, 0, 1, 2] {
            let packet = rtp(seq, 40);

            let mut protected = Vec::new();
            sender
                .protect_rtp(&packet, &mut protected)
                .expect("protect");

            let mut plain = Vec::new();
            receiver
                .unprotect_rtp(&protected, &mut plain)
                .expect("unprotect");
            assert_eq!(plain, packet, "{profile:?} seq {seq}");
        }
    }
}

#[test]
fn reordered_packets_within_the_window_are_accepted() {
    for &profile in SrtpProfile::ALL {
        let (mut sender, mut receiver) = pair(profile);

        // Protect in order, deliver in a shuffled order
        let mut protected: Vec<(u16, Vec<u8>)> = Vec::new();
        for seq in 500u16..520 {
            let packet = rtp(seq, 32);
            let mut out = Vec::new();
            sender.protect_rtp(&packet, &mut out).expect("protect");
            protected.push((seq, out));
        }
        protected.reverse();

        for (seq, srtp) in &protected {
            let mut plain = Vec::new();
            receiver
                .unprotect_rtp(srtp, &mut plain)
                .unwrap_or_else(|e| panic!("{profile:?} seq {seq}: {e}"));
            assert_eq!(plain, rtp(*seq, 32));
        }
    }
}

#[test]
fn replayed_packets_are_rejected() {
    for &profile in SrtpProfile::ALL {
        let (mut sender, mut receiver) = pair(profile);

        let packet = rtp(1000, 40);
        let mut protected = Vec::new();
        sender
            .protect_rtp(&packet, &mut protected)
            .expect("protect");

        let mut plain = Vec::new();
        receiver
            .unprotect_rtp(&protected, &mut plain)
            .expect("first delivery");

        assert_eq!(
            receiver.unprotect_rtp(&protected, &mut plain),
            Err(SrtpError::ReplayFail),
            "{profile:?} duplicate"
        );
        assert!(plain.is_empty(), "{profile:?} out buffer cleared on error");
    }
}

#[test]
fn packets_below_the_replay_window_are_rejected() {
    let profile = SrtpProfile::AEAD_AES_128_GCM;
    let (mut sender, mut receiver) = pair(profile);

    // Protect an early packet but hold it back until the window has moved past it
    let old = rtp(1, 40);
    let mut old_protected = Vec::new();
    sender
        .protect_rtp(&old, &mut old_protected)
        .expect("protect");

    for seq in 2u16..400 {
        let packet = rtp(seq, 40);
        let mut protected = Vec::new();
        sender
            .protect_rtp(&packet, &mut protected)
            .expect("protect");

        let mut plain = Vec::new();
        receiver
            .unprotect_rtp(&protected, &mut plain)
            .expect("unprotect");
    }

    let mut plain = Vec::new();
    assert_eq!(
        receiver.unprotect_rtp(&old_protected, &mut plain),
        Err(SrtpError::ReplayOld)
    );
}

#[test]
fn reusing_an_outbound_index_is_refused() {
    for &profile in SrtpProfile::ALL {
        let (mut sender, _) = pair(profile);

        let packet = rtp(7, 40);
        let mut out = Vec::new();
        sender.protect_rtp(&packet, &mut out).expect("protect");

        // Protecting the same sequence number again would repeat a keystream
        assert_eq!(
            sender.protect_rtp(&packet, &mut out),
            Err(SrtpError::ReplayFail),
            "{profile:?}"
        );
        assert!(out.is_empty(), "{profile:?} out buffer cleared on error");
    }
}

#[test]
fn a_different_key_fails_authentication() {
    for &profile in SrtpProfile::ALL {
        let mut sender = SrtpProtector::new(keys(profile, 0x11));
        let mut receiver = SrtpUnprotector::new(keys(profile, 0x22));

        let packet = rtp(1, 40);
        let mut protected = Vec::new();
        sender
            .protect_rtp(&packet, &mut protected)
            .expect("protect");

        let mut plain = Vec::new();
        assert_eq!(
            receiver.unprotect_rtp(&protected, &mut plain),
            Err(SrtpError::AuthFailed),
            "{profile:?}"
        );
        assert!(plain.is_empty(), "{profile:?} out buffer cleared on error");
    }
}

#[test]
fn tampering_with_any_byte_fails_authentication() {
    for &profile in SrtpProfile::ALL {
        let (mut sender, mut receiver) = pair(profile);

        let packet = rtp(1, 40);
        let mut protected = Vec::new();
        sender
            .protect_rtp(&packet, &mut protected)
            .expect("protect");

        for i in 0..protected.len() {
            let mut tampered = protected.clone();
            tampered[i] ^= 0x01;

            let mut plain = Vec::new();
            let result = receiver.unprotect_rtp(&tampered, &mut plain);

            // Flipping a bit in the sequence number changes the index, which can be
            // reported as a replay instead of an authentication failure. Either way the
            // packet must not be accepted.
            assert!(
                result.is_err(),
                "{profile:?} byte {i} was accepted after tampering"
            );
        }
    }
}

#[test]
fn truncated_and_malformed_packets_are_rejected() {
    for &profile in SrtpProfile::ALL {
        let (mut sender, mut receiver) = pair(profile);

        let packet = rtp(1, 40);
        let mut protected = Vec::new();
        sender
            .protect_rtp(&packet, &mut protected)
            .expect("protect");

        for len in 0..protected.len() {
            let mut plain = Vec::new();
            assert!(
                receiver
                    .unprotect_rtp(&protected[..len], &mut plain)
                    .is_err(),
                "{profile:?} truncated to {len} bytes was accepted"
            );
            assert!(plain.is_empty());
        }

        let mut rtcp_protected = Vec::new();
        sender
            .protect_rtcp(&rtcp(1), &mut rtcp_protected)
            .expect("protect");

        for len in 0..rtcp_protected.len() {
            let mut plain = Vec::new();
            assert!(
                receiver
                    .unprotect_rtcp(&rtcp_protected[..len], &mut plain)
                    .is_err(),
                "{profile:?} truncated SRTCP of {len} bytes was accepted"
            );
        }
    }
}

#[test]
fn rekey_preserves_the_rollover_counter() {
    let profile = SrtpProfile::AEAD_AES_256_GCM;
    let (mut sender, mut receiver) = pair(profile);

    // Push both sides past a rollover
    for seq in [65534u16, 65535, 0, 1] {
        let packet = rtp(seq, 32);
        let mut protected = Vec::new();
        sender
            .protect_rtp(&packet, &mut protected)
            .expect("protect");
        let mut plain = Vec::new();
        receiver
            .unprotect_rtp(&protected, &mut plain)
            .expect("unprotect");
    }

    sender.rekey(keys(profile, 0x99));
    receiver.rekey(keys(profile, 0x99));

    // Sequence numbers continue where they left off, still in rollover 1
    for seq in [2u16, 3, 4] {
        let packet = rtp(seq, 32);
        let mut protected = Vec::new();
        sender
            .protect_rtp(&packet, &mut protected)
            .expect("protect");

        let mut plain = Vec::new();
        receiver
            .unprotect_rtp(&protected, &mut plain)
            .expect("unprotect after rekey");
        assert_eq!(plain, packet);
    }

    // A receiver that starts fresh after the rekey is in rollover 0 and must therefore
    // fail, which is what proves the counter was carried over rather than reset
    let mut fresh = SrtpUnprotector::new(keys(profile, 0x99));
    let packet = rtp(5, 32);
    let mut protected = Vec::new();
    sender
        .protect_rtp(&packet, &mut protected)
        .expect("protect");
    let mut plain = Vec::new();
    assert_eq!(
        fresh.unprotect_rtp(&protected, &mut plain),
        Err(SrtpError::AuthFailed)
    );
}

#[test]
fn multiple_ssrcs_get_independent_state() {
    let profile = SrtpProfile::AES_CM_128_HMAC_SHA1_80;
    let (mut sender, mut receiver) = pair(profile);

    let packet_for = |ssrc: u32, seq: u16| {
        let mut pkt = vec![0x80, 0x60];
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(&[0, 0, 0, 0]);
        pkt.extend_from_slice(&ssrc.to_be_bytes());
        pkt.extend_from_slice(&[1, 2, 3, 4]);
        pkt
    };

    // Both streams use the same sequence numbers, which must not collide
    for seq in 1u16..5 {
        for ssrc in [0xaaaa_aaaa, 0xbbbb_bbbb] {
            let packet = packet_for(ssrc, seq);
            let mut protected = Vec::new();
            sender
                .protect_rtp(&packet, &mut protected)
                .expect("protect");

            let mut plain = Vec::new();
            receiver
                .unprotect_rtp(&protected, &mut plain)
                .expect("unprotect");
            assert_eq!(plain, packet);
        }
    }
}

#[test]
fn key_length_is_validated() {
    let profile = SrtpProfile::AEAD_AES_128_GCM;

    assert_eq!(
        SrtpKeys::new(profile, &[0; 15], &[0; 12]).err(),
        Some(SrtpError::BadKeyLength {
            expected: 16,
            got: 15
        })
    );
    assert_eq!(
        SrtpKeys::new(profile, &[0; 16], &[0; 14]).err(),
        Some(SrtpError::BadKeyLength {
            expected: 12,
            got: 14
        })
    );
    assert_eq!(
        SrtpKeys::from_concatenated(profile, &[0; 27]).err(),
        Some(SrtpError::BadKeyLength {
            expected: 28,
            got: 27
        })
    );
    assert!(SrtpKeys::from_concatenated(profile, &[0; 28]).is_ok());
}
