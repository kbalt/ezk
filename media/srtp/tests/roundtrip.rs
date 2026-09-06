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

            let mut buf = packet.clone();
            sender.protect_rtp(&mut buf).expect("protect");

            assert_eq!(
                buf.len(),
                packet.len() + profile.rtp_overhead(),
                "{profile:?} overhead for payload {len}"
            );
            // The header must stay in the clear, the payload must not
            assert_eq!(&buf[..12], &packet[..12], "{profile:?} header");
            if len > 0 {
                assert_ne!(&buf[12..12 + len], &packet[12..], "{profile:?} payload");
            }

            receiver.unprotect_rtp(&mut buf).expect("unprotect");
            assert_eq!(buf, packet, "{profile:?} payload {len}");
        }
    }
}

#[test]
fn rtcp_round_trip_for_every_profile_and_size() {
    for &profile in SrtpProfile::ALL {
        for blocks in [0usize, 1, 3] {
            let (mut sender, mut receiver) = pair(profile);
            let packet = rtcp(blocks);

            let mut buf = packet.clone();
            sender.protect_rtcp(&mut buf).expect("protect");

            assert_eq!(
                buf.len(),
                packet.len() + profile.rtcp_overhead(),
                "{profile:?} overhead for {blocks} blocks"
            );

            receiver.unprotect_rtcp(&mut buf).expect("unprotect");
            assert_eq!(buf, packet, "{profile:?} {blocks} blocks");
        }
    }
}

#[test]
fn sequence_number_rollover_round_trips() {
    for &profile in SrtpProfile::ALL {
        let (mut sender, mut receiver) = pair(profile);

        for seq in [65533u16, 65534, 65535, 0, 1, 2] {
            let packet = rtp(seq, 40);

            let mut buf = packet.clone();
            sender.protect_rtp(&mut buf).expect("protect");
            receiver.unprotect_rtp(&mut buf).expect("unprotect");
            assert_eq!(buf, packet, "{profile:?} seq {seq}");
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
            let mut buf = rtp(seq, 32);
            sender.protect_rtp(&mut buf).expect("protect");
            protected.push((seq, buf));
        }
        protected.reverse();

        for (seq, mut srtp) in protected {
            receiver
                .unprotect_rtp(&mut srtp)
                .unwrap_or_else(|e| panic!("{profile:?} seq {seq}: {e}"));
            assert_eq!(srtp, rtp(seq, 32));
        }
    }
}

#[test]
fn replayed_packets_are_rejected() {
    for &profile in SrtpProfile::ALL {
        let (mut sender, mut receiver) = pair(profile);

        let mut protected = rtp(1000, 40);
        sender.protect_rtp(&mut protected).expect("protect");

        let mut replay = protected.clone();
        receiver
            .unprotect_rtp(&mut protected)
            .expect("first delivery");

        assert_eq!(
            receiver.unprotect_rtp(&mut replay),
            Err(SrtpError::ReplayFail),
            "{profile:?} duplicate"
        );
        assert!(replay.is_empty(), "{profile:?} buffer cleared on error");
    }
}

#[test]
fn packets_below_the_replay_window_are_rejected() {
    let profile = SrtpProfile::AEAD_AES_128_GCM;
    let (mut sender, mut receiver) = pair(profile);

    // Protect an early packet but hold it back until the window has moved past it
    let mut old = rtp(1, 40);
    sender.protect_rtp(&mut old).expect("protect");

    for seq in 2u16..400 {
        let mut buf = rtp(seq, 40);
        sender.protect_rtp(&mut buf).expect("protect");
        receiver.unprotect_rtp(&mut buf).expect("unprotect");
    }

    assert_eq!(receiver.unprotect_rtp(&mut old), Err(SrtpError::ReplayOld));
}

#[test]
fn reusing_an_outbound_index_is_refused() {
    for &profile in SrtpProfile::ALL {
        let (mut sender, _) = pair(profile);

        let packet = rtp(7, 40);
        let mut buf = packet.clone();
        sender.protect_rtp(&mut buf).expect("protect");

        // Protecting the same sequence number again would repeat a keystream
        let mut again = packet.clone();
        assert_eq!(
            sender.protect_rtp(&mut again),
            Err(SrtpError::ReplayFail),
            "{profile:?}"
        );
        assert!(again.is_empty(), "{profile:?} buffer cleared on error");
    }
}

#[test]
fn a_different_key_fails_authentication() {
    for &profile in SrtpProfile::ALL {
        let mut sender = SrtpProtector::new(keys(profile, 0x11));
        let mut receiver = SrtpUnprotector::new(keys(profile, 0x22));

        let mut protected = rtp(1, 40);
        sender.protect_rtp(&mut protected).expect("protect");

        assert_eq!(
            receiver.unprotect_rtp(&mut protected),
            Err(SrtpError::AuthFailed),
            "{profile:?}"
        );
        assert!(protected.is_empty(), "{profile:?} buffer cleared on error");
    }
}

#[test]
fn tampering_with_any_byte_fails_authentication() {
    for &profile in SrtpProfile::ALL {
        let (mut sender, mut receiver) = pair(profile);

        let mut protected = rtp(1, 40);
        sender.protect_rtp(&mut protected).expect("protect");

        for i in 0..protected.len() {
            let mut tampered = protected.clone();
            tampered[i] ^= 0x01;

            // Flipping a bit in the sequence number changes the index, so this can be
            // reported as a replay rather than an authentication failure
            assert!(
                receiver.unprotect_rtp(&mut tampered).is_err(),
                "{profile:?} byte {i} was accepted after tampering"
            );
        }
    }
}

#[test]
fn truncated_and_malformed_packets_are_rejected() {
    for &profile in SrtpProfile::ALL {
        let (mut sender, mut receiver) = pair(profile);

        let mut protected = rtp(1, 40);
        sender.protect_rtp(&mut protected).expect("protect");

        for len in 0..protected.len() {
            let mut buf = protected[..len].to_vec();
            assert!(
                receiver.unprotect_rtp(&mut buf).is_err(),
                "{profile:?} truncated to {len} bytes was accepted"
            );
            assert!(buf.is_empty());
        }

        let mut rtcp_protected = rtcp(1);
        sender.protect_rtcp(&mut rtcp_protected).expect("protect");

        for len in 0..rtcp_protected.len() {
            let mut buf = rtcp_protected[..len].to_vec();
            assert!(
                receiver.unprotect_rtcp(&mut buf).is_err(),
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
        let mut buf = rtp(seq, 32);
        sender.protect_rtp(&mut buf).expect("protect");
        receiver.unprotect_rtp(&mut buf).expect("unprotect");
    }

    sender.rekey(keys(profile, 0x99));
    receiver.rekey(keys(profile, 0x99));

    // Sequence numbers continue where they left off, still in rollover 1
    for seq in [2u16, 3, 4] {
        let packet = rtp(seq, 32);
        let mut buf = packet.clone();
        sender.protect_rtp(&mut buf).expect("protect");

        receiver
            .unprotect_rtp(&mut buf)
            .expect("unprotect after rekey");
        assert_eq!(buf, packet);
    }

    // A receiver that starts fresh after the rekey is in rollover 0 and must fail, which
    // proves the counter was carried over rather than reset
    let mut fresh = SrtpUnprotector::new(keys(profile, 0x99));
    let mut protected = rtp(5, 32);
    sender.protect_rtp(&mut protected).expect("protect");
    assert_eq!(
        fresh.unprotect_rtp(&mut protected),
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
            let mut buf = packet.clone();
            sender.protect_rtp(&mut buf).expect("protect");

            receiver.unprotect_rtp(&mut buf).expect("unprotect");
            assert_eq!(buf, packet);
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

/// An AES counter mode packet may span at most 2^16 blocks, because SRTP keeps the block
/// index in the two least significant octets of the counter block (RFC 3711 section
/// 4.1.1). Past that the counter carries into the packet index and repeats another
/// packet's keystream, so the packet has to be refused.
#[test]
fn oversized_counter_mode_packets_are_refused() {
    // The same bound libsrtp enforces
    const LIMIT: usize = 0xffff * 16;

    for &profile in SrtpProfile::ALL {
        let (mut sender, mut receiver) = pair(profile);

        // The header is not encrypted, so the limit applies to the payload alone
        let at_limit = rtp(1, LIMIT);
        let over_limit = rtp(2, LIMIT + 1);

        let mut buf = at_limit.clone();
        sender
            .protect_rtp(&mut buf)
            .unwrap_or_else(|e| panic!("{profile:?} refused a packet at the limit: {e}"));

        receiver
            .unprotect_rtp(&mut buf)
            .unwrap_or_else(|e| panic!("{profile:?} refused a packet at the limit: {e}"));
        assert_eq!(buf, at_limit, "{profile:?}");

        let mut buf = over_limit.clone();
        let result = sender.protect_rtp(&mut buf);

        let aead = matches!(
            profile,
            SrtpProfile::AEAD_AES_128_GCM | SrtpProfile::AEAD_AES_256_GCM
        );

        if aead {
            // AES-GCM uses a 32 bit block counter, so it has no such limit
            assert_eq!(result, Ok(()), "{profile:?}");
        } else {
            assert_eq!(result, Err(SrtpError::PacketTooLarge), "{profile:?}");
            assert!(buf.is_empty(), "{profile:?} buffer cleared on error");
        }
    }
}

#[test]
fn keying_material_length_is_exact() {
    let profile = SrtpProfile::AEAD_AES_128_GCM;
    let expected = 2 * profile.key_and_salt_len();

    assert!(SrtpKeys::from_keying_material(profile, &vec![0; expected], false).is_ok());

    // Trailing bytes mean the peer and the profile disagree, so they must not be
    // truncated away
    assert_eq!(
        SrtpKeys::from_keying_material(profile, &vec![0; expected + 1], false).err(),
        Some(SrtpError::BadKeyLength {
            expected,
            got: expected + 1
        })
    );
    assert_eq!(
        SrtpKeys::from_keying_material(profile, &vec![0; expected - 1], false).err(),
        Some(SrtpError::BadKeyLength {
            expected,
            got: expected - 1
        })
    );
}

/// Each side reads what the other writes (RFC 5764 section 4.2), so the two endpoints must
/// derive mirrored key pairs from the same exporter output
#[test]
fn keying_material_is_split_the_same_way_on_both_ends() {
    for &profile in SrtpProfile::ALL {
        let material: Vec<u8> = (0..2 * profile.key_and_salt_len())
            .map(|i| (i as u8).wrapping_mul(13).wrapping_add(5))
            .collect();

        let (client_in, client_out) =
            SrtpKeys::from_keying_material(profile, &material, false).expect("client keys");
        let (server_in, server_out) =
            SrtpKeys::from_keying_material(profile, &material, true).expect("server keys");

        // What the client sends, the server must be able to read, and the other way round
        for (sender, receiver) in [(client_out, server_in), (server_out, client_in)] {
            let mut sender = SrtpProtector::new(sender);
            let mut receiver = SrtpUnprotector::new(receiver);

            let packet = rtp(9, 40);
            let mut buf = packet.clone();
            sender.protect_rtp(&mut buf).expect("protect");

            receiver
                .unprotect_rtp(&mut buf)
                .unwrap_or_else(|e| panic!("{profile:?}: {e}"));
            assert_eq!(buf, packet, "{profile:?}");
        }
    }
}
