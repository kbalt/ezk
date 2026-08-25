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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Ext {
    None,
    OneByte,
    TwoByte,
    EmptyOneByte,
    EmptyTwoByte,
}

impl Ext {
    const WITH_EXTENSION: &'static [Ext] = &[
        Ext::OneByte,
        Ext::TwoByte,
        Ext::EmptyOneByte,
        Ext::EmptyTwoByte,
    ];

    /// "Defined by profile" value and the extension data
    fn block(self) -> Option<(u16, &'static [u8])> {
        match self {
            Ext::None => None,
            Ext::OneByte => Some((0xbede, &[0x51, 0x00, 0x02, 0x00])),
            Ext::TwoByte => Some((0x1000, &[0x05, 0x02, 0x00, 0x02])),
            Ext::EmptyOneByte => Some((0xbede, &[])),
            Ext::EmptyTwoByte => Some((0x1000, &[])),
        }
    }

    fn cryptex_tag(self) -> Option<[u8; 2]> {
        match self {
            Ext::None => None,
            Ext::OneByte | Ext::EmptyOneByte => Some([0xc0, 0xde]),
            Ext::TwoByte | Ext::EmptyTwoByte => Some([0xc2, 0xde]),
        }
    }
}

fn cryptex_rtp(seq: u16, csrcs: usize, ext: Ext, payload_len: usize) -> Vec<u8> {
    assert!(csrcs <= 15);

    let x = u8::from(ext != Ext::None);
    let mut pkt = vec![0x80 | (x << 4) | csrcs as u8, 0x60];
    pkt.extend_from_slice(&seq.to_be_bytes());
    pkt.extend_from_slice(&(u32::from(seq) * 960).to_be_bytes());
    pkt.extend_from_slice(&SSRC.to_be_bytes());

    for i in 0..csrcs {
        pkt.extend_from_slice(&(0x1111_1111u32 * (i as u32 + 1)).to_be_bytes());
    }

    if let Some((profile, data)) = ext.block() {
        assert_eq!(data.len() % 4, 0);
        pkt.extend_from_slice(&profile.to_be_bytes());
        pkt.extend_from_slice(&((data.len() / 4) as u16).to_be_bytes());
        pkt.extend_from_slice(data);
    }

    pkt.extend((0..payload_len).map(|i| (i as u8) ^ 0x5a));
    pkt
}

fn ext_at(csrcs: usize) -> usize {
    12 + csrcs * 4
}

#[test]
fn cryptex_round_trips_for_every_profile_shape_and_size() {
    for &profile in SrtpProfile::ALL {
        for &ext in Ext::WITH_EXTENSION {
            for csrcs in [0usize, 1, 2, 15] {
                for len in [0usize, 1, 12, 20, 172, 1200] {
                    let (mut sender, mut receiver) = pair(profile);
                    sender.set_cryptex(true);

                    let packet = cryptex_rtp(1000, csrcs, ext, len);
                    let mut buf = packet.clone();
                    sender
                        .protect_rtp(&mut buf)
                        .unwrap_or_else(|e| panic!("{profile:?} {ext:?} {csrcs} csrcs: {e}"));

                    assert_eq!(
                        buf.len(),
                        packet.len() + profile.rtp_overhead(),
                        "{profile:?} {ext:?} {csrcs} csrcs, cryptex adds nothing"
                    );

                    assert_eq!(buf[..12], packet[..12], "{profile:?} fixed header");
                    let at = ext_at(csrcs);
                    assert_eq!(
                        buf[at..at + 2],
                        ext.cryptex_tag().unwrap(),
                        "{profile:?} {ext:?} {csrcs} csrcs, tag rewritten"
                    );
                    assert_eq!(
                        buf[at + 2..at + 4],
                        packet[at + 2..at + 4],
                        "{profile:?} extension length untouched"
                    );
                    if csrcs > 0 {
                        assert_ne!(
                            buf[12..at],
                            packet[12..at],
                            "{profile:?} {csrcs} csrcs encrypted"
                        );
                    }

                    receiver.unprotect_rtp(&mut buf).expect("unprotect");
                    assert_eq!(buf, packet, "{profile:?} {ext:?} {csrcs} csrcs payload {len}");
                }
            }
        }
    }
}

#[test]
fn cryptex_restores_the_packet_exactly() {
    for &profile in SrtpProfile::ALL {
        for csrcs in [0usize, 1, 2, 7, 15] {
            let (mut sender, mut receiver) = pair(profile);
            sender.set_cryptex(true);

            let packet = cryptex_rtp(4242, csrcs, Ext::OneByte, 40);
            let mut buf = packet.clone();

            sender.protect_rtp(&mut buf).expect("protect");
            receiver.unprotect_rtp(&mut buf).expect("unprotect");

            assert_eq!(buf, packet, "{profile:?} {csrcs} csrcs");
        }
    }
}

#[test]
fn a_bare_packet_is_protected_identically_with_and_without_cryptex() {
    for &profile in SrtpProfile::ALL {
        let packet = rtp(77, 40);

        let mut plain = packet.clone();
        SrtpProtector::new(keys(profile, 0x11))
            .protect_rtp(&mut plain)
            .expect("protect");

        let mut with_cryptex = packet;
        SrtpProtector::new(keys(profile, 0x11))
            .cryptex(true)
            .protect_rtp(&mut with_cryptex)
            .expect("protect");

        assert_eq!(plain, with_cryptex, "{profile:?}");
    }
}

/// The empty block RFC 9335 section 5.1 wants would grow the packet past the profile's
/// overhead, so the caller has to add it
#[test]
fn cryptex_refuses_csrcs_without_a_header_extension() {
    for &profile in SrtpProfile::ALL {
        let mut sender = SrtpProtector::new(keys(profile, 0x11)).cryptex(true);
        let mut buf = cryptex_rtp(5, 2, Ext::None, 40);

        assert_eq!(
            sender.protect_rtp(&mut buf),
            Err(SrtpError::CryptexNeedsExtension),
            "{profile:?}"
        );
        assert!(buf.is_empty(), "{profile:?} buffer cleared on error");
    }
}

#[test]
fn cryptex_refuses_extensions_it_cannot_represent() {
    for &profile in SrtpProfile::ALL {
        for profile_value in [0x100fu16, 0x1001, 0xabcd, 0xc0de] {
            let mut sender = SrtpProtector::new(keys(profile, 0x11)).cryptex(true);

            let mut buf = cryptex_rtp(5, 1, Ext::OneByte, 40);
            let at = ext_at(1);
            buf[at..at + 2].copy_from_slice(&profile_value.to_be_bytes());

            assert_eq!(
                sender.protect_rtp(&mut buf),
                Err(SrtpError::CryptexUnsupportedExtension),
                "{profile:?} {profile_value:#06x}"
            );
            assert!(buf.is_empty(), "{profile:?} buffer cleared on error");
        }
    }
}

/// RFC 9335 section 4 allows the choice per packet, and flipping it must not disturb the
/// index or replay state
#[test]
fn cryptex_can_be_toggled_per_packet() {
    for &profile in SrtpProfile::ALL {
        let (mut sender, mut receiver) = pair(profile);

        for seq in 0..8u16 {
            let on = seq % 2 == 0;
            sender.set_cryptex(on);

            let packet = cryptex_rtp(seq, 2, Ext::OneByte, 40);
            let mut buf = packet.clone();
            sender.protect_rtp(&mut buf).expect("protect");

            let at = ext_at(2);
            let expected_tag: [u8; 2] = if on { [0xc0, 0xde] } else { [0xbe, 0xde] };
            assert_eq!(buf[at..at + 2], expected_tag, "{profile:?} seq {seq}");

            receiver.unprotect_rtp(&mut buf).expect("unprotect");
            assert_eq!(buf, packet, "{profile:?} seq {seq}");
        }
    }
}

#[test]
fn a_receiver_handles_cryptex_and_plain_packets_alike() {
    for &profile in SrtpProfile::ALL {
        for sender_cryptex in [false, true] {
            let (mut sender, mut receiver) = pair(profile);
            sender.set_cryptex(sender_cryptex);

            let packet = cryptex_rtp(9, 2, Ext::OneByte, 40);
            let mut buf = packet.clone();
            sender.protect_rtp(&mut buf).expect("protect");
            receiver.unprotect_rtp(&mut buf).expect("unprotect");

            assert_eq!(buf, packet, "{profile:?} sender cryptex {sender_cryptex}");
        }
    }
}

/// RFC 9335 section 5.2's mandatory variant
#[test]
fn a_strict_receiver_rejects_packets_that_are_not_cryptex_protected() {
    for &profile in SrtpProfile::ALL {
        let strict = |receiver: SrtpUnprotector| receiver.require_cryptex(true);

        let mut sender = SrtpProtector::new(keys(profile, 0x11));
        let mut buf = cryptex_rtp(11, 2, Ext::OneByte, 40);
        sender.protect_rtp(&mut buf).expect("protect");
        assert_eq!(
            strict(SrtpUnprotector::new(keys(profile, 0x11))).unprotect_rtp(&mut buf),
            Err(SrtpError::CryptexRequired),
            "{profile:?} plain extension"
        );
        assert!(buf.is_empty(), "{profile:?} buffer cleared on error");

        // Csrcs with no extension to carry the tag
        let mut buf = cryptex_rtp(12, 2, Ext::None, 40);
        sender.protect_rtp(&mut buf).expect("protect");
        assert_eq!(
            strict(SrtpUnprotector::new(keys(profile, 0x11))).unprotect_rtp(&mut buf),
            Err(SrtpError::CryptexRequired),
            "{profile:?} bare contributing sources"
        );

        // Nothing to protect, still accepted
        let packet = rtp(13, 40);
        let mut buf = packet.clone();
        sender.protect_rtp(&mut buf).expect("protect");
        strict(SrtpUnprotector::new(keys(profile, 0x11)))
            .unprotect_rtp(&mut buf)
            .unwrap_or_else(|e| panic!("{profile:?} bare packet: {e}"));
        assert_eq!(buf, packet, "{profile:?}");

        let mut sender = SrtpProtector::new(keys(profile, 0x11)).cryptex(true);
        let packet = cryptex_rtp(14, 2, Ext::OneByte, 40);
        let mut buf = packet.clone();
        sender.protect_rtp(&mut buf).expect("protect");
        strict(SrtpUnprotector::new(keys(profile, 0x11)))
            .unprotect_rtp(&mut buf)
            .unwrap_or_else(|e| panic!("{profile:?} cryptex packet: {e}"));
        assert_eq!(buf, packet, "{profile:?}");
    }
}

#[test]
fn tampering_with_a_cryptex_packet_fails_authentication() {
    for &profile in SrtpProfile::ALL {
        let (mut sender, mut receiver) = pair(profile);
        sender.set_cryptex(true);

        let mut protected = cryptex_rtp(1, 2, Ext::OneByte, 40);
        sender.protect_rtp(&mut protected).expect("protect");

        for i in 0..protected.len() {
            let mut tampered = protected.clone();
            tampered[i] ^= 0x01;
            assert!(
                receiver.unprotect_rtp(&mut tampered).is_err(),
                "{profile:?} byte {i} was accepted after tampering"
            );
            assert!(tampered.is_empty(), "{profile:?} buffer cleared on error");
        }
    }
}

#[test]
fn truncated_cryptex_packets_are_rejected() {
    for &profile in SrtpProfile::ALL {
        let (mut sender, mut receiver) = pair(profile);
        sender.set_cryptex(true);

        let mut protected = cryptex_rtp(1, 2, Ext::OneByte, 40);
        sender.protect_rtp(&mut protected).expect("protect");

        for cut in 1..protected.len() {
            let mut truncated = protected[..cut].to_vec();
            assert!(
                receiver.unprotect_rtp(&mut truncated).is_err(),
                "{profile:?} truncated to {cut} bytes was accepted"
            );
            assert!(truncated.is_empty(), "{profile:?} buffer cleared on error");
        }
    }
}
