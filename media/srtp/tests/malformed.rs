//! Hostile input handling.
//!
//! `unprotect_rtp` and `unprotect_rtcp` are the only entry points an attacker can reach
//! directly, so they must never panic, slice out of bounds or overflow no matter what
//! bytes arrive. The `fuzz/` directory holds proper cargo-fuzz targets for this; these
//! tests cover the same ground deterministically so that it runs in normal CI, where a
//! nightly toolchain and cargo-fuzz are not available.

use ezk_srtp::{SrtpKeys, SrtpProfile, SrtpProtector, SrtpUnprotector};

/// xorshift64*, so the corpus is reproducible without pulling in a rng crate
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }

    fn byte(&mut self) -> u8 {
        (self.next() >> 33) as u8
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() >> 33) as usize % n
    }
}

fn unprotector(profile: SrtpProfile) -> SrtpUnprotector {
    let material = vec![0x5au8; profile.key_and_salt_len()];
    SrtpUnprotector::new(SrtpKeys::from_concatenated(profile, &material).expect("valid keys"))
}

fn protector(profile: SrtpProfile) -> SrtpProtector {
    let material = vec![0x5au8; profile.key_and_salt_len()];
    SrtpProtector::new(SrtpKeys::from_concatenated(profile, &material).expect("valid keys"))
}

#[test]
fn random_bytes_never_panic() {
    let mut rng = Rng(0x1234_5678_9abc_def0);

    for &profile in SrtpProfile::ALL {
        let mut receiver = unprotector(profile);
        let mut out = Vec::new();

        for _ in 0..2000 {
            let len = rng.below(80);
            let packet: Vec<u8> = (0..len).map(|_| rng.byte()).collect();

            let _ = receiver.unprotect_rtp(&packet, &mut out);
            let _ = receiver.unprotect_rtcp(&packet, &mut out);
        }
    }
}

/// Random bytes almost never form a plausible header, so also generate packets that look
/// structurally valid but lie about their CSRC count and extension length
#[test]
fn hostile_headers_never_panic() {
    let mut rng = Rng(0xdead_beef_cafe_d00d);

    for &profile in SrtpProfile::ALL {
        let mut receiver = unprotector(profile);
        let mut out = Vec::new();

        for _ in 0..2000 {
            let mut packet = Vec::new();

            // Version 2, random padding/extension bit and CSRC count
            packet.push(0x80 | (rng.byte() & 0x3f));
            packet.push(rng.byte());
            packet.extend_from_slice(&rng.byte().to_be_bytes());
            packet.push(rng.byte());
            packet.extend((0..8).map(|_| rng.byte()));

            if rng.byte() & 1 == 0 {
                // A header extension whose length is usually a lie
                packet.extend_from_slice(&[0xbe, 0xde]);
                packet.push(rng.byte());
                packet.push(rng.byte());
            }

            packet.extend((0..rng.below(64)).map(|_| rng.byte()));

            let _ = receiver.unprotect_rtp(&packet, &mut out);
            let _ = receiver.unprotect_rtcp(&packet, &mut out);
        }
    }
}

/// Bit flips and truncations of genuine packets are the most likely thing to slip past
/// the length checks and reach the crypto
#[test]
fn mutated_valid_packets_never_panic() {
    let mut rng = Rng(0x0bad_c0de_0bad_c0de);

    for &profile in SrtpProfile::ALL {
        let mut sender = protector(profile);
        let mut receiver = unprotector(profile);

        let mut rtp = vec![0x90, 0x60, 0x00, 0x01, 0, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd];
        rtp.extend_from_slice(&[0xbe, 0xde, 0x00, 0x01, 0x10, 0x11, 0x00, 0x00]);
        rtp.extend((0..40).map(|i| i as u8));

        let mut rtcp = vec![0x81, 0xc9, 0x00, 0x07, 0xaa, 0xbb, 0xcc, 0xdd];
        rtcp.extend((0..24).map(|i| i as u8));

        let mut protected_rtp = Vec::new();
        sender
            .protect_rtp(&rtp, &mut protected_rtp)
            .expect("protect");
        let mut protected_rtcp = Vec::new();
        sender
            .protect_rtcp(&rtcp, &mut protected_rtcp)
            .expect("protect");

        let mut out = Vec::new();

        for _ in 0..2000 {
            let mut mutated = protected_rtp.clone();
            for _ in 0..1 + rng.below(4) {
                let at = rng.below(mutated.len());
                mutated[at] ^= 1 << (rng.below(8));
            }
            mutated.truncate(rng.below(mutated.len() + 1));
            let _ = receiver.unprotect_rtp(&mutated, &mut out);

            let mut mutated = protected_rtcp.clone();
            for _ in 0..1 + rng.below(4) {
                let at = rng.below(mutated.len());
                mutated[at] ^= 1 << (rng.below(8));
            }
            mutated.truncate(rng.below(mutated.len() + 1));
            let _ = receiver.unprotect_rtcp(&mutated, &mut out);
        }
    }
}

/// A header extension length field is 16 bits of words, so it can claim up to 256 KiB
/// that is not there. The parser must reject it rather than slice past the end.
#[test]
fn extension_length_overflow_is_rejected() {
    for &profile in SrtpProfile::ALL {
        let mut receiver = unprotector(profile);

        let mut packet = vec![0x9f, 0x60, 0x00, 0x01, 0, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd];
        // 15 CSRCs are claimed by the header but not present
        packet.extend_from_slice(&[0xbe, 0xde, 0xff, 0xff]);
        packet.extend([0u8; 32]);

        let mut out = Vec::new();
        assert!(receiver.unprotect_rtp(&packet, &mut out).is_err());
        assert!(out.is_empty());
    }
}
