use ezk_srtp::{SrtpKeys, SrtpProfile, SrtpUnprotector};
use rand::{RngExt, SeedableRng, rngs::Xoshiro256PlusPlus};

fn rng(seed: u64) -> Xoshiro256PlusPlus {
    Xoshiro256PlusPlus::seed_from_u64(seed)
}

fn unprotector(profile: SrtpProfile) -> SrtpUnprotector {
    let material = vec![0x5au8; profile.key_and_salt_len()];
    SrtpUnprotector::new(SrtpKeys::from_concatenated(profile, &material).expect("valid keys"))
}

#[test]
fn hostile_headers() {
    let mut rng = rng(0xdead_beef_cafe_d00d);

    for &profile in SrtpProfile::ALL {
        let mut receiver = unprotector(profile);

        for _ in 0..2000 {
            let mut packet = Vec::new();

            packet.push(0x80 | (rng.random::<u8>() & 0x3f));
            packet.push(rng.random());
            packet.extend_from_slice(&rng.random::<u16>().to_be_bytes());
            packet.extend((0..8).map(|_| rng.random::<u8>()));

            if rng.random::<bool>() {
                packet.extend_from_slice(&[0xbe, 0xde]);
                packet.extend_from_slice(&rng.random::<u16>().to_be_bytes());
            }

            packet.extend((0..rng.random_range(0..64)).map(|_| rng.random::<u8>()));

            let mut buf = packet.clone();
            let _ = receiver.unprotect_rtp(&mut buf);
            let mut buf = packet;
            let _ = receiver.unprotect_rtcp(&mut buf);
        }
    }
}

#[test]
fn extension_length_overflow_is_rejected() {
    for &profile in SrtpProfile::ALL {
        let mut receiver = unprotector(profile);

        let mut packet = vec![0x9f, 0x60, 0x00, 0x01, 0, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd];
        // 15 CSRCs are claimed by the header but not present
        packet.extend_from_slice(&[0xbe, 0xde, 0xff, 0xff]);
        packet.extend([0u8; 32]);

        assert!(receiver.unprotect_rtp(&mut packet).is_err());
    }
}
