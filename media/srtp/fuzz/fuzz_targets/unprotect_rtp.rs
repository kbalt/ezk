//! `unprotect_rtp` is the attacker controlled surface: anyone who can reach the socket
//! can hand it arbitrary bytes. This asserts nothing beyond the absence of panics,
//! out of bounds slicing and arithmetic overflow.
#![no_main]

use libfuzzer_sys::fuzz_target;
use srtp::{SrtpKeys, SrtpProfile, SrtpUnprotector};

fuzz_target!(|data: &[u8]| {
    for &profile in SrtpProfile::ALL {
        let material = vec![0x5au8; profile.key_and_salt_len()];
        let keys = SrtpKeys::from_concatenated(profile, &material).expect("valid keys");
        let mut receiver = SrtpUnprotector::new(keys);

        let mut out = Vec::new();
        let _ = receiver.unprotect_rtp(data, &mut out);
    }
});
