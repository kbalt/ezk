//! See `unprotect_rtp`. SRTCP has a second attacker controlled length, the index
//! trailer, and two different tag placements depending on the profile, so it gets its
//! own target.
#![no_main]

use libfuzzer_sys::fuzz_target;
use srtp::{SrtpKeys, SrtpProfile, SrtpUnprotector};

fuzz_target!(|data: &[u8]| {
    for &profile in SrtpProfile::ALL {
        let material = vec![0x5au8; profile.key_and_salt_len()];
        let keys = SrtpKeys::from_concatenated(profile, &material).expect("valid keys");
        let mut receiver = SrtpUnprotector::new(keys);

        let mut out = Vec::new();
        let _ = receiver.unprotect_rtcp(data, &mut out);
    }
});
