#![no_main]

use libfuzzer_sys::fuzz_target;
use srtp::{SrtpKeys, SrtpProfile, SrtpUnprotector};

fuzz_target!(|data: &[u8]| {
    for &profile in SrtpProfile::ALL {
        let material = vec![0x5au8; profile.key_and_salt_len()];
        let keys = SrtpKeys::from_concatenated(profile, &material).expect("valid keys");
        let mut receiver = SrtpUnprotector::new(keys);

        let mut buf = data.to_vec();
        let _ = receiver.unprotect_rtp(&mut buf);
    }
});
