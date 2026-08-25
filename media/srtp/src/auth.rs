use hmac::{Hmac, KeyInit, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

use crate::profile::HMAC_SHA1_KEY_LEN;

/// Compute the HMAC-SHA1 of `parts` concatenated, truncated into `tag`
/// (RFC 3711 section 4.2)
pub(crate) fn tag(key: &[u8], parts: &[&[u8]], tag: &mut [u8]) {
    debug_assert!(tag.len() <= HMAC_SHA1_KEY_LEN);

    let mut mac = Hmac::<Sha1>::new_from_slice(key).expect("HMAC accepts keys of any length");
    for part in parts {
        mac.update(part);
    }

    let full = mac.finalize().into_bytes();
    tag.copy_from_slice(&full[..tag.len()]);
}

/// Verify a truncated HMAC-SHA1 tag in constant time
pub(crate) fn verify(key: &[u8], parts: &[&[u8]], expected: &[u8]) -> bool {
    if expected.is_empty() || expected.len() > HMAC_SHA1_KEY_LEN {
        return false;
    }

    let mut computed = [0u8; HMAC_SHA1_KEY_LEN];
    let computed = &mut computed[..expected.len()];
    tag(key, parts, computed);

    bool::from(computed.ct_eq(expected))
}
