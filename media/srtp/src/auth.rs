use hmac::{Hmac, Mac};
use sha1::Sha1;
use subtle::ConstantTimeEq;

use crate::profile::HMAC_SHA1_KEY_LEN;

type HmacSha1 = Hmac<Sha1>;

/// Compute the HMAC-SHA1 of `parts` concatenated, truncated into `tag`
///
/// This is the authentication transform of RFC 3711 section 4.2. The caller passes the
/// authenticated portion in `parts` so that the trailing rollover counter of SRTP does
/// not have to be copied into a contiguous buffer.
pub(crate) fn tag(key: &[u8], parts: &[&[u8]], tag: &mut [u8]) {
    debug_assert!(tag.len() <= HMAC_SHA1_KEY_LEN);

    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC accepts keys of any length");
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
