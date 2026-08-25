use aes::cipher::{KeyIvInit, StreamCipher};
use aes::{Aes128, Aes192, Aes256};
use ctr::Ctr128BE;

/// Apply the AES-CM keystream for `key` and `iv` to `data` in place
///
/// SRTP's AES-CM (RFC 3711 section 4.1.1) is AES in counter mode where the two least
/// significant octets of the 128 bit counter block hold the block index. Because
/// [`aes_cm_iv`](super::aes_cm_iv) always leaves those two octets zero and a single
/// packet never spans more than 2^16 blocks, a plain big endian 128 bit counter is
/// equivalent.
///
/// # Panics
///
/// Panics if `key` is not 16, 24 or 32 bytes long. Key lengths are validated against the
/// profile when [`SrtpKeys`](crate::SrtpKeys) is constructed, so this cannot be reached
/// through the public API.
pub(crate) fn apply(key: &[u8], iv: &[u8; 16], data: &mut [u8]) {
    match key.len() {
        16 => Ctr128BE::<Aes128>::new_from_slices(key, iv)
            .expect("lengths checked")
            .apply_keystream(data),
        24 => Ctr128BE::<Aes192>::new_from_slices(key, iv)
            .expect("lengths checked")
            .apply_keystream(data),
        32 => Ctr128BE::<Aes256>::new_from_slices(key, iv)
            .expect("lengths checked")
            .apply_keystream(data),
        len => unreachable!("unsupported AES key length {len}"),
    }
}

/// Write the AES-CM keystream for `key` and `iv` into `out`
pub(crate) fn keystream(key: &[u8], iv: &[u8; 16], out: &mut [u8]) {
    out.fill(0);
    apply(key, iv, out);
}

#[cfg(test)]
mod test {
    use super::*;

    /// RFC 3711 appendix B.2
    ///
    /// The appendix prints the session salt already shifted by 2^16, so it is the AES-CM
    /// input block verbatim.
    #[test]
    fn rfc3711_b2_aes_cm_keystream() {
        let key = hex("2B7E151628AED2A6ABF7158809CF4F3C");
        let iv: [u8; 16] = hex("F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000").try_into().unwrap();

        let mut out = [0u8; 48];
        keystream(&key, &iv, &mut out);

        assert_eq!(out[..16], hex("E03EAD0935C95E80E166B16DD92B4EB4"));
        assert_eq!(out[16..32], hex("D23513162B02D0F72A43A2FE4A5F97AB"));
        assert_eq!(out[32..48], hex("41E95B3BB0A2E8DD477901E4FCA894C0"));
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
