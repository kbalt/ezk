use aes::cipher::{KeyIvInit, StreamCipher};
use aes::{Aes128, Aes192, Aes256};
use ctr::Ctr128BE;

use crate::SrtpError;
use crate::profile::MAX_AES_CM_LEN;

/// Apply the AES-CM keystream for `key` and `iv` to `data` in place
///
/// SRTP's AES-CM (RFC 3711 section 4.1.1) is AES in counter mode where the two least
/// significant octets of the counter block hold the block index. Since
/// [`aes_cm_iv`](super::aes_cm_iv) leaves those octets zero, a plain big endian 128 bit
/// counter is equivalent as long as the packet stays inside them.
///
/// Anything longer than [`MAX_AES_CM_LEN`] is rejected with
/// [`SrtpError::PacketTooLarge`], because the counter would carry into the packet index
/// and repeat another packet's keystream.
///
/// # Panics
///
/// Panics if `key` is not 16, 24 or 32 bytes long.
pub(crate) fn apply(key: &[u8], iv: &[u8; 16], data: &mut [u8]) -> Result<(), SrtpError> {
    if data.len() > MAX_AES_CM_LEN {
        return Err(SrtpError::PacketTooLarge);
    }

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

    Ok(())
}

/// Write the AES-CM keystream for `key` and `iv` into `out`
///
/// # Panics
///
/// Panics if `key` is not 16, 24 or 32 bytes long, or if `out` is longer than
/// [`MAX_AES_CM_LEN`].
pub(crate) fn keystream(key: &[u8], iv: &[u8; 16], out: &mut [u8]) {
    out.fill(0);
    apply(key, iv, out)
        .expect("key derivation asked for more than one AES-CM counter block segment");
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hex;

    /// RFC 3711 appendix B.2, which prints the session salt already shifted by 2^16, so
    /// it is the AES-CM input block verbatim
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

    /// A packet spanning 2^16 blocks steps the block counter into octet 13, the low octet
    /// of the packet index, and reproduces the keystream of the following packet
    #[test]
    fn the_block_counter_carries_into_the_packet_index() {
        let key = [0x11u8; 16];

        // A zero session salt leaves the initialization vector as the bare packet index,
        // isolating the counter arithmetic
        let first = crate::cipher::aes_cm_iv(&[0u8; 14], 0, 1);
        let second = crate::cipher::aes_cm_iv(&[0u8; 14], 0, 2);

        // Past `apply`'s bound on purpose, so the counter is free to carry
        let mut long = vec![0u8; (65536 + 1) * 16];
        unchecked(&key, &first, &mut long);

        let mut next = [0u8; 16];
        unchecked(&key, &second, &mut next);

        // The last block whose counter still fits the field is unrelated to the next packet
        assert_ne!(long[65535 * 16..65536 * 16], next[..]);

        // The one after it is the next packet's first block, byte for byte
        assert_eq!(
            long[65536 * 16..65537 * 16],
            next[..],
            "block 2^16 is where the counter carries"
        );

        // `apply` stops two blocks short of that, at libsrtp's own bound
        assert_eq!(MAX_AES_CM_LEN / 16, 65535);
        assert_eq!(apply(&key, &first, &mut vec![0u8; MAX_AES_CM_LEN]), Ok(()));
        assert_eq!(
            apply(&key, &first, &mut vec![0u8; MAX_AES_CM_LEN + 1]),
            Err(SrtpError::PacketTooLarge)
        );
    }

    #[test]
    #[should_panic(expected = "one AES-CM counter block segment")]
    fn keystream_refuses_to_cross_the_block_counter() {
        keystream(
            &[0x11u8; 16],
            &[0u8; 16],
            &mut vec![0u8; MAX_AES_CM_LEN + 1],
        );
    }

    /// [`apply`] without its block counter check
    fn unchecked(key: &[u8; 16], iv: &[u8; 16], data: &mut [u8]) {
        Ctr128BE::<Aes128>::new(key.into(), iv.into()).apply_keystream(data);
    }
}
