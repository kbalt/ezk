use crate::cipher::aes_cm;

// Key derivation labels (RFC 3711 sections 4.3.1 and 4.3.2)
pub(crate) const LABEL_RTP_ENCRYPTION: u8 = 0x00;
pub(crate) const LABEL_RTP_AUTHENTICATION: u8 = 0x01;
pub(crate) const LABEL_RTP_SALT: u8 = 0x02;
pub(crate) const LABEL_RTCP_ENCRYPTION: u8 = 0x03;
pub(crate) const LABEL_RTCP_AUTHENTICATION: u8 = 0x04;
pub(crate) const LABEL_RTCP_SALT: u8 = 0x05;

/// Derive `out.len()` bytes of session key material for `label`
///
/// The AES-CM pseudo random function of RFC 3711 section 4.3.1 with a key derivation rate
/// of zero, so the key id reduces to the label alone:
///
/// ```text
/// key_id = label || (index DIV kdr)      // 8 + 48 bits
/// x      = key_id XOR master_salt        // key_id occupies the low 56 of 112 bits
/// out    = AES-CM(master_key, x * 2^16)
/// ```
///
/// A 96 bit AEAD master salt is right padded with two zero octets to the 112 bits the
/// function expects (RFC 7714 section 11).
pub(crate) fn derive(master_key: &[u8], master_salt: &[u8], label: u8, out: &mut [u8]) {
    debug_assert!(master_salt.len() == 14 || master_salt.len() == 12);

    let mut iv = [0u8; 16];
    iv[..master_salt.len()].copy_from_slice(master_salt);
    iv[7] ^= label;

    // Octets 14 and 15 stay zero, they are the AES-CM block counter

    aes_cm::keystream(master_key, &iv, out);
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hex;

    const MASTER_KEY: &str = "E1F97A0D3E018BE0D64FA32C06DE4139";
    const MASTER_SALT: &str = "0EC675AD498AFEEBB6960B3AABE6";

    #[test]
    fn rfc3711_b3_key_derivation() {
        let key = hex(MASTER_KEY);
        let salt = hex(MASTER_SALT);

        let mut cipher_key = [0u8; 16];
        derive(&key, &salt, LABEL_RTP_ENCRYPTION, &mut cipher_key);
        assert_eq!(cipher_key, hex("C61E7A93744F39EE10734AFE3FF7A087")[..]);

        let mut cipher_salt = [0u8; 14];
        derive(&key, &salt, LABEL_RTP_SALT, &mut cipher_salt);
        assert_eq!(cipher_salt, hex("30CBBC08863D8C85D49DB34A9AE1")[..]);

        // The full 94 octet authentication key of the RFC's example transform, of which
        // the HMAC-SHA1 profiles use the first 20
        let mut auth_key = [0u8; 94];
        derive(&key, &salt, LABEL_RTP_AUTHENTICATION, &mut auth_key);
        assert_eq!(
            auth_key[..],
            hex(
                "CEBE321F6FF7716B6FD4AB49AF256A156D38BAA48F0A0ACF3C34E2359E6CDBCEE049646C43D9327AD175578EF72270986371C10C9A369AC2F94A8C5FBCDDDC256D6E919A48B610EF17C2041E474035766B68642C59BBFC2F34DB60DBDFB2"
            )
        );
    }

    /// The label is exclusive ored into octet 7 of the master salt, aligning the 56 bit
    /// key id with the low bits of the 112 bit salt
    #[test]
    fn label_lands_on_octet_seven() {
        let salt = hex(MASTER_SALT);

        // RFC 3711 appendix B.3 prints the PRF input for label 0x02 as
        // 0EC675AD498AFEE9B6960B3AABE6, i.e. 0xEB ^ 0x02 = 0xE9 at octet 7
        let mut expected = salt.clone();
        expected[7] ^= LABEL_RTP_SALT;
        assert_eq!(expected, hex("0EC675AD498AFEE9B6960B3AABE6"));

        let mut expected = salt;
        expected[7] ^= LABEL_RTP_AUTHENTICATION;
        assert_eq!(expected, hex("0EC675AD498AFEEAB6960B3AABE6"));
    }
}
