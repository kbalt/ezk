//! Cipher primitives and initialization vector construction

pub(crate) mod aes_cm;
pub(crate) mod aes_gcm;

/// Build the AES-CM initialization vector for an SRTP or SRTCP packet
///
/// Per RFC 3711 section 4.1.1 the IV is
///
/// ```text
/// IV = (session_salt * 2^16) XOR (SSRC * 2^64) XOR (index * 2^16)
/// ```
///
/// placing the 112 bit session salt in octets 0..14, the SSRC in octets 4..8, the 48 bit
/// packet index in octets 8..14 and leaving octets 14..16 as the AES-CM block counter. For
/// SRTCP `index` is the 31 bit SRTCP index (RFC 3711 section 3.4).
pub(crate) fn aes_cm_iv(session_salt: &[u8], ssrc: u32, index: u64) -> [u8; 16] {
    debug_assert_eq!(session_salt.len(), 14);

    let mut iv = [0u8; 16];
    iv[..session_salt.len()].copy_from_slice(session_salt);

    for (dst, src) in iv[4..8].iter_mut().zip(ssrc.to_be_bytes()) {
        *dst ^= src;
    }

    // The packet index is 48 bits wide, so skip the two most significant octets
    for (dst, src) in iv[8..14].iter_mut().zip(index.to_be_bytes()[2..].iter()) {
        *dst ^= src;
    }

    iv
}

/// Build the AES-GCM initialization vector for an SRTP packet
///
/// Per RFC 7714 section 8.1 the 96 bit IV is
///
/// ```text
/// (0x0000 || SSRC || ROC || SEQ) XOR session_salt
/// ```
///
/// `ROC || SEQ` is exactly the low 48 bits of the packet index.
pub(crate) fn aes_gcm_srtp_iv(session_salt: &[u8], ssrc: u32, index: u64) -> [u8; 12] {
    debug_assert_eq!(session_salt.len(), 12);

    let mut iv = [0u8; 12];
    iv[2..6].copy_from_slice(&ssrc.to_be_bytes());
    iv[6..12].copy_from_slice(&index.to_be_bytes()[2..]);

    for (dst, src) in iv.iter_mut().zip(session_salt) {
        *dst ^= src;
    }

    iv
}

/// Build the AES-GCM initialization vector for an SRTCP packet
///
/// Per RFC 7714 section 9.1 the 96 bit IV is
///
/// ```text
/// (0x0000 || SSRC || 0x0000 || 0 || SRTCP index) XOR session_salt
/// ```
///
/// The SRTCP index goes into octets 8..12, not 6..12 as for SRTP, and the `E` flag is not
/// part of the IV.
pub(crate) fn aes_gcm_srtcp_iv(session_salt: &[u8], ssrc: u32, index: u32) -> [u8; 12] {
    debug_assert_eq!(session_salt.len(), 12);
    debug_assert_eq!(index & 0x8000_0000, 0);

    let mut iv = [0u8; 12];
    iv[2..6].copy_from_slice(&ssrc.to_be_bytes());
    iv[8..12].copy_from_slice(&index.to_be_bytes());

    for (dst, src) in iv.iter_mut().zip(session_salt) {
        *dst ^= src;
    }

    iv
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hex;

    /// RFC 7714 section 16, SSRC 0x5501a0b2, rollover counter 0, sequence number 0xf17b
    #[test]
    fn rfc7714_srtp_iv() {
        let salt = hex("517569642070726f2071756f");
        let iv = aes_gcm_srtp_iv(&salt, 0x5501_a0b2, 0xf17b);

        assert_eq!(iv[..], hex("51753c6580c2726f20718414")[..]);
    }

    /// RFC 7714 section 17, SSRC "Mars", SRTCP index 0x5d4
    #[test]
    fn rfc7714_srtcp_iv() {
        let salt = hex("517569642070726f2071756f");
        let iv = aes_gcm_srtcp_iv(&salt, 0x4d61_7273, 0x5d4);

        assert_eq!(iv[..], hex("517524055203726f207170bb")[..]);
    }

    /// RFC 3711 section 4.1.1 places the SSRC at octets 4..8 and the 48 bit index at
    /// octets 8..14
    #[test]
    fn aes_cm_iv_layout() {
        let iv = aes_cm_iv(&[0u8; 14], 0x0102_0304, 0x0000_5566_7788);

        assert_eq!(iv, hex("00000000010203040000556677880000")[..]);
    }
}
