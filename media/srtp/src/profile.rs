use crate::SrtpError;

/// An SRTP protection profile, describing the cipher and authentication transform
/// applied to a stream
///
/// The names match the SDES crypto suite names of [RFC 4568] and [RFC 6188]. DTLS-SRTP
/// can negotiate [`SrtpProfile::AES_CM_128_HMAC_SHA1_80`],
/// [`SrtpProfile::AEAD_AES_128_GCM`] and [`SrtpProfile::AEAD_AES_256_GCM`]
/// ([RFC 5764] section 4.1.2).
///
/// [RFC 4568]: https://www.rfc-editor.org/rfc/rfc4568#section-6.2
/// [RFC 6188]: https://www.rfc-editor.org/rfc/rfc6188
/// [RFC 5764]: https://www.rfc-editor.org/rfc/rfc5764#section-4.1.2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(non_camel_case_types)]
#[non_exhaustive]
pub enum SrtpProfile {
    /// AES-128 counter mode with a 80 bit HMAC-SHA1 tag
    AES_CM_128_HMAC_SHA1_80,
    /// AES-128 counter mode with a 32 bit HMAC-SHA1 tag on RTP
    AES_CM_128_HMAC_SHA1_32,
    /// AES-192 counter mode with a 80 bit HMAC-SHA1 tag
    AES_CM_192_HMAC_SHA1_80,
    /// AES-192 counter mode with a 32 bit HMAC-SHA1 tag on RTP
    AES_CM_192_HMAC_SHA1_32,
    /// AES-256 counter mode with a 80 bit HMAC-SHA1 tag
    AES_CM_256_HMAC_SHA1_80,
    /// AES-256 counter mode with a 32 bit HMAC-SHA1 tag on RTP
    AES_CM_256_HMAC_SHA1_32,
    /// AES-128 in Galois/Counter Mode ([RFC 7714])
    ///
    /// [RFC 7714]: https://www.rfc-editor.org/rfc/rfc7714
    AEAD_AES_128_GCM,
    /// AES-256 in Galois/Counter Mode ([RFC 7714])
    ///
    /// [RFC 7714]: https://www.rfc-editor.org/rfc/rfc7714
    AEAD_AES_256_GCM,
}

use SrtpProfile::*;

/// Length of a HMAC-SHA1 session authentication key (RFC 3711 section 5.2)
pub(crate) const HMAC_SHA1_KEY_LEN: usize = 20;

/// Length of the authentication tag used by the AEAD profiles (RFC 7714 section 14)
pub(crate) const GCM_TAG_LEN: usize = 16;

/// Length of the `E` flag plus 31 bit SRTCP index trailer (RFC 3711 section 3.4)
pub(crate) const SRTCP_INDEX_LEN: usize = 4;

/// Largest portion of a packet the AES counter mode transform may cover
///
/// SRTP keeps the block index in the two least significant octets of the counter block
/// (RFC 3711 section 4.1.1). Once a packet spans more blocks than that field can hold, the
/// counter carries into the packet index of the initialization vector and repeats the
/// keystream of a different packet.
///
/// The bound stops one block short of the 2^16 the field could hold, matching libsrtp, and
/// applies in both directions.
pub(crate) const MAX_AES_CM_LEN: usize = 0xffff * 16;

/// Largest plaintext AES-GCM may cover (RFC 5116 section 5.1)
const MAX_AES_GCM_LEN: u64 = (1 << 36) - 32;

impl SrtpProfile {
    /// All profiles supported by this crate
    pub const ALL: &'static [SrtpProfile] = &[
        AES_CM_128_HMAC_SHA1_80,
        AES_CM_128_HMAC_SHA1_32,
        AES_CM_192_HMAC_SHA1_80,
        AES_CM_192_HMAC_SHA1_32,
        AES_CM_256_HMAC_SHA1_80,
        AES_CM_256_HMAC_SHA1_32,
        AEAD_AES_128_GCM,
        AEAD_AES_256_GCM,
    ];

    /// Length of the master key in bytes
    pub const fn master_key_len(self) -> usize {
        match self {
            AES_CM_128_HMAC_SHA1_80 | AES_CM_128_HMAC_SHA1_32 | AEAD_AES_128_GCM => 16,
            AES_CM_192_HMAC_SHA1_80 | AES_CM_192_HMAC_SHA1_32 => 24,
            AES_CM_256_HMAC_SHA1_80 | AES_CM_256_HMAC_SHA1_32 | AEAD_AES_256_GCM => 32,
        }
    }

    /// Length of the master salt in bytes
    ///
    /// The counter mode profiles use a 112 bit salt, the AEAD profiles a 96 bit salt
    /// (RFC 7714 section 12).
    pub const fn master_salt_len(self) -> usize {
        if self.is_aead() { 12 } else { 14 }
    }

    /// Combined length of master key and master salt in bytes
    ///
    /// This is the length of the base64 decoded `a=crypto` keying material of an SDES
    /// offer or answer.
    pub const fn key_and_salt_len(self) -> usize {
        self.master_key_len() + self.master_salt_len()
    }

    /// Number of bytes that [`SrtpProtector::protect_rtp`] adds to a packet
    ///
    /// [`SrtpProtector::protect_rtp`]: crate::SrtpProtector::protect_rtp
    pub const fn rtp_overhead(self) -> usize {
        self.rtp_auth_tag_len()
    }

    /// Number of bytes that [`SrtpProtector::protect_rtcp`] adds to a packet
    ///
    /// [`SrtpProtector::protect_rtcp`]: crate::SrtpProtector::protect_rtcp
    pub const fn rtcp_overhead(self) -> usize {
        self.rtcp_auth_tag_len() + SRTCP_INDEX_LEN
    }

    pub(crate) const fn is_aead(self) -> bool {
        matches!(self, AEAD_AES_128_GCM | AEAD_AES_256_GCM)
    }

    pub(crate) const fn rtp_auth_tag_len(self) -> usize {
        match self {
            AES_CM_128_HMAC_SHA1_80 | AES_CM_192_HMAC_SHA1_80 | AES_CM_256_HMAC_SHA1_80 => 10,
            AES_CM_128_HMAC_SHA1_32 | AES_CM_192_HMAC_SHA1_32 | AES_CM_256_HMAC_SHA1_32 => 4,
            AEAD_AES_128_GCM | AEAD_AES_256_GCM => GCM_TAG_LEN,
        }
    }

    /// The `_32` suites truncate the tag to 32 bits for RTP but keep the full 80 bits for
    /// RTCP (RFC 4568 section 6.2.1, RFC 6188 sections 2.2 and 3.2)
    pub(crate) const fn rtcp_auth_tag_len(self) -> usize {
        if self.is_aead() { GCM_TAG_LEN } else { 10 }
    }

    /// Zero for the AEAD profiles, which have no separate authentication transform
    pub(crate) const fn auth_key_len(self) -> usize {
        if self.is_aead() { 0 } else { HMAC_SHA1_KEY_LEN }
    }

    /// Reject a region the profile's cipher cannot cover without repeating a keystream
    ///
    /// Checked up front so the in-place transforms fail before they write anything.
    pub(crate) fn check_cipher_len(self, len: usize) -> Result<(), SrtpError> {
        let max = if self.is_aead() {
            MAX_AES_GCM_LEN
        } else {
            MAX_AES_CM_LEN as u64
        };

        if len as u64 > max {
            return Err(SrtpError::PacketTooLarge);
        }

        Ok(())
    }
}
