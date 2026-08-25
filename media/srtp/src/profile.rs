/// An SRTP protection profile, describing the cipher and authentication transform
/// applied to a stream.
///
/// The names match the SDES crypto suite names of [RFC 4568] and [RFC 6188]. The
/// three profiles that DTLS-SRTP can negotiate ([RFC 5764] section 4.1.2) are
/// [`SrtpProfile::AES_CM_128_HMAC_SHA1_80`], [`SrtpProfile::AEAD_AES_128_GCM`] and
/// [`SrtpProfile::AEAD_AES_256_GCM`].
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
    /// offer or answer, and the length accepted by [`SrtpKeys::from_concatenated`].
    ///
    /// [`SrtpKeys::from_concatenated`]: crate::SrtpKeys::from_concatenated
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

    /// Whether this profile uses an AEAD cipher instead of a separate cipher and
    /// authentication transform
    pub(crate) const fn is_aead(self) -> bool {
        matches!(self, AEAD_AES_128_GCM | AEAD_AES_256_GCM)
    }

    /// Length of the SRTP authentication tag in bytes
    pub(crate) const fn rtp_auth_tag_len(self) -> usize {
        match self {
            AES_CM_128_HMAC_SHA1_80 | AES_CM_192_HMAC_SHA1_80 | AES_CM_256_HMAC_SHA1_80 => 10,
            AES_CM_128_HMAC_SHA1_32 | AES_CM_192_HMAC_SHA1_32 | AES_CM_256_HMAC_SHA1_32 => 4,
            AEAD_AES_128_GCM | AEAD_AES_256_GCM => GCM_TAG_LEN,
        }
    }

    /// Length of the SRTCP authentication tag in bytes
    ///
    /// Note that the `_32` suites truncate the tag to 32 bits for RTP but keep the full
    /// 80 bits for RTCP (RFC 4568 section 6.2.1, RFC 6188 sections 2.2 and 3.2). libsrtp
    /// leaves this to the caller, and passing its `..._hmac_sha1_32` crypto policy for
    /// RTCP as well - as `ezk-libsrtp` callers used to do - produces a 32 bit SRTCP tag
    /// that does not interoperate with an RFC compliant peer.
    pub(crate) const fn rtcp_auth_tag_len(self) -> usize {
        if self.is_aead() { GCM_TAG_LEN } else { 10 }
    }

    /// Length of the session authentication key in bytes, zero for the AEAD profiles
    pub(crate) const fn auth_key_len(self) -> usize {
        if self.is_aead() { 0 } else { HMAC_SHA1_KEY_LEN }
    }
}
