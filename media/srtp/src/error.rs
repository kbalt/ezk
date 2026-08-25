/// Error returned by the protect, unprotect and key setup operations
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SrtpError {
    /// The DTLS-SRTP protection profile is not implemented by this crate
    #[error("unsupported SRTP protection profile")]
    UnsupportedProfile,

    /// Key or salt length does not match the profile
    #[error("invalid key material length, expected {expected} bytes, got {got}")]
    BadKeyLength {
        /// Number of bytes the profile requires
        expected: usize,
        /// Number of bytes that were given
        got: usize,
    },

    /// The packet is shorter than the smallest possible (S)RTP/(S)RTCP packet
    #[error("packet is too short")]
    PacketTooShort,

    /// The packet headers are self-inconsistent, e.g. the CSRC count or header
    /// extension length point past the end of the packet
    #[error("packet is malformed")]
    MalformedPacket,

    /// The authentication tag does not match, the packet has been modified or was
    /// protected with a different key
    #[error("authentication tag mismatch")]
    AuthFailed,

    /// The packet index has already been seen
    #[error("packet has already been processed")]
    ReplayFail,

    /// The packet index is too far below the replay window to be checked
    #[error("packet is too old to be checked against the replay window")]
    ReplayOld,

    /// The 48 bit SRTP index or 31 bit SRTCP index is exhausted, the master key must
    /// be replaced before any further packets can be protected
    #[error("packet index space is exhausted, the master key must be replaced")]
    IndexExhausted,

    /// The underlying cipher rejected the input
    #[error("cipher failure")]
    CipherFailed,
}
