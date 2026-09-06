#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SrtpError {
    #[error("unsupported SRTP protection profile")]
    UnsupportedProfile,
    #[error("invalid key material length, expected {expected} bytes, got {got}")]
    BadKeyLength { expected: usize, got: usize },
    #[error("packet is too short")]
    PacketTooShort,
    #[error("packet is too large for the cipher")]
    PacketTooLarge,
    #[error("packet is malformed")]
    MalformedPacket,
    #[error("authentication tag mismatch")]
    AuthFailed,
    #[error("packet has already been processed")]
    ReplayFail,
    #[error("packet is too old to be checked against the replay window")]
    ReplayOld,
    #[error("packet index space is exhausted, the master key must be replaced")]
    IndexExhausted,
    #[error("cipher failure")]
    CipherFailed,
}
