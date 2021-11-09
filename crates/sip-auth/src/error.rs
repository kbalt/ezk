use bytesstr::BytesStr;
use sip_types::header::HeaderError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Header(HeaderError),
    #[error("response contains no challenges")]
    NoAuthHeaders,
    #[error("unknown challenge scheme: {0}")]
    UnknownScheme(BytesStr),
    #[error("failed to authenticate realms: {0}")]
    FailedToAuthenticate(BytesStr),
    #[error("unsupported qop")]
    UnsupportedQop,
    #[error("unsupported algorithm: {0}")]
    UnsupportedAlgorithm(BytesStr),
}
