use sip_types::header::HeaderError;
use std::io;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error(transparent)]
    Header(#[from] HeaderError),
    #[error("request timed out")]
    RequestTimedOut,
}

#[derive(Debug, thiserror::Error)]
pub enum StunError {
    #[error(transparent)]
    Io(#[from] io::Error),
    #[error("stun request timed out")]
    RequestTimedOut,
    #[error("stun response contained no addresses")]
    InvalidResponse,
    #[error("failed to parse stun response, {0}")]
    MalformedResponse(stun_types::Error),
}
