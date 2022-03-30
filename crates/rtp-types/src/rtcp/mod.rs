pub mod app;
pub mod bye;
mod header;
mod packet;
pub mod report;
pub mod sdes;

use std::str::Utf8Error;

pub use header::Header;
pub use packet::Packet;

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("version is not 2")]
    InvalidVersion,
    #[error("input is too short")]
    Incomplete,
    #[error("packet is not properly aligned")]
    InvalidAlignment,
    #[error(transparent)]
    Utf8(#[from] Utf8Error),
}
