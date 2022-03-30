mod header;
mod packet;

pub use header::Header;
pub use packet::Packet;

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("version is not 2")]
    InvalidVersion,
    #[error("input is too short")]
    Incomplete,
}
