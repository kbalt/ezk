#![warn(unreachable_pub)]

mod codecs;
mod options;
pub mod state;
#[cfg(feature = "tokio")]
pub mod tokio;

pub use codecs::{Codec, Codecs, NegotiatedCodec};

pub use ice::ReceivedPkt;
pub use options::{BundlePolicy, Options, RtcpMuxPolicy, TransportType};
pub use sdp_types::{Direction, MediaType, ParseSessionDescriptionError, SessionDescription};

/// Identifies a single media stream.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MediaId(u32);

impl MediaId {
    fn increment(&mut self) -> Self {
        let id = *self;
        self.0 += 1;
        id
    }
}

slotmap::new_key_type! {
    pub struct LocalMediaId;
    pub struct TransportId;
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
}
