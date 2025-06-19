//! # Real Time Media using SDP & RTP
//!
//! This crate provides a implementation for SDP based media sessions. The goal is to support more use cases than those
//! covered by WebRTC, including support for SIP which does not always require the usage of ICE or even SRTP.
//!
//! [`SdpSession`](sdp::SdpSession) found in the [`sdp`] module is the top level type provided by this crate, which
//! is sans-io.
//!
//! Support for IO is provided when enabling the `tokio` feature flag. Unlike in other protocol implementations, it does
//! not provide a wrapper type around `SdpSession`, but is rather a "companion" type to be used alongside `SdpSession`.

mod mtu;

pub mod rtp_session;
pub mod rtp_transport;
pub mod sdp;
mod ssl;
#[cfg(feature = "tokio")]
pub mod tokio;

pub use ice::ReceivedPkt;
pub use mtu::Mtu;
pub use ssl::OpenSslContext;

fn opt_min<T: Ord>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (None, None) => None,
        (None, Some(b)) => Some(b),
        (Some(a), None) => Some(a),
        (Some(a), Some(b)) => Some(std::cmp::min(a, b)),
    }
}
