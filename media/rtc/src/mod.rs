use std::cmp::min;

mod mtu;
mod rtp;
pub mod rtp_session;
pub mod sdp;
pub mod transport;

pub use mtu::Mtu;

fn opt_min<T: Ord>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (None, None) => None,
        (None, Some(b)) => Some(b),
        (Some(a), None) => Some(a),
        (Some(a), Some(b)) => Some(min(a, b)),
    }
}
