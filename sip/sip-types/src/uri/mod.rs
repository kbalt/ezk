//! Contains the URI trait, SIP and NameAddr implementation

#[macro_use]
pub mod params;
mod name_addr;
mod sip;

pub use name_addr::NameAddr;
pub use sip::{SipUri, SipUriUserPart, SipUriUserPassword};
