use bytes::Bytes;
use bytesstr::BytesStr;
use std::fmt;

mod candidate;
mod crypto;
mod direction;
mod fmtp;
mod ice;
mod rtcp;
mod rtpmap;

pub use candidate::{IceCandidate, InvalidCandidateParamError, UntaggedAddress};
pub use crypto::{SrtpCrypto, SrtpFecOrder, SrtpKeyingMaterial, SrtpSessionParam, SrtpSuite};
pub use direction::Direction;
pub use fmtp::Fmtp;
pub use ice::{IceOptions, IcePassword, IceUsernameFragment};
pub use rtcp::Rtcp;
pub use rtpmap::RtpMap;

/// `name:[value]` pair which contains an unparsed/unknown attribute
#[derive(Debug, Clone)]
pub struct UnknownAttribute {
    /// Attribute name, the part before the optional `:`
    pub name: BytesStr,

    /// if the optional `:` is present the part parsed after is stored inside `value`
    pub value: Option<BytesStr>,
}

impl UnknownAttribute {
    pub fn parse(src: &Bytes, line: &str) -> Self {
        match line.split_once(':') {
            None => Self {
                name: BytesStr::from_parse(src, line),
                value: None,
            },
            Some((name, value)) => Self {
                name: BytesStr::from_parse(src, name),
                value: Some(BytesStr::from_parse(src, value)),
            },
        }
    }
}

impl fmt::Display for UnknownAttribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a={}", self.name)?;

        if let Some(value) = &self.value {
            write!(f, ":{}", value)?;
        }

        Ok(())
    }
}
