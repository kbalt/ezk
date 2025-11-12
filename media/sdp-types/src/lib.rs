#![warn(unreachable_pub)]

use internal::IResult;
use nom::character::complete::{char, digit1};
use nom::combinator::map_res;
use nom::sequence::preceded;
use std::str::FromStr;

mod attributes;
mod bandwidth;
mod connection;
mod media;
mod media_description;
mod origin;
mod parser;
mod session_description;
mod tagged_address;
mod time;

pub use attributes::{
    Direction, ExtMap, Fingerprint, FingerprintAlgorithm, Fmtp, Group, IceCandidate, IceOptions,
    IcePassword, IceUsernameFragment, InvalidCandidateParamError, Rtcp, RtcpFeedback,
    RtcpFeedbackKind, RtcpFeedbackPt, RtpMap, Setup, SourceAttribute, SrtpCrypto, SrtpFecOrder,
    SrtpKeyingMaterial, SrtpSessionParam, SrtpSuite, Ssrc, UnknownAttribute, UntaggedAddress,
};
pub use bandwidth::Bandwidth;
pub use connection::Connection;
pub use media::{Media, MediaType, TransportProtocol};
pub use media_description::MediaDescription;
pub use origin::Origin;
pub use parser::ParseSessionDescriptionError;
pub use session_description::SessionDescription;
pub use tagged_address::TaggedAddress;
pub use time::Time;

fn slash_num(i: &str) -> IResult<&str, u32> {
    preceded(char('/'), map_res(digit1, FromStr::from_str))(i)
}

fn not_whitespace(c: char) -> bool {
    !c.is_ascii_whitespace()
}

fn ice_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/')
}

fn probe_host(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')
}

fn probe_host6(c: char) -> bool {
    probe_host(c) || c == ':'
}
