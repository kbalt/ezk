//! Some ICE related SDP attributes (`a=ice-options:...`, `a=ice-ufrag:...`, `a=ice-pwd:...`)

use crate::ice_char;
use bytes::Bytes;
use bytesstr::BytesStr;
use internal::IResult;
use nom::bytes::complete::{take_while1, take_while_m_n};
use nom::combinator::map;
use nom::multi::many1;
use std::fmt;

/// ice-options
///
/// Session Level attribute
///
/// [RFC5245](https://datatracker.ietf.org/doc/html/rfc5245#section-15.5)
#[derive(Default, Debug, Clone)]
pub struct Options {
    /// Non empty list of options
    pub options: Vec<BytesStr>,
}

impl Options {
    pub fn parse<'i>(src: &Bytes, i: &'i str) -> IResult<&'i str, Self> {
        map(
            many1(map(take_while1(ice_char), |option| {
                BytesStr::from_parse(src, option)
            })),
            |options| Self { options },
        )(i)
    }
}

impl fmt::Display for Options {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.options.is_empty() {
            return Ok(());
        }

        write!(f, "a=ice-options:")?;

        for option in &self.options {
            write!(f, " {}", option)?;
        }

        f.write_str("\r\n")
    }
}

/// ice-ufrag attribute
///
/// Session and Media Level attribute  
/// If not present at media level the attribute at session level is taken as default.
///
/// [RFC5245](https://datatracker.ietf.org/doc/html/rfc5245#section-15.4)
#[derive(Debug, Clone)]
pub struct UsernameFragment {
    /// The username fragment.
    ///
    /// Must be between 4 and 256 bytes long
    pub ufrag: BytesStr,
}

impl UsernameFragment {
    pub fn parse<'i>(src: &Bytes, i: &'i str) -> IResult<&'i str, Self> {
        map(take_while_m_n(4, 256, ice_char), |ufrag| Self {
            ufrag: BytesStr::from_parse(src, ufrag),
        })(i)
    }
}

impl fmt::Display for UsernameFragment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a=ice-ufrag:{}", self.ufrag)
    }
}

/// ice-pwd attribute
///
/// Session and Media Level attribute  
/// If not present at media level the attribute at session level is taken as default.
///
/// [RFC5245](https://datatracker.ietf.org/doc/html/rfc5245#section-15.4)
#[derive(Debug, Clone)]
pub struct Password {
    /// The password
    ///
    /// Must be between 22 and 256 bytes long
    pub pwd: BytesStr,
}

impl Password {
    pub fn parse<'i>(src: &Bytes, i: &'i str) -> IResult<&'i str, Self> {
        map(take_while_m_n(22, 256, ice_char), |pwd| Self {
            pwd: BytesStr::from_parse(src, pwd),
        })(i)
    }
}

impl fmt::Display for Password {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a=ice-pwd:{}", self.pwd)
    }
}
