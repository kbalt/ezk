//! Some ICE related SDP attributes (`a=ice-options:...`, `a=ice-ufrag:...`, `a=ice-pwd:...`)

use crate::ice_char;
use bytes::Bytes;
use bytesstr::BytesStr;
use internal::IResult;
use nom::bytes::complete::{take_while1, take_while_m_n};
use nom::combinator::map;
use nom::error::context;
use nom::multi::many1;
use std::fmt;

/// Ice options attribute (`a=ice-options`)
///
/// Session Level attribute
///
/// [RFC5245](https://datatracker.ietf.org/doc/html/rfc5245#section-15.5)
#[derive(Default, Debug, Clone)]
pub struct IceOptions {
    /// Non empty list of options
    pub options: Vec<BytesStr>,
}

impl IceOptions {
    pub fn parse<'i>(src: &Bytes, i: &'i str) -> IResult<&'i str, Self> {
        context(
            "parsing ice-options",
            map(
                many1(map(take_while1(ice_char), |option| {
                    BytesStr::from_parse(src, option)
                })),
                |options| Self { options },
            ),
        )(i)
    }
}

impl fmt::Display for IceOptions {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.options.is_empty() {
            return Ok(());
        }

        for option in &self.options {
            write!(f, " {}", option)?;
        }

        Ok(())
    }
}

/// Ice username fragment attribute (`a=ice-ufrag`)
///
/// Session and Media Level attribute  
/// If not present at media level the attribute at session level is taken as default.
///
/// [RFC5245](https://datatracker.ietf.org/doc/html/rfc5245#section-15.4)
#[derive(Debug, Clone)]
pub struct IceUsernameFragment {
    /// The username fragment.
    ///
    /// Must be between 4 and 256 bytes long
    pub ufrag: BytesStr,
}

impl IceUsernameFragment {
    pub fn parse<'i>(src: &Bytes, i: &'i str) -> IResult<&'i str, Self> {
        context(
            "parsing ice-ufrag",
            map(take_while_m_n(4, 256, ice_char), |ufrag| Self {
                ufrag: BytesStr::from_parse(src, ufrag),
            }),
        )(i)
    }
}

impl fmt::Display for IceUsernameFragment {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a=ice-ufrag:{}", self.ufrag)
    }
}

/// Ice password attribute (`a=ice-pwd`)
///
/// Session and Media Level attribute  
/// If not present at media level the attribute at session level is taken as default.
///
/// [RFC5245](https://datatracker.ietf.org/doc/html/rfc5245#section-15.4)
#[derive(Debug, Clone)]
pub struct IcePassword {
    /// The password
    ///
    /// Must be between 22 and 256 bytes long
    pub pwd: BytesStr,
}

impl IcePassword {
    pub fn parse<'i>(src: &Bytes, i: &'i str) -> IResult<&'i str, Self> {
        context(
            "parsing ice-pwd",
            map(take_while_m_n(22, 256, ice_char), |pwd| Self {
                pwd: BytesStr::from_parse(src, pwd),
            }),
        )(i)
    }
}

impl fmt::Display for IcePassword {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a=ice-pwd:{}", self.pwd)
    }
}
