#![allow(unused_parens)]
//! Parsing utilities for SIP message components

use crate::uri::sip::SipUri;
use crate::uri::Uri;
use bytes::Bytes;
use internal::IResult;
use nom::branch::alt;
use nom::bytes::complete::{escaped, is_not};
use nom::character::complete::char;
use nom::combinator::map;
use nom::sequence::delimited;

pub(crate) fn parse_quoted(i: &str) -> IResult<&str, &str> {
    delimited(char('"'), escaped(is_not("\""), '\\', char('"')), char('"'))(i)
}

pub(crate) fn whitespace(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

#[rustfmt::skip]
pub(crate) fn token(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '-' | '.' | '!' | '%' | '*' | '_' | '`' | '\'' | '~' | '+')
}

/// Can be used to extend the parsing capabilities of this library.
///
/// Currently this can be used to register nom parsers for custom URI types
#[derive(Copy, Clone)]
pub struct Parser {
    pub parse_other_uri: fn(&str) -> IResult<&str, Box<dyn Uri>>,
    pub parse_other_uri_no_params: fn(&str) -> IResult<&str, Box<dyn Uri>>,
}

fn fail(_: &str) -> IResult<&str, Box<dyn Uri>> {
    Err(nom::Err::Error(nom::error::VerboseError { errors: vec![] }))
}

impl Default for Parser {
    fn default() -> Self {
        Self {
            parse_other_uri: fail,
            parse_other_uri_no_params: fail,
        }
    }
}

/// Contains the source buffer and a parser
#[derive(Copy, Clone)]
pub struct ParseCtx<'p> {
    pub src: &'p Bytes,
    pub parser: Parser,
}

impl<'p> ParseCtx<'p> {
    pub(crate) fn default<B>(src: &'p B) -> Self
    where
        B: AsRef<Bytes> + 'p,
    {
        Self {
            src: src.as_ref(),
            parser: Default::default(),
        }
    }

    pub fn new(src: &'p Bytes, parser: Parser) -> Self {
        ParseCtx { src, parser }
    }

    pub fn parse_uri(self) -> impl Fn(&str) -> IResult<&str, Box<dyn Uri>> + 'p {
        move |i| {
            alt((
                map(SipUri::parse(self), |uri| -> Box<dyn Uri> { Box::new(uri) }),
                self.parser.parse_other_uri,
            ))(i)
        }
    }

    pub fn parse_uri_no_params(self) -> impl Fn(&str) -> IResult<&str, Box<dyn Uri>> + 'p {
        move |i| {
            alt((
                map(SipUri::parse_no_params(self), |uri| -> Box<dyn Uri> {
                    Box::new(uri)
                }),
                self.parser.parse_other_uri_no_params,
            ))(i)
        }
    }
}
