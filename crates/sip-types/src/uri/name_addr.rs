use crate::parse::{parse_quoted, whitespace, ParseCtx};
use crate::print::{AppendCtx, Print, PrintCtx};
use crate::uri::Uri;
use bytesstr::BytesStr;
use internal::IResult;
use nom::branch::alt;
use nom::bytes::complete::{tag, take_while, take_while1};
use nom::combinator::{map, opt};
use nom::sequence::{delimited, tuple};
use std::fmt;

/// Represents an URI with a display name or just a URI
/// `(token|"display") <URI> | URI`
/// Used in From / To Headers
#[derive(Clone, Debug)]
pub struct NameAddr {
    pub name: Option<BytesStr>,
    pub uri: Box<dyn Uri>,
}

impl NameAddr {
    #[inline]
    pub fn new<N, U>(name: N, uri: U) -> Self
    where
        N: Into<BytesStr>,
        U: Into<Box<dyn Uri>>,
    {
        Self {
            name: Some(name.into()),
            uri: uri.into(),
        }
    }

    #[inline]
    pub fn uri<U>(uri: U) -> Self
    where
        U: Into<Box<dyn Uri>>,
    {
        Self {
            name: None,
            uri: uri.into(),
        }
    }

    pub fn parse(ctx: ParseCtx<'_>) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            map(
                alt((
                    tuple((
                        opt(alt((parse_quoted, take_while1(display)))),
                        take_while(whitespace),
                        delimited(tag("<"), ctx.parse_uri(), tag(">")),
                    )),
                    map(ctx.parse_uri(), |uri| (None, "", uri)),
                )),
                move |(name, _, uri)| Self {
                    name: name.map(|name| BytesStr::from_parse(ctx.src, name.trim())),
                    uri,
                },
            )(i)
        }
    }

    pub fn parse_no_params(ctx: ParseCtx<'_>) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            map(
                alt((
                    tuple((
                        opt(alt((parse_quoted, take_while1(display)))),
                        take_while(whitespace),
                        delimited(tag("<"), ctx.parse_uri(), tag(">")),
                    )),
                    map(ctx.parse_uri_no_params(), |uri| (None, "", uri)),
                )),
                move |(name, _, uri)| Self {
                    name: name.map(|name| BytesStr::from_parse(ctx.src, name.trim())),
                    uri,
                },
            )(i)
        }
    }
}

impl Print for NameAddr {
    fn print(&self, f: &mut fmt::Formatter<'_>, ctx: PrintCtx<'_>) -> fmt::Result {
        if let Some(name) = &self.name {
            write!(f, "\"{}\"", name)?;
        }

        write!(f, "<{}>", self.uri.print_ctx(ctx))
    }
}

fn display(c: char) -> bool {
    !matches!(c, ':' | '\r' | '\n' | '<')
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::host::Host;
    use crate::uri::sip::{SipUri, UserPart};

    #[test]
    fn name_addr() {
        let input = BytesStr::from_static("Bob <sip:bob@example.com>");

        let (rem, name_addr) = NameAddr::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(name_addr.name.as_ref().map(BytesStr::as_ref), Some("Bob"));

        let sip_uri: &SipUri = name_addr.uri.downcast_ref().unwrap();

        assert!(!sip_uri.sips);
        assert!(sip_uri.uri_params.is_empty());
        assert!(sip_uri.header_params.is_empty());
        assert!(matches!(&sip_uri.user_part, UserPart::User(x) if x == "bob"));

        assert!(sip_uri.host_port.port.is_none());
        assert!(matches!(&sip_uri.host_port.host,  Host::Name(name) if name == "example.com"));
    }
}
