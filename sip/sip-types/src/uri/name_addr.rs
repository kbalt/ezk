use super::sip::SipUri;
use crate::parse::{parse_quoted, whitespace, Parse};
use crate::print::{AppendCtx, Print, PrintCtx};
use bytes::Bytes;
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
    pub uri: SipUri,
}

impl NameAddr {
    #[inline]
    pub fn new<N, U>(name: N, uri: SipUri) -> Self
    where
        N: Into<BytesStr>,
    {
        Self {
            name: Some(name.into()),
            uri,
        }
    }

    #[inline]
    pub fn uri(uri: SipUri) -> Self {
        Self { name: None, uri }
    }

    pub(crate) fn parse_no_params(src: &Bytes) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            map(
                alt((
                    tuple((
                        opt(alt((parse_quoted, take_while1(display)))),
                        take_while(whitespace),
                        delimited(tag("<"), SipUri::parse(src), tag(">")),
                    )),
                    map(SipUri::parse_no_params(src), |uri| (None, "", uri)),
                )),
                move |(name, _, uri)| Self {
                    name: name.map(|name| BytesStr::from_parse(src, name.trim())),
                    uri,
                },
            )(i)
        }
    }
}

impl Parse for NameAddr {
    fn parse(src: &Bytes) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            map(
                alt((
                    tuple((
                        opt(alt((parse_quoted, take_while1(display)))),
                        take_while(whitespace),
                        delimited(tag("<"), SipUri::parse(src), tag(">")),
                    )),
                    map(SipUri::parse(src), |uri| (None, "", uri)),
                )),
                move |(name, _, uri)| Self {
                    name: name.map(|name| BytesStr::from_parse(src, name.trim())),
                    uri,
                },
            )(i)
        }
    }
}
impl_from_str!(NameAddr);

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
    use crate::uri::sip::{SipUri, SipUriUserPart};

    #[test]
    fn name_addr() {
        let input = BytesStr::from_static("Bob <sip:bob@example.com>");

        let (rem, name_addr) = NameAddr::parse(input.as_ref())(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(name_addr.name.as_ref().map(BytesStr::as_ref), Some("Bob"));

        let sip_uri: &SipUri = &name_addr.uri;

        assert!(!sip_uri.sips);
        assert!(sip_uri.uri_params.is_empty());
        assert!(sip_uri.header_params.is_empty());
        assert!(matches!(&sip_uri.user_part, SipUriUserPart::User(x) if x == "bob"));

        assert!(sip_uri.host_port.port.is_none());
        assert!(matches!(&sip_uri.host_port.host,  Host::Name(name) if name == "example.com"));
    }
}
