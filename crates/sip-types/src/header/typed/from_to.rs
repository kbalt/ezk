use crate::header::name::Name;
use crate::parse::ParseCtx;
use crate::print::{Print, PrintCtx, UriContext};
use crate::uri::params::{Params, CPS};
use crate::uri::NameAddr;
use bytesstr::BytesStr;
use nom::combinator::map;
use nom::sequence::tuple;
use nom::IResult;
use std::fmt;

/// Type which is being wrapped by [From] and [To]
#[derive(Debug, Clone)]
pub struct FromTo {
    pub uri: NameAddr,
    pub tag: Option<BytesStr>,
    pub params: Params<CPS>,
}

impl FromTo {
    fn new(uri: NameAddr, tag: Option<BytesStr>) -> Self {
        Self {
            uri,
            tag,
            params: Params::new(),
        }
    }

    pub fn parse<'p>(ctx: ParseCtx<'p>) -> impl Fn(&'p str) -> IResult<&'p str, Self> + 'p {
        move |i| {
            map(
                tuple((NameAddr::parse_no_params(ctx), Params::<CPS>::parse(ctx))),
                |(uri, mut params)| FromTo {
                    uri,
                    tag: params.take("tag"),
                    params,
                },
            )(i)
        }
    }
}

impl Print for FromTo {
    fn print(&self, f: &mut fmt::Formatter<'_>, mut ctx: PrintCtx<'_>) -> fmt::Result {
        ctx.uri = Some(UriContext::FromTo);
        self.uri.print(f, ctx)?;
        if let Some(tag) = &self.tag {
            write!(f, ";tag={}", tag)?;
        }
        self.params.print(f, ctx)
    }
}

impl_wrap_header!(
    /// `To` header. Wraps [FromTo]
    FromTo,
    To,
    Single,
    Name::TO
);

impl_wrap_header!(
    /// `From` header. Wraps [FromTo]
    FromTo,
    From,
    Single,
    Name::FROM
);

impl From {
    #[inline]
    pub fn new(uri: NameAddr, tag: Option<BytesStr>) -> Self {
        Self(FromTo::new(uri, tag))
    }
}

impl To {
    #[inline]
    pub fn new(uri: NameAddr, tag: Option<BytesStr>) -> Self {
        Self(FromTo::new(uri, tag))
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::host::HostPort;
    use crate::print::AppendCtx;
    use crate::uri::sip::SipUri;

    #[test]
    fn from_to() {
        let input = BytesStr::from_static("Bob <sip:bob@example.com>;tag=abc123");

        let (rem, from) = From::parse(ParseCtx::default(&input))(&input).unwrap();

        let from_to = from.0;

        assert!(rem.is_empty());

        assert_eq!(from_to.tag.unwrap(), "abc123")
    }

    #[test]
    fn from_to_print() {
        let from = From::new(
            NameAddr::new("Bob", SipUri::new(HostPort::host_name("example.com"))),
            Some("abc123".into()),
        );

        assert_eq!(
            from.default_print_ctx().to_string(),
            "\"Bob\"<sip:example.com>;tag=abc123"
        )
    }
}
