use crate::header::headers::OneOrMore;
use crate::header::{ExtendValues, HeaderParse};
use crate::parse::ParseCtx;
use crate::print::{AppendCtx, Print, PrintCtx, UriContext};
use crate::uri::params::{Params, CPS};
use crate::uri::NameAddr;
use bytesstr::BytesStr;
use internal::IResult;
use nom::combinator::map;
use nom::sequence::tuple;
use std::fmt;

/// Type which represent the `From` and `To` header value
#[derive(Debug, Clone)]
pub struct FromTo {
    pub uri: NameAddr,
    pub tag: Option<BytesStr>,
    pub params: Params<CPS>,
}

impl FromTo {
    pub fn new(uri: NameAddr, tag: Option<BytesStr>) -> Self {
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

impl HeaderParse for FromTo {
    fn parse<'i>(ctx: ParseCtx, i: &'i str) -> IResult<&'i str, Self> {
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

impl ExtendValues for FromTo {
    fn extend_values(&self, ctx: PrintCtx<'_>, values: &mut OneOrMore) {
        *values = self.create_values(ctx)
    }

    fn create_values(&self, ctx: PrintCtx<'_>) -> OneOrMore {
        OneOrMore::One(self.print_ctx(ctx).to_string().into())
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::uri::sip::SipUri;
    use crate::{Headers, Name};

    fn test_fromto() -> FromTo {
        let uri: SipUri = "sip:example.org".parse().unwrap();

        FromTo {
            uri: NameAddr::uri(uri),
            tag: Some("123".into()),
            params: Params::new(),
        }
    }

    #[test]
    fn print_fromto() {
        let mut headers = Headers::new();
        headers.insert_type(Name::FROM, &test_fromto());
        let headers = headers.to_string();

        assert_eq!(headers, "From: <sip:example.org>;tag=123\r\n");
    }

    #[test]
    fn parse_fromto() {
        let mut headers = Headers::new();
        headers.insert(Name::FROM, "<sip:example.org>;tag=321");

        let from_to: FromTo = headers.get(Name::FROM).unwrap();

        assert_eq!(&from_to.uri.uri, &test_fromto().uri.uri);
        assert_eq!(from_to.tag, Some(BytesStr::from_static("321")));
    }
}
