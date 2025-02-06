use crate::header::headers::OneOrMore;
use crate::header::{ExtendValues, HeaderParse};
use crate::parse::ParseCtx;
use crate::print::{AppendCtx, Print, PrintCtx, UriContext};
use crate::uri::params::{Params, CPS};
use crate::uri::NameAddr;
use internal::IResult;
use nom::combinator::map;
use nom::sequence::tuple;
use std::fmt;

/// Implementation for all Route-related headers.
#[derive(Debug, Clone)]
pub struct Routing {
    pub uri: NameAddr,
    pub params: Params<CPS>,
}

impl HeaderParse for Routing {
    fn parse<'i>(ctx: ParseCtx<'_>, i: &'i str) -> IResult<&'i str, Self> {
        map(
            tuple((NameAddr::parse_no_params(ctx), Params::<CPS>::parse(ctx))),
            |(uri, params)| Self { uri, params },
        )(i)
    }
}

impl ExtendValues for Routing {
    fn extend_values(&self, ctx: PrintCtx<'_>, values: &mut OneOrMore) {
        let value = match values {
            OneOrMore::One(value) => value,
            OneOrMore::More(values) => values.last_mut().expect("empty OneOrMore::More variant"),
        };

        *value = format!("{}, {}", value, self.print_ctx(ctx)).into();
    }

    fn create_values(&self, ctx: PrintCtx<'_>) -> OneOrMore {
        OneOrMore::One(self.print_ctx(ctx).to_string().into())
    }
}

impl Print for Routing {
    fn print(&self, f: &mut fmt::Formatter<'_>, mut ctx: PrintCtx<'_>) -> fmt::Result {
        ctx.uri = Some(UriContext::Routing);
        write!(f, "{}{}", self.uri.print_ctx(ctx), self.params)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::uri::sip::SipUri;
    use crate::{Headers, Name};

    fn test_routing() -> Routing {
        let uri: SipUri = "sip:example.org".parse().unwrap();

        Routing {
            uri: NameAddr::uri(uri),
            params: Params::new(),
        }
    }

    #[test]
    fn print_routing_single() {
        let mut headers = Headers::new();
        headers.insert_type(Name::ROUTE, &test_routing());
        let headers = headers.to_string();

        assert_eq!(headers, "Route: <sip:example.org>\r\n")
    }

    #[test]
    fn print_routing_multiple_vec() {
        let mut headers = Headers::new();
        headers.insert_type(Name::ROUTE, &vec![test_routing(), test_routing()]);
        let headers = headers.to_string();

        assert_eq!(headers, "Route: <sip:example.org>, <sip:example.org>\r\n")
    }

    #[test]
    fn print_routing_multiple_insert() {
        let mut headers = Headers::new();
        headers.insert_type(Name::ROUTE, &test_routing());
        headers.insert_type(Name::ROUTE, &test_routing());
        let headers = headers.to_string();

        assert_eq!(headers, "Route: <sip:example.org>, <sip:example.org>\r\n")
    }

    #[test]
    fn parse_routing_single() {
        let mut headers = Headers::new();
        headers.insert(Name::ROUTE, "<sip:example.org>");

        let routing: Routing = headers.get(Name::ROUTE).unwrap();
        assert_eq!(&routing.uri.uri, &test_routing().uri.uri);
        assert!(routing.params.is_empty());
        assert_eq!(routing.uri.name, None)
    }

    #[test]
    fn parse_multiple_vec() {
        let mut headers = Headers::new();
        headers.insert(Name::ROUTE, "<sip:example.org>, <sip:example.org>");

        let routing: Vec<Routing> = headers.get(Name::ROUTE).unwrap();

        assert_eq!(routing.len(), 2);

        assert_eq!(&routing[0].uri.uri, &test_routing().uri.uri);
        assert!(routing[0].params.is_empty());
        assert_eq!(routing[0].uri.name, None);

        assert_eq!(&routing[1].uri.uri, &test_routing().uri.uri);
        assert!(routing[1].params.is_empty());
        assert_eq!(routing[1].uri.name, None)
    }
}
