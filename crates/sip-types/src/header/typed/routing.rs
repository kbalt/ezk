use crate::header::name::Name;
use crate::parse::ParseCtx;
use crate::print::{AppendCtx, Print, PrintCtx, UriContext};
use crate::uri::params::{Params, CPS};
use crate::uri::NameAddr;
use nom::combinator::map;
use nom::sequence::tuple;
use nom::IResult;
use std::fmt;

/// Implementation for all Route-related headers.
#[derive(Debug, Clone)]
pub struct Routing {
    pub uri: NameAddr,
    pub params: Params<CPS>,
}

impl Routing {
    pub(crate) fn parse<'p>(ctx: ParseCtx<'p>) -> impl Fn(&'p str) -> IResult<&'p str, Self> + 'p {
        move |i| {
            map(
                tuple((NameAddr::parse_no_params(ctx), Params::<CPS>::parse(ctx))),
                |(uri, params)| Routing { uri, params },
            )(i)
        }
    }
}

impl Print for Routing {
    fn print(&self, f: &mut fmt::Formatter<'_>, mut ctx: PrintCtx<'_>) -> fmt::Result {
        ctx.uri = Some(UriContext::Routing);
        write!(f, "{}{}", self.uri.print_ctx(ctx), self.params)?;
        Ok(())
    }
}

impl_wrap_header!(
    /// `Route` header. Wraps [Routing].
    Routing,
    Route,
    CSV,
    Name::ROUTE
);

impl_wrap_header!(
    /// `Record-Route` header. Wraps [`Routing`]. Contains only one route. To get all routes use [`Vec`].
    Routing,
    RecordRoute,
    CSV,
    Name::RECORD_ROUTE
);

#[cfg(test)]
mod test {
    use super::*;
    use crate::header::Header;
    use crate::host::{Host, HostPort};
    use crate::uri::sip::{SipUri, UserPart};
    use bytesstr::BytesStr;
    use std::iter::once;

    #[test]
    fn routing() {
        let input = BytesStr::from_static(
            "<sip:bigbox3.site3.atlanta.com;lr>, <sip:server10.biloxi.com;lr>",
        );

        let (rem, routing) = Routing::parse(ParseCtx::default(&input))(&input).unwrap();

        assert_eq!(rem, ", <sip:server10.biloxi.com;lr>");
        assert!(routing.params.is_empty());
        assert!(routing.uri.name.is_none());

        let sip_uri: &SipUri = routing.uri.uri.downcast_ref().unwrap();

        assert!(!sip_uri.sips);
        assert!(sip_uri.header_params.is_empty());

        let lr = sip_uri.uri_params.get("lr").unwrap();
        assert!(lr.value.is_none());

        assert!(matches!(sip_uri.user_part, UserPart::Empty));
        assert!(
            matches!(&sip_uri.host_port.host, Host::Name(n) if n == "bigbox3.site3.atlanta.com")
        );
        assert!(sip_uri.host_port.port.is_none());
    }

    #[test]
    fn routing_multiple() {
        let input = BytesStr::from_static(
            "<sip:bigbox3.site3.atlanta.com;lr>, <sip:server10.biloxi.com;lr>",
        );
        let (rem, routing) = Vec::<Route>::decode(Default::default(), &mut once(&input)).unwrap();

        assert!(rem.is_none());

        let _r1 = &routing[0];
        let _r2 = &routing[1];
    }

    #[test]
    fn routing_print() {
        let routing = Routing {
            uri: NameAddr::uri(
                SipUri::new(HostPort::host_name("bigbox3.site3.atlanta.com")).uri_param_key("lr"),
            ),
            params: Default::default(),
        };

        assert_eq!(
            routing.default_print_ctx().to_string(),
            "<sip:bigbox3.site3.atlanta.com;lr>"
        );
    }
}
