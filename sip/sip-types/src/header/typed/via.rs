use crate::header::headers::OneOrMore;
use crate::header::name::Name;
use crate::header::{ConstNamed, ExtendValues, HeaderParse};
use crate::host::HostPort;
use crate::parse::{token, whitespace, ParseCtx};
use crate::print::{AppendCtx, Print, PrintCtx};
use crate::uri::params::{Param, Params, CPS};
use bytesstr::BytesStr;
use internal::ws;
use internal::IResult;
use nom::bytes::complete::{tag, take_while};
use nom::combinator::map;
use nom::sequence::{delimited, preceded, tuple};
use std::fmt;

/// `Via` header
#[derive(Debug, Clone)]
pub struct Via {
    pub transport: BytesStr,
    pub sent_by: HostPort,
    pub params: Params<CPS>,
}

fn parse_sip_version(i: &str) -> IResult<&str, ()> {
    map(ws((tag("SIP"), tag("/"), tag("2.0"), tag("/"))), |_| ())(i)
}

impl Via {
    /// Returns a new Via header
    pub fn new<T, S, B>(transport: T, sent_by: S, branch: B) -> Via
    where
        T: Into<BytesStr>,
        S: Into<HostPort>,
        B: Into<BytesStr>,
    {
        Via {
            transport: transport.into(),
            sent_by: sent_by.into(),
            params: Params::new().with(Param::value("branch", branch)),
        }
    }
}

impl ConstNamed for Via {
    const NAME: Name = Name::VIA;
}

impl HeaderParse for Via {
    fn parse<'i>(ctx: ParseCtx<'_>, i: &'i str) -> IResult<&'i str, Self> {
        map(
            tuple((
                preceded(
                    parse_sip_version,
                    delimited(
                        take_while(whitespace),
                        take_while(token),
                        take_while(whitespace),
                    ),
                ),
                HostPort::parse(ctx),
                Params::<CPS>::parse(ctx),
            )),
            move |(tp, hp, p)| Via {
                transport: BytesStr::from_parse(ctx.src, tp),
                sent_by: hp,
                params: p,
            },
        )(i)
    }
}

impl ExtendValues for Via {
    fn extend_values(&self, ctx: PrintCtx<'_>, values: &mut OneOrMore) {
        // Do not create Via CSV header
        values.push(self.print_ctx(ctx).to_string().into());
    }

    fn create_values(&self, ctx: PrintCtx<'_>) -> OneOrMore {
        OneOrMore::One(self.print_ctx(ctx).to_string().into())
    }
}

impl Print for Via {
    fn print(&self, f: &mut fmt::Formatter<'_>, ctx: PrintCtx<'_>) -> fmt::Result {
        write!(
            f,
            "SIP/2.0/{} {}{}",
            self.transport,
            self.sent_by.print_ctx(ctx),
            self.params
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::host::Host;
    use std::net::Ipv4Addr;
    use std::net::SocketAddr;

    #[test]
    fn via() {
        let input = BytesStr::from_static("SIP/2.0/TCP 192.168.123.222:53983;branch=abc123");

        let (rem, via) = Via::parse(ParseCtx::default(&input), &input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(via.transport, "TCP");
        assert_eq!(
            via.sent_by.host,
            Host::IP4(Ipv4Addr::new(192, 168, 123, 222))
        );
        assert_eq!(via.sent_by.port, Some(53983));
        let branch = via.params.get_val("branch").unwrap();
        assert_eq!(branch, "abc123");
    }

    #[test]
    fn via_print() {
        let via = Via::new(
            "TCP",
            SocketAddr::new(Ipv4Addr::new(192, 168, 123, 222).into(), 53983),
            "abc123",
        );

        assert_eq!(
            via.default_print_ctx().to_string(),
            "SIP/2.0/TCP 192.168.123.222:53983;branch=abc123"
        );
    }
}
