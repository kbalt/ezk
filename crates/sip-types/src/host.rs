//! [HostPort] and [Host] type found in URIs and [Via] header
//!
//! [Via]: crate::header::typed::Via

use crate::parse::ParseCtx;
use crate::print::{Print, PrintCtx, UriContext};
use bytesstr::BytesStr;
use nom::branch::alt;
use nom::bytes::complete::{is_not, tag, take_while};
use nom::combinator::{map_res, opt};
use nom::sequence::{delimited, preceded, tuple};
use nom::{AsChar, IResult};
use std::fmt;
use std::hash::Hash;
use std::net::{
    AddrParseError, IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6,
};
use std::num::ParseIntError;

/// Either IP address or FQDN
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum Host {
    IP6(Ipv6Addr),
    IP4(Ipv4Addr),
    Name(BytesStr),
}

impl Host {
    pub fn parse(ctx: ParseCtx<'_>) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            alt((
                map_res(
                    delimited(tag("["), is_not("]"), tag("]")),
                    |ip: &str| -> Result<Host, AddrParseError> { Ok(Host::IP6(ip.parse()?)) },
                ),
                map_res(
                    take_while(probe_host),
                    |host: &str| -> Result<Host, AddrParseError> {
                        if host.chars().any(|c| !(c.is_numeric() || c == '.')) {
                            Ok(Host::Name(BytesStr::from_parse(ctx.src, host)))
                        } else {
                            Ok(Host::IP4(host.parse()?))
                        }
                    },
                ),
            ))(i)
        }
    }
}

impl From<IpAddr> for Host {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(addr) => Host::IP4(addr),
            IpAddr::V6(addr) => Host::IP6(addr),
        }
    }
}

impl From<Ipv4Addr> for Host {
    fn from(addr: Ipv4Addr) -> Self {
        Host::IP4(addr)
    }
}

impl From<Ipv6Addr> for Host {
    fn from(addr: Ipv6Addr) -> Self {
        Host::IP6(addr)
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Host::IP6(addr) => write!(f, "[{}]", addr),
            Host::IP4(addr) => write!(f, "{}", addr),
            Host::Name(name) => f.write_str(name),
        }
    }
}

pub(crate) fn probe_host(c: char) -> bool {
    lookup_table!(c => alpha; num; '_', '-', '.')
}

// ==== HOST PORT ====

/// Contains [Host] paired with an optional port
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct HostPort {
    pub host: Host,
    pub port: Option<u16>,
}

impl HostPort {
    /// Returns `Some` ip-address if the host part is an ip-address
    pub fn ip(&self) -> Option<IpAddr> {
        match self.host {
            Host::IP4(ip) => Some(IpAddr::V4(ip)),
            Host::IP6(ip) => Some(IpAddr::V6(ip)),
            Host::Name(_) => None,
        }
    }

    /// Creates a new host-port from a hostname
    pub fn host_name<S: Into<BytesStr>>(name: S) -> HostPort {
        HostPort {
            host: Host::Name(name.into()),
            port: None,
        }
    }

    pub fn parse(ctx: ParseCtx<'_>) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            map_res(
                tuple((
                    Host::parse(ctx),
                    opt(preceded(tag(":"), take_while(char::is_dec_digit))),
                )),
                |(host, port): (Host, Option<&str>)| -> Result<_, ParseIntError> {
                    Ok(HostPort {
                        host,
                        port: match port {
                            None => None,
                            Some(port) => Some(port.parse()?),
                        },
                    })
                },
            )(i)
        }
    }
}

impl From<SocketAddrV4> for HostPort {
    fn from(addr: SocketAddrV4) -> Self {
        HostPort {
            host: (*addr.ip()).into(),
            port: Some(addr.port()),
        }
    }
}

impl From<SocketAddrV6> for HostPort {
    fn from(addr: SocketAddrV6) -> Self {
        HostPort {
            host: (*addr.ip()).into(),
            port: Some(addr.port()),
        }
    }
}

impl From<SocketAddr> for HostPort {
    fn from(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr) => addr.into(),
            SocketAddr::V6(addr) => addr.into(),
        }
    }
}

impl Print for HostPort {
    fn print(&self, f: &mut fmt::Formatter<'_>, ctx: PrintCtx<'_>) -> fmt::Result {
        write!(f, "{}", self.host)?;

        match self.port {
            Some(port) if !matches!(ctx.uri, Some(UriContext::FromTo)) => {
                write!(f, ":{}", port)
            }
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn host_ip4() {
        let input = BytesStr::from_static("192.168.123.222");

        let (rem, host) = Host::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        match host {
            Host::IP4(ip) => assert_eq!(ip, Ipv4Addr::new(192, 168, 123, 222)),
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn host_ip6() {
        let input = BytesStr::from_static("[::1]");

        let (rem, host) = Host::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        match host {
            Host::IP6(ip) => assert_eq!(ip, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn host_name() {
        let input = BytesStr::from_static("example.com");

        let (rem, host) = Host::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        match host {
            Host::Name(name) => assert_eq!(name, "example.com"),
            other => panic!("{:?}", other),
        }
    }
}
