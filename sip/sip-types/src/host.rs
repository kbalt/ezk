//! [HostPort] and [Host] type found in URIs and [Via] header
//!
//! [Via]: crate::header::typed::Via

use crate::parse::Parse;
use crate::print::{Print, PrintCtx, UriContext};
use bytesstr::BytesStr;
use internal::IResult;
use nom::AsChar;
use nom::branch::alt;
use nom::bytes::complete::{tag, take_while, take_while1};
use nom::character::complete::{char, u8};
use nom::combinator::{map, map_res, opt, recognize, verify};
use nom::multi::many0;
use nom::sequence::{delimited, preceded, tuple};
use std::fmt;
use std::hash::Hash;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::num::ParseIntError;

/// Either IP address or FQDN
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum Host {
    IP6(Ipv6Addr),
    IP4(Ipv4Addr),
    Name(BytesStr),
}

impl Parse for Host {
    fn parse(src: &bytes::Bytes) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            alt((
                map_res(ip6_reference, |ip6| ip6.parse().map(Self::IP6)),
                map_res(ip4_address, |ip4| ip4.parse().map(Self::IP4)),
                map(hostname, |hostname| {
                    Self::Name(BytesStr::from_parse(src, hostname))
                }),
            ))(i)
        }
    }
}
impl_from_str!(Host);

/// IPv4addresses =  1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT "." 1*3DIGIT
fn ip4_address(i: &str) -> IResult<&str, &str> {
    recognize(tuple((u8, char('.'), u8, char('.'), u8, char('.'), u8)))(i)
}

/// IPv6reference  =  "[" IPv6address "]"
fn ip6_reference(i: &str) -> IResult<&str, &str> {
    delimited(char('['), ip6_address, char(']'))(i)
}

fn ip6_address(i: &str) -> IResult<&str, &str> {
    take_while1(|c: char| c.is_hex_digit() || matches!(c, ':' | '.'))(i)
}

/// Pretty relaxed hostname parsing.
/// SIP ABNF is too strict for modern definitions of allowed DNS names.
fn hostname(i: &str) -> IResult<&str, &str> {
    recognize(tuple((
        label,
        many0(tuple((char('.'), label))),
        opt(char('.')),
    )))(i)
}

fn label(i: &str) -> IResult<&str, &str> {
    verify(
        take_while1(|c: char| c.is_alphanum() || c == '-'),
        |label: &str| !(label.starts_with('-') || label.ends_with('-')),
    )(i)
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
}

impl Parse for HostPort {
    fn parse(src: &bytes::Bytes) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            map_res(
                tuple((
                    Host::parse(src),
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
impl_from_str!(HostPort);

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
    use std::str::FromStr;

    use super::*;

    #[track_caller]
    fn expect_hostname(i: &'static str) {
        let got = HostPort::from_str(i).unwrap();
        assert_eq!(got, HostPort::host_name(i));
    }

    #[track_caller]
    fn expect_ip4(i: &'static str) {
        let expected = HostPort {
            host: Host::IP4(i.parse().unwrap()),
            port: None,
        };
        let got = HostPort::from_str(i).unwrap();
        assert_eq!(got, expected);
    }

    #[track_caller]
    fn expect_ip6(i: &'static str) {
        let expected = HostPort {
            host: Host::IP6(i[1..i.len() - 1].parse().unwrap()),
            port: None,
        };
        let got = HostPort::from_str(i).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn host() {
        expect_ip4("123.123.123.123");
        expect_ip4("1.1.1.1");
        expect_ip4("1.100.1.100");
        expect_hostname("123.123.123.321");
        expect_hostname("123456");
        expect_hostname("123456.");
        expect_hostname("example.org");
        expect_hostname("example.org.");
        expect_hostname("very.long.hostname.example.org.");
        expect_ip6("[0:1:2:3:4:5:6:7]");
        expect_ip6("[0::7]");
        expect_ip6("[::7]");
        expect_ip6("[::]");
        expect_ip6("[::1]");
        expect_ip6("[2001:db8::1:2]");
        expect_ip6("[0001:0002:0003:0004:0005:0006:0007:0008]");
        expect_ip6("[001:2:3:4:5:6:7:8]");
        expect_ip6("[2001:db8::1:2]");
    }
}
