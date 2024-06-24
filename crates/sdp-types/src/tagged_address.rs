use bytes::Bytes;
use bytesstr::BytesStr;
use internal::IResult;
use nom::branch::alt;
use nom::bytes::complete::{tag, take_while};
use nom::combinator::map;
use nom::error::context;
use nom::sequence::preceded;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::{probe_host, probe_host6};

#[derive(Debug, Clone)]
pub enum TaggedAddress {
    IP4(Ipv4Addr),
    IP4FQDN(BytesStr),

    IP6(Ipv6Addr),
    IP6FQDN(BytesStr),
}

impl From<IpAddr> for TaggedAddress {
    fn from(addr: IpAddr) -> Self {
        match addr {
            IpAddr::V4(ip) => Self::IP4(ip),
            IpAddr::V6(ip) => Self::IP6(ip),
        }
    }
}

impl TaggedAddress {
    pub fn parse(src: &Bytes) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            context(
                "parsing tagged address",
                alt((
                    preceded(
                        tag("IN IP4 "),
                        map(take_while(probe_host), |ip4_host: &str| {
                            if let Ok(addr) = ip4_host.parse() {
                                TaggedAddress::IP4(addr)
                            } else {
                                TaggedAddress::IP4FQDN(BytesStr::from_parse(src, ip4_host))
                            }
                        }),
                    ),
                    preceded(
                        tag("IN IP6 "),
                        map(take_while(probe_host6), |ip6_host: &str| {
                            if let Ok(addr) = ip6_host.parse() {
                                TaggedAddress::IP6(addr)
                            } else {
                                TaggedAddress::IP6FQDN(BytesStr::from_parse(src, ip6_host))
                            }
                        }),
                    ),
                )),
            )(i)
        }
    }
}

impl fmt::Display for TaggedAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TaggedAddress::IP4(addr) => {
                write!(f, "IN IP4 {addr}")
            }
            TaggedAddress::IP4FQDN(fqdn) => {
                write!(f, "IN IP4 {fqdn}")
            }
            TaggedAddress::IP6(addr) => {
                write!(f, "IN IP6 {addr}")
            }
            TaggedAddress::IP6FQDN(fqdn) => {
                write!(f, "IN IP6 {fqdn}")
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bytesstr::BytesStr;

    #[test]
    fn address_ip4() {
        let input = BytesStr::from_static("IN IP4 192.168.123.222");

        let (rem, addr) = TaggedAddress::parse(input.as_ref())(&input).unwrap();

        assert!(rem.is_empty());

        match addr {
            TaggedAddress::IP4(ip) => assert_eq!(ip, Ipv4Addr::new(192, 168, 123, 222)),
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn address_ip4_print() {
        let addr = TaggedAddress::IP4(Ipv4Addr::new(192, 168, 123, 222));

        assert_eq!(addr.to_string(), "IN IP4 192.168.123.222");
    }

    #[test]
    fn address_ip4_host() {
        let input = BytesStr::from_static("IN IP4 example.com");

        let (rem, addr) = TaggedAddress::parse(input.as_ref())(&input).unwrap();

        assert!(rem.is_empty());

        match addr {
            TaggedAddress::IP4FQDN(host) => assert_eq!(host, "example.com"),
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn address_ip4_host_print() {
        let addr = TaggedAddress::IP4FQDN("example.com".into());

        assert_eq!(addr.to_string(), "IN IP4 example.com");
    }

    #[test]
    fn address_ip6() {
        let input = BytesStr::from_static("IN IP6 ::1");

        let (rem, addr) = TaggedAddress::parse(input.as_ref())(&input).unwrap();

        assert!(rem.is_empty());

        match addr {
            TaggedAddress::IP6(ip) => assert_eq!(ip, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn address_ip6_print() {
        let addr = TaggedAddress::IP6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1));

        assert_eq!(addr.to_string(), "IN IP6 ::1");
    }

    #[test]
    fn address_ip6_host() {
        let input = BytesStr::from_static("IN IP6 example.com");

        let (rem, addr) = TaggedAddress::parse(input.as_ref())(&input).unwrap();

        assert!(rem.is_empty());

        match addr {
            TaggedAddress::IP6FQDN(host) => assert_eq!(host, "example.com"),
            other => panic!("{:?}", other),
        }
    }

    #[test]
    fn address_ip6_host_print() {
        let addr = TaggedAddress::IP6FQDN("example.com".into());

        assert_eq!(addr.to_string(), "IN IP6 example.com");
    }
}
