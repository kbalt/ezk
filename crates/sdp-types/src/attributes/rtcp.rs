//! RTCP Attribute (`a=rtcp:...`)

use crate::TaggedAddress;
use bytes::Bytes;
use internal::ws;
use nom::bytes::complete::tag;
use nom::character::complete::digit1;
use nom::combinator::{map, map_res, opt};
use nom::sequence::{preceded, tuple};
use nom::IResult;
use std::fmt;
use std::str::FromStr;

/// Specify an alternative address/port for RTCP  
/// Defined as a simple fix for NAT transversal with STUN
///
/// Media Level attribute
///
/// [RFC3605](https://datatracker.ietf.org/doc/html/rfc3605)
#[derive(Debug, Clone)]
pub struct RtcpAttr {
    /// Port to be used for RTCP
    pub port: u16,

    /// Optional address
    pub address: Option<TaggedAddress>,
}

impl RtcpAttr {
    pub fn parse(src: &Bytes) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            preceded(
                tag("rtcp:"),
                map(
                    tuple((
                        // port
                        map_res(digit1, FromStr::from_str),
                        // optional tagged address
                        opt(ws((TaggedAddress::parse(src),))),
                    )),
                    |(port, address)| RtcpAttr {
                        port,
                        address: address.map(|t| t.0),
                    },
                ),
            )(i)
        }
    }
}

impl fmt::Display for RtcpAttr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "rtcp:{}", self.port)?;

        if let Some(address) = &self.address {
            write!(f, " {}", address)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bytesstr::BytesStr;
    use std::net::Ipv4Addr;

    #[test]
    fn rtcp() {
        let input = BytesStr::from_static("rtcp:4444");

        let (rem, rtcp) = RtcpAttr::parse(input.as_ref())(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(rtcp.port, 4444);
        assert!(rtcp.address.is_none());
    }

    #[test]
    fn rtcp_address() {
        let input = BytesStr::from_static("rtcp:4444 IN IP4 192.168.123.222");

        let (rem, rtcp) = RtcpAttr::parse(input.as_ref())(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(rtcp.port, 4444);
        assert!(
            matches!(rtcp.address, Some(TaggedAddress::IP4(ip)) if ip == Ipv4Addr::new(192, 168, 123, 222))
        );
    }

    #[test]
    fn rtcp_print() {
        let rtcp = RtcpAttr {
            port: 4444,
            address: None,
        };

        assert_eq!(rtcp.to_string(), "rtcp:4444");
    }

    #[test]
    fn rtcp_address_print() {
        let rtcp = RtcpAttr {
            port: 4444,
            address: Some(TaggedAddress::IP4(Ipv4Addr::new(192, 168, 123, 222))),
        };

        assert_eq!(rtcp.to_string(), "rtcp:4444 IN IP4 192.168.123.222");
    }
}
