//! ICE Candidate (`a=candidate:...`)

use crate::{ice_char, not_whitespace, probe_host6};
use bytes::Bytes;
use bytesstr::BytesStr;
use internal::{ws, IResult};
use nom::bytes::complete::{tag, take_while, take_while1, take_while_m_n};
use nom::character::complete::digit1;
use nom::combinator::{map, map_res};
use nom::multi::many0;
use nom::sequence::{preceded, tuple};
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

/// Encountered invalid values for key-value params when parsing an [`IceCandidate`]
#[derive(Debug, thiserror::Error)]
#[error("failed to parse candidate")]
pub struct InvalidCandidateParamError;

/// Used by [`IceCandidate`]
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum UntaggedAddress {
    Fqdn(BytesStr),
    IpAddress(IpAddr),
}

impl UntaggedAddress {
    fn parse(src: &Bytes) -> impl FnMut(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            map(take_while(probe_host6), |address| {
                if let Ok(address) = IpAddr::from_str(address) {
                    UntaggedAddress::IpAddress(address)
                } else {
                    UntaggedAddress::Fqdn(BytesStr::from_parse(src, address))
                }
            })(i)
        }
    }
}

impl fmt::Display for UntaggedAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self {
            UntaggedAddress::Fqdn(str) => str.fmt(f),
            UntaggedAddress::IpAddress(addr) => addr.fmt(f),
        }
    }
}

/// ICE Candidate (`a=candidate`)
///
/// [RFC5245](https://tools.ietf.org/html/rfc5245#section-15.1)
#[derive(Debug, Clone)]
pub struct IceCandidate {
    /// Session unique ID assigned to the candidate
    pub foundation: BytesStr,

    /// Identifies the specific component of the media stream for which this is a candidate.
    ///
    /// e.g. RTP is 1 and RTCP is 2
    pub component: u32,

    /// Transport protocol used by the candidate.
    ///
    /// Usually UDP or TCP
    pub transport: BytesStr,

    /// Candidate priority
    pub priority: u64,

    /// Address of the candidate
    pub address: UntaggedAddress,

    /// Port of the candidate
    pub port: u16,

    /// Candidate typ
    ///
    /// Defined are:  
    /// - `host`: host
    /// - `srflx`: server reflexive
    /// - `prflx`: peer reflexive
    /// - `relay`: relayed candidate
    /// - or something entirely else
    pub typ: BytesStr,

    /// Required for candidate typ `srflx`, `prflx` and `relay`
    ///
    /// Transport address
    pub rel_addr: Option<UntaggedAddress>,

    /// Required for candidate typ `srflx`, `prflx` and `relay`
    ///
    /// Transport port
    pub rel_port: Option<u16>,

    /// Params that aren't known to this crate
    pub unknown: Vec<(BytesStr, BytesStr)>,
}

impl IceCandidate {
    pub fn parse<'i>(src: &Bytes, i: &'i str) -> IResult<&'i str, Self> {
        map_res(
                preceded(
                    tag("candidate:"),
                    tuple((
                        // foundation
                        take_while_m_n(1, 32, ice_char),
                        ws((
                            // component id
                            map_res(digit1, FromStr::from_str),
                            // transport
                            take_while(not_whitespace),
                            // priority
                            map_res(digit1, FromStr::from_str),
                            // address
                            UntaggedAddress::parse(src),
                            // port
                            map_res(digit1, FromStr::from_str),
                            // candidate type
                            preceded(tag("typ"), ws((take_while1(not_whitespace),))),
                        )),
                        // extensions
                        many0(ws((
                            // key
                            take_while1(not_whitespace),
                            // value
                            take_while1(not_whitespace),
                        ))),
                    )),
                ),
                |(foundation, (component, transport, priority, address, port, type_), p_ext)| -> Result<IceCandidate, InvalidCandidateParamError> {
                    let mut unknown = vec![];

                    let mut rel_addr = None;
                    let mut rel_port = None;

                    for (key, value) in p_ext {
                        match key {
                            "raddr" => rel_addr = Some(UntaggedAddress::parse(src)(value).map_err(|_| InvalidCandidateParamError)?.1),
                            "rport" => rel_port = Some(u16::from_str(value).map_err(|_| InvalidCandidateParamError)?),
                            _ => unknown.push((
                                BytesStr::from_parse(src, key),
                                BytesStr::from_parse(src, value),
                            )),
                        }
                    }

                    Ok(IceCandidate {
                        foundation: BytesStr::from_parse(src, foundation),
                        component,
                        transport: BytesStr::from_parse(src, transport),
                        priority,
                        address,
                        port,
                        typ: BytesStr::from_parse(src, type_.0),
                        rel_addr,
                        rel_port,
                        unknown,
                    })
                }
            )(i)
    }
}

impl fmt::Display for IceCandidate {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "a=candidate:{} {} {} {} {} {} typ {}",
            self.foundation,
            self.component,
            self.transport,
            self.priority,
            self.address,
            self.port,
            self.typ
        )?;

        if let Some(rel_addr) = &self.rel_addr {
            write!(f, " raddr {}", rel_addr)?;
        }

        if let Some(rel_port) = &self.rel_port {
            write!(f, " rport {}", rel_port)?;
        }

        for (key, value) in &self.unknown {
            write!(f, " {} {}", key, value)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn candidate() {
        let input = BytesStr::from_static(
            "candidate:12 2 TCP 2105458942 192.168.56.1 9 typ host raddr 192.168.1.22 rport 123 tcptype active",
        );

        let (rem, candidate) = IceCandidate::parse(input.as_ref(), &input).unwrap();

        assert_eq!(candidate.foundation, "12");
        assert_eq!(candidate.component, 2);
        assert_eq!(candidate.transport, "TCP");
        assert_eq!(candidate.priority, 2105458942);
        assert_eq!(
            candidate.address,
            UntaggedAddress::IpAddress(IpAddr::V4(Ipv4Addr::new(192, 168, 56, 1)))
        );
        assert_eq!(candidate.port, 9);
        assert_eq!(candidate.typ, "host");
        assert_eq!(
            candidate.rel_addr,
            Some(UntaggedAddress::IpAddress(IpAddr::V4(Ipv4Addr::new(
                192, 168, 1, 22
            ))))
        );
        assert_eq!(candidate.rel_port, Some(123));
        assert_eq!(
            candidate.unknown[0],
            (
                BytesStr::from_static("tcptype"),
                BytesStr::from_static("active")
            )
        );

        assert!(rem.is_empty());
    }

    #[test]
    fn candidate_print() {
        let candidate = IceCandidate {
            foundation: "1".into(),
            component: 1,
            transport: "UDP".into(),
            priority: 1,
            address: UntaggedAddress::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            port: 9,
            typ: "host".into(),
            rel_addr: None,
            rel_port: None,
            unknown: vec![],
        };

        assert_eq!(
            candidate.to_string(),
            "a=candidate:1 1 UDP 1 127.0.0.1 9 typ host"
        );
    }
}
