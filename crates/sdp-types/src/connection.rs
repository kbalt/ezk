use crate::{slash_num, TaggedAddress};
use bytes::Bytes;
use internal::IResult;
use nom::combinator::opt;
use nom::sequence::pair;
use std::fmt;

/// Connection field
///
/// [RFC8866](https://www.rfc-editor.org/rfc/rfc8866.html#section-5.7)
#[derive(Debug, Clone)]
pub struct Connection {
    /// The connection address
    pub address: TaggedAddress,

    /// Must be set for IPv4 multicast sessions
    pub ttl: Option<u32>,

    /// Number of addresses
    pub num: Option<u32>,
}

impl Connection {
    pub fn parse<'i>(src: &Bytes, i: &'i str) -> IResult<&'i str, Self> {
        let (i, address) = TaggedAddress::parse(src)(i)?;

        match &address {
            TaggedAddress::IP4(_) | TaggedAddress::IP4FQDN(_) => {
                let (i, ttl) = opt(pair(slash_num, opt(slash_num)))(i)?;

                let (ttl, num) = match ttl {
                    None => (None, None),
                    Some((ttl, num)) => (Some(ttl), num),
                };

                Ok((i, Connection { address, ttl, num }))
            }
            TaggedAddress::IP6(_) | TaggedAddress::IP6FQDN(_) => {
                let (i, num) = opt(slash_num)(i)?;

                Ok((
                    i,
                    Connection {
                        address,
                        ttl: None,
                        num,
                    },
                ))
            }
        }
    }
}

impl fmt::Display for Connection {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "c={}", self.address)?;

        match self.address {
            TaggedAddress::IP4(_) | TaggedAddress::IP4FQDN(_) => {
                if let Some(ttl) = self.ttl {
                    write!(f, "/{}", ttl)?;

                    if let Some(num) = self.num {
                        write!(f, "/{}", num)?;
                    }
                }
            }
            TaggedAddress::IP6(_) | TaggedAddress::IP6FQDN(_) => {
                if let Some(num) = self.num {
                    write!(f, "/{}", num)?;
                }
            }
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
    fn connection() {
        let input = BytesStr::from_static("IN IP4 192.168.123.222");

        let (rem, connection) = Connection::parse(input.as_ref(), &input).unwrap();

        assert!(rem.is_empty());

        assert!(
            matches!(connection.address, TaggedAddress::IP4(ip) if ip == Ipv4Addr::new(192, 168, 123, 222))
        )
    }

    #[test]
    fn connection_ttl() {
        let input = BytesStr::from_static("IN IP4 192.168.123.222/127");

        let (rem, connection) = Connection::parse(input.as_ref(), &input).unwrap();

        assert!(rem.is_empty());

        assert!(
            matches!(connection.address, TaggedAddress::IP4(ip) if ip == Ipv4Addr::new(192, 168, 123, 222))
        );
        assert_eq!(connection.ttl, Some(127));
        assert_eq!(connection.num, None);
    }

    #[test]
    fn connection_ttl_num() {
        let input = BytesStr::from_static("IN IP4 192.168.123.222/127/3");

        let (rem, connection) = Connection::parse(input.as_ref(), &input).unwrap();

        assert!(rem.is_empty());

        assert!(
            matches!(connection.address, TaggedAddress::IP4(ip) if ip == Ipv4Addr::new(192, 168, 123, 222))
        );
        assert_eq!(connection.ttl, Some(127));
        assert_eq!(connection.num, Some(3));
    }

    #[test]
    fn connection_print() {
        let connection = Connection {
            address: TaggedAddress::IP4(Ipv4Addr::new(192, 168, 123, 222)),
            ttl: None,
            num: None,
        };

        assert_eq!(connection.to_string(), "c=IN IP4 192.168.123.222");
    }

    #[test]
    fn connection_print_ttl() {
        let connection = Connection {
            address: TaggedAddress::IP4(Ipv4Addr::new(192, 168, 0, 1)),
            ttl: Some(127),
            num: None,
        };

        assert_eq!(connection.to_string(), "c=IN IP4 192.168.0.1/127");
    }

    #[test]
    fn connection_print_ttl_num() {
        let connection = Connection {
            address: TaggedAddress::IP4(Ipv4Addr::new(192, 168, 0, 1)),
            ttl: Some(127),
            num: Some(3),
        };

        assert_eq!(connection.to_string(), "c=IN IP4 192.168.0.1/127/3");
    }

    #[test]
    fn connection_print_num_without_ttl() {
        let connection = Connection {
            address: TaggedAddress::IP4(Ipv4Addr::new(192, 168, 0, 1)),
            ttl: None,
            num: Some(3),
        };

        assert_eq!(connection.to_string(), "c=IN IP4 192.168.0.1");
    }
}
