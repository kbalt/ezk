use crate::{not_whitespace, TaggedAddress};
use bytes::Bytes;
use bytesstr::BytesStr;
use internal::{ws, IResult};
use nom::bytes::complete::take_while;
use nom::combinator::map;
use std::fmt;

/// Origin field (`o=`)
///
/// [RFC8866](https://www.rfc-editor.org/rfc/rfc8866.html#section-5.2)
#[derive(Debug, Clone)]
pub struct Origin {
    /// Username of the origin
    pub username: BytesStr,

    /// Globally unique session identifier
    pub session_id: BytesStr,

    /// The version of the session, changes with each modification/renegotiation.
    pub session_version: BytesStr,

    /// The source address of the message
    pub address: TaggedAddress,
}

impl Origin {
    pub fn parse<'i>(src: &Bytes, i: &'i str) -> IResult<&'i str, Self> {
        map(
            ws((
                // username
                take_while(not_whitespace),
                // Session ID
                take_while(not_whitespace),
                // Session Version
                take_while(not_whitespace),
                // Origin transport address
                TaggedAddress::parse(src),
            )),
            |(username, session_id, session_version, address)| Origin {
                username: BytesStr::from_parse(src, username),
                session_id: BytesStr::from_parse(src, session_id),
                session_version: BytesStr::from_parse(src, session_version),
                address,
            },
        )(i)
    }
}

impl fmt::Display for Origin {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "o={} {} {} {}",
            self.username, self.session_id, self.session_version, self.address
        )
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn origin() {
        let input = BytesStr::from_static("- 123456789 987654321 IN IP4 192.168.123.222");

        let (rem, origin) = Origin::parse(input.as_ref(), &input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(origin.username, "-");
        assert_eq!(origin.session_id, "123456789");
        assert_eq!(origin.session_version, "987654321");
        assert!(
            matches!(origin.address, TaggedAddress::IP4(ip) if ip == Ipv4Addr::new(192, 168, 123, 222))
        )
    }

    #[test]
    fn origin_print() {
        let origin = Origin {
            username: "-".into(),
            session_id: BytesStr::from_static("123456789"),
            session_version: BytesStr::from_static("987654321"),
            address: TaggedAddress::IP4(Ipv4Addr::new(192, 168, 123, 222)),
        };

        assert_eq!(
            origin.to_string(),
            "o=- 123456789 987654321 IN IP4 192.168.123.222"
        );
    }
}
