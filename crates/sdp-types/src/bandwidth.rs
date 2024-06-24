use bytes::Bytes;
use bytesstr::BytesStr;
use internal::IResult;
use nom::bytes::complete::{tag, take_while};
use nom::character::complete::digit1;
use nom::combinator::{map, map_res};
use nom::error::context;
use nom::sequence::tuple;
use std::fmt;
use std::str::FromStr;

/// Bandwidth field (`b=`)
///
/// [RFC8866](https://www.rfc-editor.org/rfc/rfc8866.html#section-5.8)
#[derive(Debug, Clone)]
pub struct Bandwidth {
    /// The type of bandwidth.
    /// Usually `AS` which stands for Application specific
    pub type_: BytesStr,

    /// The bandwidth.
    ///
    /// By default interpreted as kilobits per second
    /// but can be interpreted differently depending on the bandwidth type.
    pub bandwidth: u32,
}

impl Bandwidth {
    pub fn parse<'i>(src: &Bytes, i: &'i str) -> IResult<&'i str, Self> {
        context(
            "parsing bandwidth",
            map(
                tuple((
                    map(take_while(token), |m| BytesStr::from_parse(src, m)),
                    tag(":"),
                    map_res(digit1, FromStr::from_str),
                )),
                |(modifier, _, value)| Bandwidth {
                    type_: modifier,
                    bandwidth: value,
                },
            ),
        )(i)
    }
}

impl fmt::Display for Bandwidth {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "b={}:{}", self.type_, self.bandwidth)
    }
}

fn token(c: char) -> bool {
    matches!(c, '\x21' | '\x23'..='\x27' | '\x2A'..='\x2B' | '\x2D'..='\x2E' | '\x30'..='\x39' | '\x41'..='\x5A' | '\x5E'..='\x7E')
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn bandwidth() {
        let input = BytesStr::from_static("AS:96000");

        let (rem, bandwidth) = Bandwidth::parse(input.as_ref(), &input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(bandwidth.type_, "AS");
        assert_eq!(bandwidth.bandwidth, 96000);
    }

    #[test]
    fn bandwidth_print() {
        let origin = Bandwidth {
            type_: "AS".into(),
            bandwidth: 96000,
        };

        assert_eq!(origin.to_string(), "b=AS:96000");
    }
}
