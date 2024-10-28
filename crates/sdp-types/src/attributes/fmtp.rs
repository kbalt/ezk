//! Format parameters attribute (`a=fmtp:...`)

use bytes::Bytes;
use bytesstr::BytesStr;
use internal::{ws, IResult};
use nom::bytes::complete::tag;
use nom::character::complete::digit1;
use nom::combinator::{map, map_res};
use nom::error::context;
use nom::sequence::preceded;
use std::fmt;
use std::str::FromStr;

/// Fmtp attribute (`a=fmtp`)
///
/// Specify additional parameters for a format specified by a `rtpmap` in a media description
///
/// [RFC8866](https://www.rfc-editor.org/rfc/rfc8866.html#section-6.15)
#[derive(Debug, Clone)]
pub struct Fmtp {
    /// The format the parameter is for
    pub format: u8,

    /// The parameters as string
    pub params: BytesStr,
}

impl Fmtp {
    pub fn parse<'i>(src: &Bytes, i: &'i str) -> IResult<&'i str, Self> {
        context(
            "parsing fmtp",
            map(
                preceded(
                    tag("fmtp:"),
                    ws((
                        // format & remaining into params
                        map_res(digit1, FromStr::from_str),
                        |remaining| Ok(("", remaining)),
                    )),
                ),
                |(format, params)| Fmtp {
                    format,
                    params: BytesStr::from_parse(src, params),
                },
            ),
        )(i)
    }
}

impl fmt::Display for Fmtp {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a=fmtp:{} {}", self.format, self.params)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn fmtp() {
        let input = BytesStr::from_static("fmtp:111 some=param");

        let (rem, fmtp) = Fmtp::parse(input.as_ref(), &input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(fmtp.format, 111);
        assert_eq!(fmtp.params, "some=param");
    }

    #[test]
    fn fmtp_print() {
        let fmtp = Fmtp {
            format: 111,
            params: "some=param".into(),
        };

        assert_eq!(fmtp.to_string(), "a=fmtp:111 some=param");
    }
}
