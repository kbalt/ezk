use std::fmt;

use bytes::Bytes;
use bytesstr::BytesStr;
use internal::IResult;
use nom::{
    branch::alt,
    bytes::complete::{is_not, tag, take_while1},
    character::complete::{char, u8, u32},
    combinator::{map, opt},
    error::context,
    sequence::{preceded, separated_pair, tuple},
};

use crate::not_whitespace;

#[derive(Debug, Clone)]
pub struct Ssrc {
    pub ssrc: u32,
    pub attribute: SourceAttribute,
}

#[derive(Debug, Clone)]
pub enum SourceAttribute {
    CName {
        cname: BytesStr,
    },
    PreviousSsrc {
        ssrc: u32,
    },
    Fmtp {
        pt: u8,
        params: BytesStr,
    },
    Other {
        name: BytesStr,
        value: Option<BytesStr>,
    },
}

impl Ssrc {
    pub fn parse<'i>(src: &Bytes, i: &'i str) -> IResult<&'i str, Self> {
        context(
            "parsing ssrc-attribute",
            map(
                separated_pair(
                    u32,
                    take_while1(char::is_whitespace),
                    alt((
                        // cname
                        map(
                            preceded(tag("cname:"), take_while1(|c: char| !c.is_whitespace())),
                            |cname| SourceAttribute::CName {
                                cname: BytesStr::from_parse(src, cname),
                            },
                        ),
                        // previous ssrc
                        map(preceded(tag("previous-ssrc:"), u32), |ssrc| {
                            SourceAttribute::PreviousSsrc { ssrc }
                        }),
                        // fmtp
                        map(
                            tuple((
                                preceded(tag("fmtp:"), u8),
                                preceded(
                                    take_while1(char::is_whitespace),
                                    take_while1(not_whitespace),
                                ),
                            )),
                            |(pt, params)| SourceAttribute::Fmtp {
                                pt,
                                params: BytesStr::from_parse(src, params),
                            },
                        ),
                        // other
                        map(
                            tuple((is_not(":"), opt(preceded(char(':'), take_while1(|_| true))))),
                            |(key, value)| SourceAttribute::Other {
                                name: BytesStr::from_parse(src, key),
                                value: value.map(|value| BytesStr::from_parse(src, value)),
                            },
                        ),
                    )),
                ),
                |(ssrc, attribute)| Self { ssrc, attribute },
            ),
        )(i)
    }
}

impl fmt::Display for Ssrc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ", self.ssrc)?;

        match &self.attribute {
            SourceAttribute::CName { cname } => write!(f, "cname:{cname}"),
            SourceAttribute::PreviousSsrc { ssrc } => write!(f, "previous-ssrc:{ssrc}"),
            SourceAttribute::Fmtp { pt, params } => write!(f, "fmtp:{pt} {params}"),
            SourceAttribute::Other {
                name,
                value: Some(value),
            } => write!(f, "{name}:{value}"),
            SourceAttribute::Other { name, value: None } => write!(f, "{name}"),
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn ssrc_cname() {
        let input = BytesStr::from_static("1234 cname:mycname");

        let (rem, ssrc) = Ssrc::parse(input.as_ref(), &input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(ssrc.ssrc, 1234);
        if let SourceAttribute::CName { cname } = ssrc.attribute {
            assert_eq!(cname, "mycname")
        } else {
            panic!()
        }
    }

    #[test]
    fn ssrc_previous_ssrc() {
        let input = BytesStr::from_static("1234 previous-ssrc:4321");

        let (rem, ssrc) = Ssrc::parse(input.as_ref(), &input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(ssrc.ssrc, 1234);
        if let SourceAttribute::PreviousSsrc { ssrc } = ssrc.attribute {
            assert_eq!(ssrc, 4321)
        } else {
            panic!()
        }
    }

    #[test]
    fn ssrc_fmtp() {
        let input = BytesStr::from_static("1234 fmtp:99 myparams");

        let (rem, ssrc) = Ssrc::parse(input.as_ref(), &input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(ssrc.ssrc, 1234);
        if let SourceAttribute::Fmtp { pt, params } = ssrc.attribute {
            assert_eq!(pt, 99);
            assert_eq!(params, "myparams");
        } else {
            panic!()
        }
    }

    #[test]
    fn ssrc_cname_print() {
        let ssrc = Ssrc {
            ssrc: 1234,
            attribute: SourceAttribute::CName {
                cname: "mycname".into(),
            },
        };

        assert_eq!(ssrc.to_string(), "1234 cname:mycname");
    }

    #[test]
    fn ssrc_previous_ssrc_print() {
        let ssrc = Ssrc {
            ssrc: 1234,
            attribute: SourceAttribute::PreviousSsrc { ssrc: 4321 },
        };

        assert_eq!(ssrc.to_string(), "1234 previous-ssrc:4321");
    }

    #[test]
    fn ssrc_fmtp_print() {
        let ssrc = Ssrc {
            ssrc: 1234,
            attribute: SourceAttribute::Fmtp {
                pt: 99,
                params: "myparams".into(),
            },
        };

        assert_eq!(ssrc.to_string(), "1234 fmtp:99 myparams");
    }
}
