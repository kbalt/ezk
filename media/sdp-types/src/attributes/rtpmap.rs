//! RtpMap attribute (`...`)

use bytes::Bytes;
use bytesstr::BytesStr;
use internal::{IResult, ws};
use nom::bytes::complete::{tag, take_while};
use nom::character::complete::digit1;
use nom::combinator::{map, map_res, opt};
use nom::error::context;
use nom::sequence::{preceded, terminated, tuple};
use std::fmt;
use std::str::FromStr;

/// Rtpmap attribute (`a=rtpmap`)
///
/// Map a RTP payload number specified in the media description to a encoding.
///
/// Media-Level attribute
///
/// [RFC8866](https://www.rfc-editor.org/rfc/rfc8866.html#section-6.6)
#[derive(Debug, Clone)]
pub struct RtpMap {
    /// The number used in the media description which this maps a description to
    pub payload: u8,

    /// Name of the encoding
    pub encoding: BytesStr,

    /// Clock rate of the encoding
    pub clock_rate: u32,

    /// Additional parameters as a string
    pub params: Option<BytesStr>,
}

impl RtpMap {
    pub fn parse<'i>(src: &Bytes, i: &'i str) -> IResult<&'i str, Self> {
        context(
            "parsing rtpmap",
            map(
                tuple((
                    // payload num
                    map_res(digit1, FromStr::from_str),
                    // encoding
                    ws((terminated(
                        map(take_while(|c| c != '/'), |slice| {
                            BytesStr::from_parse(src, slice)
                        }),
                        tag("/"),
                    ),)),
                    // clock rate
                    map_res(digit1, FromStr::from_str),
                    // optional params
                    opt(preceded(tag("/"), |rem| {
                        Ok(("", BytesStr::from_parse(src, rem)))
                    })),
                )),
                |(payload, (encoding,), clock_rate, params)| RtpMap {
                    payload,
                    encoding,
                    clock_rate,
                    params,
                },
            ),
        )(i)
    }
}

impl fmt::Display for RtpMap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}/{}", self.payload, self.encoding, self.clock_rate)?;

        if let Some(params) = &self.params {
            let _ = write!(f, "/{params}");
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn rtpmap() {
        let input = BytesStr::from_static("0 PCMU/8000");

        let (rem, rtpmap) = RtpMap::parse(input.as_ref(), &input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(rtpmap.payload, 0);
        assert_eq!(rtpmap.encoding, "PCMU");
        assert_eq!(rtpmap.clock_rate, 8000);
        assert_eq!(rtpmap.params, None);
    }

    #[test]
    fn rtpmap_params() {
        let input = BytesStr::from_static("0 PCMU/8000/1");

        let (rem, rtpmap) = RtpMap::parse(input.as_ref(), &input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(rtpmap.payload, 0);
        assert_eq!(rtpmap.encoding, "PCMU");
        assert_eq!(rtpmap.clock_rate, 8000);
        assert_eq!(rtpmap.params.unwrap(), "1");
    }

    #[test]
    fn rtpmap_print() {
        let rtpmap = RtpMap {
            payload: 0,
            encoding: "PCMU".into(),
            clock_rate: 8000,
            params: None,
        };

        assert_eq!(rtpmap.to_string(), "0 PCMU/8000");
    }

    #[test]
    fn rtpmap_params_print() {
        let rtpmap = RtpMap {
            payload: 0,
            encoding: "PCMU".into(),
            clock_rate: 8000,
            params: Some("1".into()),
        };

        assert_eq!(rtpmap.to_string(), "0 PCMU/8000/1");
    }
}
