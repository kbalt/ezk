use crate::{not_whitespace, slash_num};
use bytes::Bytes;
use bytesstr::BytesStr;
use internal::{ws, IResult};
use nom::branch::alt;
use nom::bytes::complete::{tag, take_while1};
use nom::character::complete::digit1;
use nom::combinator::{map, map_res, opt};
use nom::error::context;
use nom::multi::many0;
use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MediaType {
    Audio,
    Video,
    Text,
    App,
}

impl MediaType {
    pub fn parse(i: &str) -> IResult<&str, Self> {
        context(
            "parsing media type",
            alt((
                map(tag("audio"), |_| MediaType::Audio),
                map(tag("video"), |_| MediaType::Video),
                map(tag("text"), |_| MediaType::Text),
                map(tag("application"), |_| MediaType::App),
            )),
        )(i)
    }
}

impl fmt::Display for MediaType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MediaType::Audio => f.write_str("audio"),
            MediaType::Video => f.write_str("video"),
            MediaType::Text => f.write_str("text"),
            MediaType::App => f.write_str("application"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportProtocol {
    Unspecified,

    /// RTP over UDP
    RtpAvp,

    /// SRTP over UDP
    RtpSavp,

    /// SRTP with [RFC5124](https://www.rfc-editor.org/rfc/rfc5124.html)
    RtpSavpf,

    /// DTLS-SRTP
    UdpTlsRtpSavp,

    /// DTLS-SRTP with [RFC5124](https://www.rfc-editor.org/rfc/rfc5124.html)
    UdpTlsRtpSavpf,

    /// Other unknown
    Other(BytesStr),
}

impl TransportProtocol {
    pub fn parse(src: &Bytes) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            alt((
                map(tag("udp"), |_| TransportProtocol::Unspecified),
                map(tag("RTP/AVP"), |_| TransportProtocol::RtpAvp),
                map(tag("RTP/SAVP"), |_| TransportProtocol::RtpSavp),
                map(tag("RTP/SAVPF"), |_| TransportProtocol::RtpSavpf),
                map(tag("UDP/TLS/RTP/SAVP"), |_| {
                    TransportProtocol::UdpTlsRtpSavp
                }),
                map(tag("UDP/TLS/RTP/SAVPF"), |_| {
                    TransportProtocol::UdpTlsRtpSavpf
                }),
                map(take_while1(not_whitespace), |tp| {
                    TransportProtocol::Other(BytesStr::from_parse(src, tp))
                }),
            ))(i)
        }
    }
}

impl fmt::Display for TransportProtocol {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TransportProtocol::Unspecified => f.write_str("udp"),
            TransportProtocol::RtpAvp => f.write_str("RTP/AVP"),
            TransportProtocol::RtpSavp => f.write_str("RTP/SAVP"),
            TransportProtocol::RtpSavpf => f.write_str("RTP/SAVPF"),
            TransportProtocol::UdpTlsRtpSavp => f.write_str("UDP/TLS/RTP/SAVP"),
            TransportProtocol::UdpTlsRtpSavpf => f.write_str("UDP/TLS/RTP/SAVPF"),
            TransportProtocol::Other(str) => f.write_str(str),
        }
    }
}

/// Media field (`m=`)
///
/// [RFC8866](https://www.rfc-editor.org/rfc/rfc8866.html#section-5.14)
#[derive(Debug, Clone)]
pub struct Media {
    pub media_type: MediaType,
    pub port: u16,
    pub ports_num: Option<u32>,
    pub proto: TransportProtocol,
    pub fmts: Vec<u8>,
}

impl Media {
    pub fn parse<'i>(src: &Bytes, i: &'i str) -> IResult<&'i str, Self> {
        context(
            "parsing media field",
            map(
                ws((
                    MediaType::parse,
                    map_res(digit1, FromStr::from_str),
                    opt(slash_num),
                    TransportProtocol::parse(src),
                    many0(map(ws((map_res(digit1, FromStr::from_str),)), |t| t.0)),
                )),
                |(media, port, ports_num, proto, fmts)| Media {
                    media_type: media,
                    port,
                    ports_num,
                    proto,
                    fmts,
                },
            ),
        )(i)
    }
}

impl fmt::Display for Media {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.media_type)?;

        if let Some(ports_num) = &self.ports_num {
            write!(f, " {}/{} ", self.port, ports_num)?;
        } else {
            write!(f, " {} ", self.port)?;
        }

        write!(f, "{}", self.proto)?;

        for fmt in &self.fmts {
            write!(f, " {}", fmt)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bytesstr::BytesStr;

    #[test]
    fn media() {
        let input = BytesStr::from_static("audio 49170 RTP/AVP 0");

        let (rem, media) = Media::parse(input.as_ref(), &input).unwrap();

        assert_eq!(media.media_type, MediaType::Audio);
        assert_eq!(media.port, 49170);
        assert!(media.ports_num.is_none());
        assert_eq!(media.proto, TransportProtocol::RtpAvp);
        assert_eq!(media.fmts, [0]);

        assert!(rem.is_empty());
    }
}
