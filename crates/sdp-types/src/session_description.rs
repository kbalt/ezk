use crate::connection::Connection;
use crate::media::Media;
use crate::origin::Origin;
use crate::time::Time;
use crate::{bandwidth::Bandwidth, Rtcp};
use crate::{
    Direction, Fmtp, IceCandidate, IceOptions, IcePassword, IceUsernameFragment, RtpMap,
    SrtpCrypto, UnknownAttribute,
};
use bytesstr::BytesStr;
use internal::{verbose_error_to_owned, Finish};
use std::fmt::{self, Debug};

#[derive(Debug, thiserror::Error)]
pub enum ParseSessionDescriptionError {
    #[error("{0}")]
    ParseError(nom::error::VerboseError<String>),
    #[error("message ended unexpectedly")]
    Incomplete,
    #[error("message is missing the origin field (o=)")]
    MissingOrigin,
    #[error("message is missing the name (s=) field")]
    MissingName,
    #[error("message is missing the time (t=) field")]
    MissingTime,
}

impl From<nom::error::VerboseError<&str>> for ParseSessionDescriptionError {
    fn from(value: nom::error::VerboseError<&str>) -> Self {
        Self::ParseError(verbose_error_to_owned(value))
    }
}

/// Part of the [`SessionDescription`] describes a single media session
///
/// [RFC8866](https://www.rfc-editor.org/rfc/rfc8866.html#section-5.14)
#[derive(Debug, Clone)]
pub struct MediaDescription {
    /// Media description's media field (m=)
    pub media: Media,

    /// Media direction
    pub direction: Direction,

    /// Optional connection (c field)
    pub connection: Option<Connection>,

    /// Optional bandwidths (b fields)
    pub bandwidth: Vec<Bandwidth>,

    /// rtcp attribute
    pub rtcp_attr: Option<Rtcp>,

    /// RTP Payload mappings
    pub rtpmaps: Vec<RtpMap>,

    /// RTP encoding parameters
    pub fmtps: Vec<Fmtp>,

    /// ICE username fragment
    pub ice_ufrag: Option<IceUsernameFragment>,

    /// ICE password
    pub ice_pwd: Option<IcePassword>,

    /// ICE candidates
    pub ice_candidates: Vec<IceCandidate>,

    /// ICE a=end-of-candidates attribute
    pub ice_end_of_candidates: bool,

    /// Crypto attributes
    pub crypto: Vec<SrtpCrypto>,

    /// Additional attributes
    pub attributes: Vec<UnknownAttribute>,
}

impl fmt::Display for MediaDescription {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}\r\n", self.media)?;

        if let Some(conn) = &self.connection {
            write!(f, "{}\r\n", conn)?;
        }

        for bw in &self.bandwidth {
            write!(f, "{}\r\n", bw)?;
        }

        write!(f, "{}\r\n", self.direction)?;

        if let Some(rtcp) = &self.rtcp_attr {
            write!(f, "{}\r\n", rtcp)?;
        }

        for rtpmap in &self.rtpmaps {
            write!(f, "{}\r\n", rtpmap)?;
        }

        for fmtp in &self.fmtps {
            write!(f, "{}\r\n", fmtp)?;
        }

        if let Some(ufrag) = &self.ice_ufrag {
            write!(f, "{}\r\n", ufrag)?;
        }

        if let Some(pwd) = &self.ice_pwd {
            write!(f, "{}\r\n", pwd)?;
        }

        for crypto in &self.crypto {
            write!(f, "a=crypto:{crypto}\r\n")?;
        }

        for attr in &self.attributes {
            write!(f, "{}\r\n", attr)?;
        }

        Ok(())
    }
}

/// The Session Description message. Can be serialized to valid SDP using the [`fmt::Display`] implementation and
/// parse SDP using [`SessionDescription::parse`].
#[derive(Debug, Clone)]
pub struct SessionDescription {
    /// The name of the sdp session (s field)
    pub name: BytesStr,

    /// Origin (o field)
    pub origin: Origin,

    /// Session start/stop time (t field)
    pub time: Time,

    /// Global session media direction
    pub direction: Direction,

    /// Optional connection (c field)
    pub connection: Option<Connection>,

    /// Bandwidth (b field)
    pub bandwidth: Vec<Bandwidth>,

    /// ICE options, omitted if empty
    pub ice_options: IceOptions,

    /// If not present: false
    ///
    /// If specified an ice-lite implementation is used
    pub ice_lite: bool,

    /// ICE username fragment
    pub ice_ufrag: Option<IceUsernameFragment>,

    /// ICE password
    pub ice_pwd: Option<IcePassword>,

    /// All attributes not parsed directly
    pub attributes: Vec<UnknownAttribute>,

    /// Media descriptions
    pub media_descriptions: Vec<MediaDescription>,
}

impl SessionDescription {
    pub fn parse(src: &BytesStr) -> Result<Self, ParseSessionDescriptionError> {
        let lines = src
            .split(|c| matches!(c, '\n' | '\r'))
            .filter(|line| !line.is_empty());

        let mut parser = Parser::default();

        for complete_line in lines {
            parser.parse_line(src, complete_line)?;
        }

        parser.finish()
    }
}

impl fmt::Display for SessionDescription {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "\
v=0\r\n\
{}\r\n\
s={}\r\n\
",
            self.origin, self.name
        )?;

        if let Some(conn) = &self.connection {
            write!(f, "{conn}\r\n")?;
        }

        for bw in &self.bandwidth {
            write!(f, "{bw}\r\n")?;
        }

        write!(f, "{}\r\n{}", self.time, self.ice_options)?;

        if self.ice_lite {
            f.write_str("a=ice-lite\r\n")?;
        }

        if let Some(ufrag) = &self.ice_ufrag {
            write!(f, "{ufrag}\r\n")?;
        }

        if let Some(pwd) = &self.ice_pwd {
            write!(f, "{pwd}\r\n")?;
        }

        for attr in &self.attributes {
            write!(f, "{attr}\r\n")?;
        }

        for media_description in &self.media_descriptions {
            write!(f, "{media_description}")?;
        }

        Ok(())
    }
}

#[derive(Default)]
struct Parser {
    name: Option<BytesStr>,
    origin: Option<Origin>,
    time: Option<Time>,
    direction: Direction,
    connection: Option<Connection>,
    bandwidth: Vec<Bandwidth>,
    ice_options: IceOptions,
    ice_lite: bool,
    ice_ufrag: Option<IceUsernameFragment>,
    ice_pwd: Option<IcePassword>,
    attributes: Vec<UnknownAttribute>,
    media_descriptions: Vec<MediaDescription>,
}

impl Parser {
    fn parse_line(
        &mut self,
        src: &BytesStr,
        complete_line: &str,
    ) -> Result<(), ParseSessionDescriptionError> {
        let line = complete_line
            .get(2..)
            .ok_or(ParseSessionDescriptionError::Incomplete)?;

        match complete_line.as_bytes() {
            [b'v', b'=', b'0'] => {
                // parsed the version yay!
            }
            [b's', b'=', ..] => {
                self.name = Some(BytesStr::from_parse(src.as_ref(), line));
            }
            [b'o', b'=', ..] => {
                let (_, o) = Origin::parse(src.as_ref(), line).finish()?;
                self.origin = Some(o);
            }
            [b't', b'=', ..] => {
                let (_, t) = Time::parse(line).finish()?;
                self.time = Some(t);
            }
            [b'c', b'=', ..] => {
                let (_, c) = Connection::parse(src.as_ref(), line).finish()?;

                if let Some(media_description) = self.media_descriptions.last_mut() {
                    media_description.connection = Some(c);
                } else {
                    self.connection = Some(c);
                }
            }
            [b'b', b'=', ..] => {
                let (_, b) = Bandwidth::parse(src.as_ref(), line).finish()?;

                if let Some(media_description) = self.media_descriptions.last_mut() {
                    media_description.bandwidth.push(b);
                } else {
                    self.bandwidth.push(b);
                }
            }
            [b'm', b'=', ..] => {
                let (_, media) = Media::parse(src.as_ref(), line).finish()?;

                self.media_descriptions.push(MediaDescription {
                    media,
                    // inherit session direction
                    direction: self.direction,
                    connection: None,
                    bandwidth: vec![],
                    rtcp_attr: None,
                    rtpmaps: vec![],
                    fmtps: vec![],
                    ice_ufrag: None,
                    ice_pwd: None,
                    ice_candidates: vec![],
                    ice_end_of_candidates: false,
                    crypto: vec![],
                    attributes: vec![],
                });
            }
            [b'a', b'=', ..] => self.parse_attribute(src, line)?,
            _ => {}
        }

        Ok(())
    }

    fn parse_attribute(
        &mut self,
        src: &BytesStr,
        line: &str,
    ) -> Result<(), ParseSessionDescriptionError> {
        if let Some((name, value)) = line.split_once(':') {
            self.parse_attribute_with_value(src, line, name, value)?;
        } else {
            self.parse_attribute_without_value(src, line);
        }

        Ok(())
    }

    fn parse_attribute_with_value(
        &mut self,
        src: &BytesStr,
        line: &str,
        name: &str,
        value: &str,
    ) -> Result<(), ParseSessionDescriptionError> {
        match name {
            "rtpmap" => {
                let (_, rtpmap) = RtpMap::parse(src.as_ref(), line).finish()?;

                if let Some(media_description) = self.media_descriptions.last_mut() {
                    media_description.rtpmaps.push(rtpmap);
                }

                // TODO error here ?
            }
            "fmtp" => {
                let (_, fmtp) = Fmtp::parse(src.as_ref(), line).finish()?;

                if let Some(media_description) = self.media_descriptions.last_mut() {
                    media_description.fmtps.push(fmtp);
                }

                // TODO error here ?
            }
            "rtcp" => {
                let (_, rtcp) = Rtcp::parse(src.as_ref(), line).finish()?;

                if let Some(media_description) = self.media_descriptions.last_mut() {
                    media_description.rtcp_attr = Some(rtcp);
                }

                // TODO error here?
            }
            "ice-lite" => {
                self.ice_lite = true;
            }
            "ice-options" => {
                let (_, options) = IceOptions::parse(src.as_ref(), value).finish()?;
                self.ice_options = options;
            }
            "ice-ufrag" => {
                let (_, ufrag) = IceUsernameFragment::parse(src.as_ref(), value).finish()?;

                if let Some(media_description) = self.media_descriptions.last_mut() {
                    media_description.ice_ufrag = Some(ufrag);
                } else {
                    self.ice_ufrag = Some(ufrag);
                }
            }
            "ice-pwd" => {
                let (_, pwd) = IcePassword::parse(src.as_ref(), value).finish()?;

                if let Some(media_description) = self.media_descriptions.last_mut() {
                    media_description.ice_pwd = Some(pwd);
                } else {
                    self.ice_pwd = Some(pwd);
                }
            }
            "candidate" => {
                let (_, candidate) = IceCandidate::parse(src.as_ref(), line).finish()?;

                if let Some(media_description) = self.media_descriptions.last_mut() {
                    media_description.ice_candidates.push(candidate);
                }

                // TODO error here?
            }
            "crypto" => {
                let (_, crypto) = SrtpCrypto::parse(src.as_ref(), value).finish()?;

                if let Some(media_description) = self.media_descriptions.last_mut() {
                    media_description.crypto.push(crypto);
                }

                // TODO error here?
            }
            _ => {
                let attr = UnknownAttribute {
                    name: src.slice_ref(name),
                    value: Some(src.slice_ref(value)),
                };

                if let Some(media_description) = self.media_descriptions.last_mut() {
                    media_description.attributes.push(attr);
                } else {
                    self.attributes.push(attr);
                }
            }
        }

        Ok(())
    }

    fn parse_attribute_without_value(&mut self, src: &BytesStr, line: &str) {
        let direction = if let Some(media_description) = self.media_descriptions.last_mut() {
            &mut media_description.direction
        } else {
            &mut self.direction
        };

        match line {
            "sendrecv" => *direction = Direction::SendRecv,
            "recvonly" => *direction = Direction::RecvOnly,
            "sendonly" => *direction = Direction::SendOnly,
            "inactive" => *direction = Direction::Inactive,
            "end-of-candidates" => {
                if let Some(media_description) = self.media_descriptions.last_mut() {
                    media_description.ice_end_of_candidates = true;
                }

                // TODO error here?
            }
            _ => {
                let attr = UnknownAttribute {
                    name: src.slice_ref(line),
                    value: None,
                };

                if let Some(media_description) = self.media_descriptions.last_mut() {
                    media_description.attributes.push(attr);
                } else {
                    self.attributes.push(attr);
                }
            }
        }
    }

    fn finish(self) -> Result<SessionDescription, ParseSessionDescriptionError> {
        Ok(SessionDescription {
            origin: self
                .origin
                .ok_or(ParseSessionDescriptionError::MissingOrigin)?,
            name: self.name.ok_or(ParseSessionDescriptionError::MissingName)?,
            time: self.time.ok_or(ParseSessionDescriptionError::MissingTime)?,
            direction: self.direction,
            connection: self.connection,
            bandwidth: self.bandwidth,
            ice_options: self.ice_options,
            ice_lite: self.ice_lite,
            ice_ufrag: self.ice_ufrag,
            ice_pwd: self.ice_pwd,
            attributes: self.attributes,
            media_descriptions: self.media_descriptions,
        })
    }
}
