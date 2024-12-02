use crate::attributes::Group;
use crate::connection::Connection;
use crate::media::Media;
use crate::origin::Origin;
use crate::time::Time;
use crate::{bandwidth::Bandwidth, Rtcp};
use crate::{
    Direction, ExtMap, Fmtp, IceCandidate, IceOptions, IcePassword, IceUsernameFragment, RtpMap,
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

    /// Optional connection (c field)
    pub connection: Option<Connection>,

    /// Optional bandwidths (b fields)
    pub bandwidth: Vec<Bandwidth>,

    /// Media direction attribute
    pub direction: Direction,

    /// rtcp attribute
    pub rtcp: Option<Rtcp>,

    /// rtcp-mux attribute
    pub rtcp_mux: bool,

    /// Media ID (a=mid)
    pub mid: Option<BytesStr>,

    /// RTP Payload mappings
    pub rtpmap: Vec<RtpMap>,

    /// RTP encoding parameters
    pub fmtp: Vec<Fmtp>,

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

    /// ExtMap attributes
    pub extmap: Vec<ExtMap>,

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
            write!(f, "b={bw}\r\n")?;
        }

        write!(f, "a={}\r\n", self.direction)?;

        if let Some(rtcp) = &self.rtcp {
            write!(f, "a=rtcp:{}\r\n", rtcp)?;
        }

        if self.rtcp_mux {
            write!(f, "a=rtcp-mux\r\n")?;
        }

        if let Some(mid) = &self.mid {
            write!(f, "a=mid:{}\r\n", mid)?;
        }

        for rtpmap in &self.rtpmap {
            write!(f, "a=rtpmap:{}\r\n", rtpmap)?;
        }

        for fmtp in &self.fmtp {
            write!(f, "a=fmtp:{}\r\n", fmtp)?;
        }

        if let Some(ufrag) = &self.ice_ufrag {
            write!(f, "{}\r\n", ufrag)?;
        }

        if let Some(pwd) = &self.ice_pwd {
            write!(f, "{}\r\n", pwd)?;
        }

        for candidate in &self.ice_candidates {
            write!(f, "a=candidate:{candidate}\r\n")?;
        }

        if self.ice_end_of_candidates {
            write!(f, "a=end-of-candidates\r\n")?;
        }

        for crypto in &self.crypto {
            write!(f, "a=crypto:{crypto}\r\n")?;
        }

        for extmap in &self.extmap {
            write!(f, "a=extmap:{extmap}\r\n")?;
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
    /// Origin (o field)
    pub origin: Origin,

    /// The name of the sdp session (s field)
    pub name: BytesStr,

    /// Optional connection (c field)
    pub connection: Option<Connection>,

    /// Bandwidth (b field)
    pub bandwidth: Vec<Bandwidth>,

    /// Session start/stop time (t field)
    pub time: Time,

    /// Global session media direction attribute
    pub direction: Direction,

    /// Media groups (a=group)
    pub group: Vec<Group>,

    /// Extmap attribute (a=extmap)
    pub extmap: Vec<ExtMap>,

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
        let lines = src.split(['\n', '\r']).filter(|line| !line.is_empty());

        let mut parser = Parser::default();

        for complete_line in lines {
            parser.parse_line(src, complete_line)?;
        }

        parser.finish()
    }
}

impl fmt::Display for SessionDescription {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "v=0\r\n")?;
        write!(f, "o={}\r\n", self.origin)?;
        write!(f, "s={}\r\n", self.name)?;

        if let Some(conn) = &self.connection {
            write!(f, "{conn}\r\n")?;
        }

        for bw in &self.bandwidth {
            write!(f, "b={bw}\r\n")?;
        }

        write!(f, "{}\r\n", self.time)?;

        // omit direction here, since it is always written in media descriptions

        for group in &self.group {
            write!(f, "a=group:{group}\r\n")?;
        }

        for extmap in &self.extmap {
            write!(f, "a=extmap:{extmap}\r\n")?;
        }

        if !self.ice_options.options.is_empty() {
            write!(f, "a=ice-options:{}\r\n", self.ice_options)?;
        }

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
    origin: Option<Origin>,
    name: Option<BytesStr>,
    connection: Option<Connection>,
    bandwidth: Vec<Bandwidth>,
    time: Option<Time>,
    direction: Direction,
    group: Vec<Group>,
    extmap: Vec<ExtMap>,
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
                    connection: None,
                    bandwidth: vec![],
                    direction: self.direction,
                    rtcp: None,
                    rtcp_mux: false,
                    mid: None,
                    rtpmap: vec![],
                    fmtp: vec![],
                    ice_ufrag: None,
                    ice_pwd: None,
                    ice_candidates: vec![],
                    ice_end_of_candidates: false,
                    crypto: vec![],
                    extmap: vec![],
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
            "mid" => {
                if let Some(media_description) = self.media_descriptions.last_mut() {
                    media_description.mid = Some(BytesStr::from_parse(src.as_ref(), value.trim()));
                }

                // TODO error here ?
            }
            "rtpmap" => {
                let (_, rtpmap) = RtpMap::parse(src.as_ref(), value).finish()?;

                if let Some(media_description) = self.media_descriptions.last_mut() {
                    media_description.rtpmap.push(rtpmap);
                }

                // TODO error here ?
            }
            "fmtp" => {
                let (_, fmtp) = Fmtp::parse(src.as_ref(), value).finish()?;

                if let Some(media_description) = self.media_descriptions.last_mut() {
                    media_description.fmtp.push(fmtp);
                }

                // TODO error here ?
            }
            "rtcp" => {
                let (_, rtcp) = Rtcp::parse(src.as_ref(), line).finish()?;

                if let Some(media_description) = self.media_descriptions.last_mut() {
                    media_description.rtcp = Some(rtcp);
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
            "group" => {
                let (_, group) = Group::parse(src.as_ref(), value).finish()?;
                self.group.push(group);
            }
            "extmap" => {
                let (_, extmap) = ExtMap::parse(src.as_ref(), value).finish()?;

                if let Some(media_description) = self.media_descriptions.last_mut() {
                    media_description.extmap.push(extmap);
                } else {
                    self.extmap.push(extmap);
                }
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
            "rtcp-mux" => {
                if let Some(media_description) = self.media_descriptions.last_mut() {
                    media_description.rtcp_mux = true;
                }
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
            connection: self.connection,
            bandwidth: self.bandwidth,
            time: self.time.ok_or(ParseSessionDescriptionError::MissingTime)?,
            direction: self.direction,
            group: self.group,
            extmap: self.extmap,
            ice_options: self.ice_options,
            ice_lite: self.ice_lite,
            ice_ufrag: self.ice_ufrag,
            ice_pwd: self.ice_pwd,
            attributes: self.attributes,
            media_descriptions: self.media_descriptions,
        })
    }
}
