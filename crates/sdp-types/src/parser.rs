use crate::{
    Bandwidth, Connection, Direction, ExtMap, Fmtp, Group, IceCandidate, IceOptions, IcePassword,
    IceUsernameFragment, Media, MediaDescription, Origin, Rtcp, RtpMap, SessionDescription,
    SrtpCrypto, Time, UnknownAttribute,
};
use bytesstr::BytesStr;
use internal::verbose_error_to_owned;
use nom::Finish;

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

#[derive(Default)]
pub(crate) struct Parser {
    origin: Option<Origin>,
    name: Option<BytesStr>,
    connection: Option<Connection>,
    bandwidth: Vec<Bandwidth>,
    time: Option<Time>,
    direction: Direction,
    group: Vec<Group>,
    extmap: Vec<ExtMap>,
    extmap_allow_mixed: bool,
    ice_options: IceOptions,
    ice_lite: bool,
    ice_ufrag: Option<IceUsernameFragment>,
    ice_pwd: Option<IcePassword>,
    attributes: Vec<UnknownAttribute>,
    media_descriptions: Vec<MediaDescription>,
}

impl Parser {
    pub(crate) fn parse_line(
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
                    // inherit extmap allow mixed atr
                    extmap_allow_mixed: self.extmap_allow_mixed,
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
            self.parse_attribute_with_value(src, name, value)?;
        } else {
            self.parse_attribute_without_value(src, line);
        }

        Ok(())
    }

    fn parse_attribute_with_value(
        &mut self,
        src: &BytesStr,
        name: &str,
        value: &str,
    ) -> Result<(), ParseSessionDescriptionError> {
        match name {
            "group" => {
                let (_, group) = Group::parse(src.as_ref(), value).finish()?;
                self.group.push(group);
            }
            "rtcp" => {
                let (_, rtcp) = Rtcp::parse(src.as_ref(), value).finish()?;

                if let Some(media_description) = self.media_descriptions.last_mut() {
                    media_description.rtcp = Some(rtcp);
                }

                // TODO error here?
            }
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
                let (_, candidate) = IceCandidate::parse(src.as_ref(), value).finish()?;

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
            "extmap-allow-mixed" => {
                if let Some(media_description) = self.media_descriptions.last_mut() {
                    media_description.extmap_allow_mixed = true;
                } else {
                    self.extmap_allow_mixed = true;
                }
            }
            "rtcp-mux" => {
                if let Some(media_description) = self.media_descriptions.last_mut() {
                    media_description.rtcp_mux = true;
                }
            }
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

    pub(crate) fn finish(self) -> Result<SessionDescription, ParseSessionDescriptionError> {
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
            extmap_allow_mixed: self.extmap_allow_mixed,
            ice_lite: self.ice_lite,
            ice_options: self.ice_options,
            ice_ufrag: self.ice_ufrag,
            ice_pwd: self.ice_pwd,
            attributes: self.attributes,
            media_descriptions: self.media_descriptions,
        })
    }
}
