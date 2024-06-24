use crate::connection::Connection;
use crate::media::Media;
use crate::origin::Origin;
use crate::time::Time;
use crate::{bandwidth::Bandwidth, Rtcp};
use crate::{
    Direction, Fmtp, IceCandidate, IceOptions, IcePassword, IceUsernameFragment, RtpMap,
    UnknownAttribute,
};
use bytesstr::BytesStr;
use internal::{Finish, ParseError};
use std::fmt::{self, Debug};

#[derive(Debug, thiserror::Error)]
pub enum ParseSessionDescriptionError {
    #[error(transparent)]
    ParseError(#[from] ParseError),

    #[error("message ended unexpectedly")]
    Incomplete,

    #[error("message is missing the origin field (o=)")]
    MissingOrigin,
    #[error("message is missing the name (s=) field")]
    MissingName,
    #[error("message is missing the time (t=) field")]
    MissingTime,
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

    /// RTP mappings
    pub rtpmaps: Vec<RtpMap>,

    /// Format parameters
    pub fmtps: Vec<Fmtp>,

    /// ICE username fragment
    pub ice_ufrag: Option<IceUsernameFragment>,

    /// ICE password
    pub ice_pwd: Option<IcePassword>,

    /// ICE candidates
    pub ice_candidates: Vec<IceCandidate>,

    /// ICE a=end-of-candidates attribute
    pub ice_end_of_candidates: bool,

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

        let mut name: Option<BytesStr> = Default::default();
        let mut origin: Option<Origin> = Default::default();
        let mut time: Option<Time> = Default::default();
        let mut direction: Direction = Default::default();
        let mut connection: Option<Connection> = Default::default();
        let mut bandwidth: Vec<Bandwidth> = Default::default();
        let mut ice_options: IceOptions = Default::default();
        let mut ice_lite: bool = Default::default();
        let mut ice_ufrag: Option<IceUsernameFragment> = Default::default();
        let mut ice_pwd: Option<IcePassword> = Default::default();
        let mut attributes: Vec<UnknownAttribute> = Default::default();
        let mut media_scopes: Vec<MediaDescription> = Default::default();

        for complete_line in lines {
            let line = complete_line
                .get(2..)
                .ok_or(ParseSessionDescriptionError::Incomplete)?;

            match complete_line.as_bytes() {
                [b'v', b'=', b'0'] => {
                    // parsed the version yay!
                }
                [b's', b'=', ..] => {
                    name = Some(BytesStr::from_parse(src.as_ref(), line));
                }
                [b'o', b'=', ..] => {
                    let (_, o) = Origin::parse(src.as_ref(), line).finish()?;
                    origin = Some(o);
                }
                [b't', b'=', ..] => {
                    let (_, t) = Time::parse(line).finish()?;
                    time = Some(t);
                }
                [b'c', b'=', ..] => {
                    let (_, c) = Connection::parse(src.as_ref(), line).finish()?;

                    if let Some(media_scope) = media_scopes.last_mut() {
                        media_scope.connection = Some(c);
                    } else {
                        connection = Some(c);
                    }
                }
                [b'b', b'=', ..] => {
                    let (_, b) = Bandwidth::parse(src.as_ref(), line).finish()?;

                    if let Some(media_scope) = media_scopes.last_mut() {
                        media_scope.bandwidth.push(b);
                    } else {
                        bandwidth.push(b);
                    }
                }
                [b'm', b'=', ..] => {
                    let (_, desc) = Media::parse(src.as_ref(), line).finish()?;

                    media_scopes.push(MediaDescription {
                        media: desc,
                        // inherit session direction
                        direction,
                        connection: None,
                        bandwidth: vec![],
                        rtcp_attr: None,
                        rtpmaps: vec![],
                        fmtps: vec![],
                        ice_ufrag: None,
                        ice_pwd: None,
                        ice_candidates: vec![],
                        ice_end_of_candidates: false,
                        attributes: vec![],
                    });
                }
                [b'a', b'=', ..] => {
                    if let Some((attr, attr_v)) = line.split_once(':') {
                        match attr {
                            "rtpmap" => {
                                let (_, rtpmap) = RtpMap::parse(src.as_ref(), line).finish()?;

                                if let Some(media_scope) = media_scopes.last_mut() {
                                    media_scope.rtpmaps.push(rtpmap);
                                }

                                // TODO error here ?
                            }
                            "fmtp" => {
                                let (_, fmtp) = Fmtp::parse(src.as_ref(), line).finish()?;

                                if let Some(media_scope) = media_scopes.last_mut() {
                                    media_scope.fmtps.push(fmtp);
                                }

                                // TODO error here ?
                            }
                            "rtcp" => {
                                let (_, rtcp) = Rtcp::parse(src.as_ref(), line).finish()?;

                                if let Some(media_scope) = media_scopes.last_mut() {
                                    media_scope.rtcp_attr = Some(rtcp)
                                }

                                // TODO error here?
                            }
                            "ice-lite" => {
                                ice_lite = true;
                            }
                            "ice-options" => {
                                let (_, options) =
                                    IceOptions::parse(src.as_ref(), attr_v).finish()?;
                                ice_options = options;
                            }
                            "ice-ufrag" => {
                                let (_, ufrag) =
                                    IceUsernameFragment::parse(src.as_ref(), attr_v).finish()?;

                                if let Some(media_scope) = media_scopes.last_mut() {
                                    media_scope.ice_ufrag = Some(ufrag)
                                } else {
                                    ice_ufrag = Some(ufrag);
                                }
                            }
                            "ice-pwd" => {
                                let (_, pwd) = IcePassword::parse(src.as_ref(), attr_v).finish()?;

                                if let Some(media_scope) = media_scopes.last_mut() {
                                    media_scope.ice_pwd = Some(pwd)
                                } else {
                                    ice_pwd = Some(pwd);
                                }
                            }
                            "candidate" => {
                                let (_, candidate) =
                                    IceCandidate::parse(src.as_ref(), line).finish()?;

                                if let Some(media_scope) = media_scopes.last_mut() {
                                    media_scope.ice_candidates.push(candidate);
                                }

                                // TODO error here?
                            }
                            _ => {
                                let attr = UnknownAttribute {
                                    name: src.slice_ref(attr),
                                    value: Some(src.slice_ref(attr_v)),
                                };

                                if let Some(media_scope) = media_scopes.last_mut() {
                                    media_scope.attributes.push(attr);
                                } else {
                                    attributes.push(attr);
                                }
                            }
                        }
                    } else {
                        match line {
                            "sendrecv" => direction = Direction::SendRecv,
                            "recvonly" => direction = Direction::RecvOnly,
                            "sendonly" => direction = Direction::SendOnly,
                            "inactive" => direction = Direction::Inactive,
                            "end-of-candidates" => {
                                if let Some(media_scope) = media_scopes.last_mut() {
                                    media_scope.ice_end_of_candidates = true;
                                }

                                // TODO error here?
                            }
                            _ => {
                                let attr = UnknownAttribute {
                                    name: src.slice_ref(line),
                                    value: None,
                                };

                                if let Some(media_scope) = media_scopes.last_mut() {
                                    media_scope.attributes.push(attr);
                                } else {
                                    attributes.push(attr);
                                }
                            }
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(Self {
            origin: origin.ok_or(ParseSessionDescriptionError::MissingOrigin)?,
            name: name.ok_or(ParseSessionDescriptionError::MissingName)?,
            time: time.ok_or(ParseSessionDescriptionError::MissingTime)?,
            direction,
            connection,
            bandwidth,
            ice_options,
            ice_lite,
            ice_ufrag,
            ice_pwd,
            attributes,
            media_descriptions: media_scopes,
        })
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
            write!(f, "{}\r\n", conn)?;
        }

        for bw in &self.bandwidth {
            write!(f, "{}\r\n", bw)?;
        }

        write!(f, "{}\r\n{}", self.time, self.ice_options)?;

        if self.ice_lite {
            f.write_str("a=ice-lite\r\n")?;
        }

        if let Some(ufrag) = &self.ice_ufrag {
            write!(f, "{}\r\n", ufrag)?;
        }

        if let Some(pwd) = &self.ice_pwd {
            write!(f, "{}\r\n", pwd)?;
        }

        for attr in &self.attributes {
            write!(f, "{}\r\n", attr)?;
        }

        for media_scope in &self.media_descriptions {
            write!(f, "{}", media_scope)?;
        }

        Ok(())
    }
}
