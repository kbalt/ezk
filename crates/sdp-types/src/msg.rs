use crate::attributes::candidate::Candidate;
use crate::attributes::direction::Direction;
use crate::attributes::fmtp::Fmtp;
use crate::attributes::ice::{Options, Password, UsernameFragment};
use crate::attributes::rtcp::RtcpAttr;
use crate::attributes::rtpmap::RtpMap;
use crate::attributes::{ice, UnknownAttribute};
use crate::bandwidth::Bandwidth;
use crate::connection::Connection;
use crate::media::MediaDescription;
use crate::origin::Origin;
use crate::time::Time;
use anyhow::Context;
use bytesstr::BytesStr;
use std::fmt;

pub trait ParseBuilder: Default {
    type Message;
    type Error;

    fn finish(self) -> Result<Self::Message, Self::Error>;

    fn set_name(&mut self, name: BytesStr) -> Result<(), Self::Error>;
    fn set_origin(&mut self, origin: Origin) -> Result<(), Self::Error>;
    fn set_time(&mut self, time: Time) -> Result<(), Self::Error>;
    fn set_direction(&mut self, direction: Direction) -> Result<(), Self::Error>;
    fn set_connection(&mut self, connection: Connection) -> Result<(), Self::Error>;
    fn add_bandwidth(&mut self, bandwidth: Bandwidth) -> Result<(), Self::Error>;
    fn begin_media(&mut self, desc: MediaDescription) -> Result<(), Self::Error>;
    fn add_rtpmap(&mut self, rtpmap: RtpMap) -> Result<(), Self::Error>;
    fn add_fmtp(&mut self, fmtp: Fmtp) -> Result<(), Self::Error>;
    fn add_rtcp(&mut self, rtcp: RtcpAttr) -> Result<(), Self::Error>;
    fn set_ice_lite(&mut self, lite: bool) -> Result<(), Self::Error>;
    fn set_ice_options(&mut self, options: ice::Options) -> Result<(), Self::Error>;
    fn set_ice_ufrag(&mut self, ufrag: ice::UsernameFragment) -> Result<(), Self::Error>;
    fn set_ice_pwd(&mut self, pwd: ice::Password) -> Result<(), Self::Error>;
    fn add_ice_candidate(&mut self, candidate: Candidate) -> Result<(), Self::Error>;
    fn set_ice_end_of_candidates(&mut self, end: bool) -> Result<(), Self::Error>;
    fn add_unknown_attr(&mut self, attr: UnknownAttribute) -> Result<(), Self::Error>;
}

#[derive(Default)]
pub struct Builder {
    name: Option<BytesStr>,
    origin: Option<Origin>,
    time: Option<Time>,
    direction: Direction,
    connection: Option<Connection>,
    bandwidth: Vec<Bandwidth>,
    ice_options: ice::Options,
    ice_lite: bool,
    ice_ufrag: Option<ice::UsernameFragment>,
    ice_pwd: Option<ice::Password>,
    attributes: Vec<UnknownAttribute>,
    media_scopes: Vec<MediaScope>,
}

impl ParseBuilder for Builder {
    type Message = Message;
    type Error = anyhow::Error;

    fn finish(self) -> Result<Self::Message, Self::Error> {
        Ok(Message {
            origin: self.origin.context("missing origin")?,
            name: self.name.context("missing name")?,
            time: self.time.context("missing time")?,
            direction: self.direction,
            connection: self.connection,
            bandwidth: self.bandwidth,
            ice_options: self.ice_options,
            ice_lite: self.ice_lite,
            ice_ufrag: self.ice_ufrag,
            ice_pwd: self.ice_pwd,
            attributes: self.attributes,
            media_scopes: self.media_scopes,
        })
    }

    fn set_name(&mut self, name: BytesStr) -> Result<(), Self::Error> {
        self.name = Some(name);
        Ok(())
    }

    fn set_origin(&mut self, origin: Origin) -> Result<(), Self::Error> {
        self.origin = Some(origin);
        Ok(())
    }

    fn set_time(&mut self, time: Time) -> Result<(), Self::Error> {
        self.time = Some(time);
        Ok(())
    }

    fn set_direction(&mut self, direction: Direction) -> Result<(), Self::Error> {
        if let Some(media_scope) = self.media_scopes.last_mut() {
            media_scope.direction = direction;
        } else {
            self.direction = direction;
        }

        Ok(())
    }

    fn set_connection(&mut self, connection: Connection) -> Result<(), Self::Error> {
        if let Some(media_scope) = self.media_scopes.last_mut() {
            media_scope.connection = Some(connection);
        } else {
            self.connection = Some(connection);
        }

        Ok(())
    }

    fn add_bandwidth(&mut self, bandwidth: Bandwidth) -> Result<(), Self::Error> {
        if let Some(media_scope) = self.media_scopes.last_mut() {
            media_scope.bandwidth.push(bandwidth);
        } else {
            self.bandwidth.push(bandwidth);
        }

        Ok(())
    }

    fn begin_media(&mut self, desc: MediaDescription) -> Result<(), Self::Error> {
        self.media_scopes.push(MediaScope {
            desc,
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
            attributes: vec![],
        });

        Ok(())
    }

    fn add_rtpmap(&mut self, rtpmap: RtpMap) -> Result<(), Self::Error> {
        if let Some(media_scope) = self.media_scopes.last_mut() {
            media_scope.rtpmaps.push(rtpmap);
        }

        // TODO error here ?

        Ok(())
    }

    fn add_fmtp(&mut self, fmtp: Fmtp) -> Result<(), Self::Error> {
        if let Some(media_scope) = self.media_scopes.last_mut() {
            media_scope.fmtps.push(fmtp);
        }

        // TODO error here ?

        Ok(())
    }

    fn add_rtcp(&mut self, rtcp: RtcpAttr) -> Result<(), Self::Error> {
        if let Some(media_scope) = self.media_scopes.last_mut() {
            media_scope.rtcp_attr = Some(rtcp)
        }

        // TODO error here?

        Ok(())
    }

    fn set_ice_lite(&mut self, lite: bool) -> Result<(), Self::Error> {
        self.ice_lite = lite;
        Ok(())
    }

    fn set_ice_options(&mut self, options: Options) -> Result<(), Self::Error> {
        self.ice_options = options;

        Ok(())
    }

    fn set_ice_ufrag(&mut self, ufrag: UsernameFragment) -> Result<(), Self::Error> {
        if let Some(media_scope) = self.media_scopes.last_mut() {
            media_scope.ice_ufrag = Some(ufrag)
        } else {
            self.ice_ufrag = Some(ufrag);
        }

        Ok(())
    }

    fn set_ice_pwd(&mut self, pwd: Password) -> Result<(), Self::Error> {
        if let Some(media_scope) = self.media_scopes.last_mut() {
            media_scope.ice_pwd = Some(pwd)
        } else {
            self.ice_pwd = Some(pwd);
        }

        Ok(())
    }

    fn add_ice_candidate(&mut self, candidate: Candidate) -> Result<(), Self::Error> {
        if let Some(media_scope) = self.media_scopes.last_mut() {
            media_scope.ice_candidates.push(candidate);
        }

        // TODO error here?

        Ok(())
    }

    fn set_ice_end_of_candidates(&mut self, end: bool) -> Result<(), Self::Error> {
        if let Some(media_scope) = self.media_scopes.last_mut() {
            media_scope.ice_end_of_candidates = end;
        }

        // TODO error here?

        Ok(())
    }

    fn add_unknown_attr(&mut self, attr: UnknownAttribute) -> Result<(), Self::Error> {
        if let Some(media_scope) = self.media_scopes.last_mut() {
            media_scope.attributes.push(attr);
        } else {
            self.attributes.push(attr);
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct MediaScope {
    /// Scope's media description line (m field)
    pub desc: MediaDescription,

    /// Media direction
    pub direction: Direction,

    /// Optional connection (c field)
    pub connection: Option<Connection>,

    /// Optional bandwidths (b fields)
    pub bandwidth: Vec<Bandwidth>,

    /// rtcp attribute
    pub rtcp_attr: Option<RtcpAttr>,

    /// RTP mappings
    pub rtpmaps: Vec<RtpMap>,

    /// Format parameters
    pub fmtps: Vec<Fmtp>,

    /// ICE username fragment
    pub ice_ufrag: Option<ice::UsernameFragment>,

    /// ICE password
    pub ice_pwd: Option<ice::Password>,

    /// ICE candidates
    pub ice_candidates: Vec<Candidate>,

    /// ICE a=end-of-candidates attribute
    pub ice_end_of_candidates: bool,

    /// Additional attributes
    pub attributes: Vec<UnknownAttribute>,
}

impl fmt::Display for MediaScope {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}{}", self.desc, self.direction)?;

        if let Some(conn) = &self.connection {
            write!(f, "{}\r\n", conn)?;
        }

        for bw in &self.bandwidth {
            write!(f, "{}\r\n", bw)?;
        }

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

#[derive(Debug, Clone)]
pub struct Message {
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
    pub ice_options: ice::Options,

    /// If not present: false
    ///
    /// If specified an ice-lite implementation is used
    pub ice_lite: bool,

    /// ICE username fragment
    pub ice_ufrag: Option<ice::UsernameFragment>,

    /// ICE password
    pub ice_pwd: Option<ice::Password>,

    /// All attributes not parsed directly
    pub attributes: Vec<UnknownAttribute>,

    /// Media scopes
    pub media_scopes: Vec<MediaScope>,
}

#[derive(Debug)]
pub enum ParseError<E> {
    Nom(nom::error::ErrorKind),
    Incomplete,
    Builder(E),
}

impl<E> From<nom::Err<nom::error::Error<&str>>> for ParseError<E> {
    fn from(err: nom::Err<nom::error::Error<&str>>) -> Self {
        match err {
            nom::Err::Incomplete(_) => Self::Incomplete,
            nom::Err::Error(e) | nom::Err::Failure(e) => Self::Nom(e.code),
        }
    }
}

pub fn parse<B: ParseBuilder>(src: &BytesStr) -> Result<B::Message, ParseError<B::Error>> {
    let lines = src
        .split(|c| matches!(c, '\n' | '\r'))
        .filter(|line| !line.is_empty());

    let mut builder = B::default();

    for complete_line in lines {
        let line = complete_line.get(2..).ok_or(ParseError::Incomplete)?;

        match complete_line.as_bytes() {
            [b'v', b'=', b'0'] => {
                // parsed the version yay!
            }
            [b's', b'=', ..] => {
                let name = BytesStr::from_parse(src.as_ref(), line);
                builder.set_name(name).map_err(ParseError::Builder)?;
            }
            [b'o', b'=', ..] => {
                let (_, origin) = Origin::parse(src.as_ref())(line)?;
                builder.set_origin(origin).map_err(ParseError::Builder)?;
            }
            [b't', b'=', ..] => {
                let (_, time) = Time::parse(line)?;
                builder.set_time(time).map_err(ParseError::Builder)?;
            }
            [b'c', b'=', ..] => {
                let (_, connection) = Connection::parse(src.as_ref())(line)?;
                builder
                    .set_connection(connection)
                    .map_err(ParseError::Builder)?;
            }
            [b'b', b'=', ..] => {
                let (_, bandwidth) = Bandwidth::parse(src.as_ref())(line)?;
                builder
                    .add_bandwidth(bandwidth)
                    .map_err(ParseError::Builder)?;
            }
            [b'm', b'=', ..] => {
                let (_, desc) = MediaDescription::parse(src.as_ref())(line)?;
                builder.begin_media(desc).map_err(ParseError::Builder)?;
            }
            [b'a', b'=', ..] => {
                if let Some((attr, attr_v)) = line.split_once(':') {
                    match attr {
                        "rtpmap" => {
                            let (_, rtpmap) = RtpMap::parse(src.as_ref())(line)?;
                            builder.add_rtpmap(rtpmap).map_err(ParseError::Builder)?;
                        }
                        "fmtp" => {
                            let (_, fmtp) = Fmtp::parse(src.as_ref())(line)?;
                            builder.add_fmtp(fmtp).map_err(ParseError::Builder)?;
                        }
                        "rtcp" => {
                            let (_, rtcp_attr) = RtcpAttr::parse(src.as_ref())(line)?;
                            builder.add_rtcp(rtcp_attr).map_err(ParseError::Builder)?;
                        }
                        "ice-lite" => {
                            builder.set_ice_lite(true).map_err(ParseError::Builder)?;
                        }
                        "ice-options" => {
                            let (_, options) = ice::Options::parse(src.as_ref())(attr_v)?;
                            builder
                                .set_ice_options(options)
                                .map_err(ParseError::Builder)?;
                        }
                        "ice-ufrag" => {
                            let (_, ice_ufrag) =
                                ice::UsernameFragment::parse(src.as_ref())(attr_v)?;
                            builder
                                .set_ice_ufrag(ice_ufrag)
                                .map_err(ParseError::Builder)?;
                        }
                        "ice-pwd" => {
                            let (_, ice_pwd) = ice::Password::parse(src.as_ref())(attr_v)?;
                            builder.set_ice_pwd(ice_pwd).map_err(ParseError::Builder)?;
                        }
                        "candidate" => {
                            let (_, ice_candidate) = Candidate::parse(src.as_ref())(attr_v)?;
                            builder
                                .add_ice_candidate(ice_candidate)
                                .map_err(ParseError::Builder)?;
                        }
                        _ => {
                            let attr = UnknownAttribute {
                                name: src.slice_ref(attr),
                                value: Some(src.slice_ref(attr_v)),
                            };

                            builder
                                .add_unknown_attr(attr)
                                .map_err(ParseError::Builder)?;
                        }
                    }
                } else {
                    match line {
                        "sendrecv" => {
                            builder
                                .set_direction(Direction::SendRecv)
                                .map_err(ParseError::Builder)?;
                        }
                        "recvonly" => {
                            builder
                                .set_direction(Direction::RecvOnly)
                                .map_err(ParseError::Builder)?;
                        }
                        "sendonly" => {
                            builder
                                .set_direction(Direction::SendOnly)
                                .map_err(ParseError::Builder)?;
                        }
                        "inactive" => {
                            builder
                                .set_direction(Direction::Inactive)
                                .map_err(ParseError::Builder)?;
                        }
                        "end-of-candidates" => builder
                            .set_ice_end_of_candidates(true)
                            .map_err(ParseError::Builder)?,
                        _ => {
                            let attr = UnknownAttribute {
                                name: src.slice_ref(line),
                                value: None,
                            };

                            builder
                                .add_unknown_attr(attr)
                                .map_err(ParseError::Builder)?;
                        }
                    }
                }
            }
            _ => {}
        }
    }

    builder.finish().map_err(ParseError::Builder)
}

impl fmt::Display for Message {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "\
v=0\r\n\
s={}\r\n\
{}\r\n\
{}\r\n\
{}\r\n\
",
            self.name, self.origin, self.time, self.direction
        )?;

        if let Some(conn) = &self.connection {
            write!(f, "{}\r\n", conn)?;
        }

        for bw in &self.bandwidth {
            write!(f, "{}\r\n", bw)?;
        }

        self.ice_options.fmt(f)?;

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

        for media_scope in &self.media_scopes {
            media_scope.fmt(f)?;
        }

        Ok(())
    }
}
