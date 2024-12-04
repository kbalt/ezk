use crate::attributes::Group;
use crate::bandwidth::Bandwidth;
use crate::connection::Connection;
use crate::origin::Origin;
use crate::parser::{ParseSessionDescriptionError, Parser};
use crate::time::Time;
use crate::{
    Direction, ExtMap, IceOptions, IcePassword, IceUsernameFragment, MediaDescription,
    UnknownAttribute,
};
use bytesstr::BytesStr;
use std::fmt::{self, Debug};

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

    /// If not present: false
    ///
    /// If specified an ice-lite implementation is used
    pub ice_lite: bool,

    /// ICE options, omitted if empty
    pub ice_options: IceOptions,

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
