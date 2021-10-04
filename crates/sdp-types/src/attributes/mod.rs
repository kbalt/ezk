use bytes::{Bytes, BytesMut};
use bytesstr::BytesStr;
use std::fmt;

pub mod candidate;
pub mod direction;
pub mod fmtp;
pub mod ice;
pub mod rtcp;
pub mod rtpmap;

/// `name:[value]` pair which contains an unparsed/unknown attribute
#[derive(Debug, Clone)]
pub struct UnknownAttribute {
    /// Attribute name, the part before the optional `:`
    pub name: BytesStr,

    /// if the optional `:` is present the part parsed after is stored inside `value`
    pub value: Option<BytesStr>,
}

impl UnknownAttribute {
    pub fn parse(src: &Bytes, line: &str) -> Self {
        match line.split_once(':') {
            None => Self {
                name: BytesStr::from_parse(src, line),
                value: None,
            },
            Some((name, value)) => Self {
                name: BytesStr::from_parse(src, name),
                value: Some(BytesStr::from_parse(src, value)),
            },
        }
    }

    pub fn print(&self, buf: &mut BytesMut) {
        buf.extend_from_slice(self.name.as_ref());

        if let Some(value) = &self.value {
            buf.extend_from_slice(b":");
            buf.extend_from_slice(value.as_ref());
        }
    }
}

impl fmt::Display for UnknownAttribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(self.name.as_str())?;

        if let Some(value) = &self.value {
            write!(f, ":{}", value)?;
        }

        Ok(())
    }
}
