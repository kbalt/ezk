//! Media direction attribute (`a=sendrecv`, `a=recvonly`, `a=sendonly`, `a=inactive`)

use std::fmt;

/// Media direction attribute e.g. (`a=sendrecv`)
///
/// Session and Media Level attribute.  
/// If the direction is specified at the session level but not as media level
/// the direction of the session is used for the media
///
/// > If not specified at all `sendrecv` is assumed by default
///
/// [RFC8866](https://www.rfc-editor.org/rfc/rfc8866.html#section-6.7)
#[derive(Default, Debug, Copy, Clone, PartialEq)]
pub enum Direction {
    /// Send and receive media data
    #[default]
    SendRecv,

    /// Only receive media data
    RecvOnly,

    /// Only send media data
    SendOnly,

    /// Media is inactive not sending any data
    Inactive,
}

impl Direction {
    pub fn flipped(self) -> Self {
        match self {
            Direction::SendRecv => self,
            Direction::RecvOnly => Direction::SendOnly,
            Direction::SendOnly => Direction::RecvOnly,
            Direction::Inactive => self,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Direction::SendRecv => "sendrecv",
            Direction::RecvOnly => "recvonly",
            Direction::SendOnly => "sendonly",
            Direction::Inactive => "inactive",
        }
    }
}

impl fmt::Display for Direction {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
