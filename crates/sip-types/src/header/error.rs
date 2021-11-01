use super::name::Name;
use std::error;
use std::fmt;

/// Error that occurred when trying to decode a header from [Headers].
///
/// [Headers]: crate::Headers
#[derive(Debug)]
pub struct HeaderError {
    name: Name,
    repr: Repr,
}

#[derive(Debug)]
enum Repr {
    Missing,
    Malformed(anyhow::Error),
}

impl HeaderError {
    pub const fn missing(name: Name) -> Self {
        HeaderError {
            name,
            repr: Repr::Missing,
        }
    }

    pub const fn malformed(name: Name, error: anyhow::Error) -> Self {
        HeaderError {
            name,
            repr: Repr::Malformed(error),
        }
    }

    pub fn malformed_adhoc(name: Name, error: &'static str) -> Self {
        HeaderError {
            name,
            repr: Repr::Malformed(anyhow::Error::msg(error)),
        }
    }

    pub const fn is_missing(&self) -> bool {
        matches!(&self.repr, Repr::Missing)
    }
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.repr {
            Repr::Missing => write!(f, "header {:?} is missing", self.name),
            Repr::Malformed(err) => write!(
                f,
                "header {:?} was found but is malformed: {}",
                self.name, err
            ),
        }
    }
}

impl error::Error for HeaderError {}
