//! Parsing utilities for SIP message components

use std::str::FromStr;

use bytes::Bytes;
use bytesstr::BytesStr;
use internal::IResult;
use nom::bytes::complete::{escaped, is_not};
use nom::character::complete::char;
use nom::error::{VerboseError, VerboseErrorKind};
use nom::sequence::delimited;
use nom::Finish;

pub(crate) fn parse_quoted(i: &str) -> IResult<&str, &str> {
    delimited(char('"'), escaped(is_not("\""), '\\', char('"')), char('"'))(i)
}

pub(crate) fn whitespace(c: char) -> bool {
    matches!(c, ' ' | '\t' | '\r' | '\n')
}

#[rustfmt::skip]
pub(crate) fn token(c: char) -> bool {
    c.is_alphanumeric() || matches!(c, '-' | '.' | '!' | '%' | '*' | '_' | '`' | '\'' | '~' | '+')
}

/// Parsable type using nom
pub trait Parse: Sized + FromStr {
    /// Create a parser which references the given buffer
    fn parse(src: &Bytes) -> impl Fn(&str) -> IResult<&str, Self> + '_;

    /// Parse from str
    fn parse_str(i: &str) -> Result<Self, VerboseError<String>> {
        let src = BytesStr::from(i);

        let (remaining, parsed) = Self::parse(src.as_ref())(&src)
            .finish()
            .map_err(internal::verbose_error_to_owned)?;

        if remaining.is_empty() {
            Ok(parsed)
        } else {
            Err(VerboseError {
                errors: vec![(
                    remaining.into(),
                    VerboseErrorKind::Context("Input was not completely consumed"),
                )],
            })
        }
    }
}

macro_rules! impl_from_str {
    ($ty:ty) => {
        impl std::str::FromStr for $ty {
            type Err = $crate::_private_reexport::nom::error::VerboseError<String>;

            fn from_str(i: &str) -> Result<Self, Self::Err> {
                <Self as Parse>::parse_str(i)
            }
        }
    };
}
