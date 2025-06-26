use crate::header::headers::OneOrMore;
use crate::header::name::Name;
use crate::header::{ConstNamed, ExtendValues, HeaderParse};
use crate::parse::whitespace;
use crate::print::PrintCtx;
use crate::uri::params::{CPS, Params};
use bytes::Bytes;
use bytesstr::BytesStr;
use internal::IResult;
use nom::bytes::complete::{is_not, tag, take_while};
use nom::character::complete::digit1;
use nom::combinator::{map, map_res, opt};
use nom::sequence::{delimited, preceded, tuple};
use std::fmt;
use std::str::FromStr;

// TODO: Support Date

#[derive(Debug, Clone)]
#[non_exhaustive]
/// `Retry-After` header
///
/// Currently only supports seconds representation
pub struct RetryAfter {
    pub value: u32,
    pub params: Params<CPS>,
    pub comment: Option<BytesStr>,
}

impl RetryAfter {
    pub fn new(value: u32) -> Self {
        Self {
            value,
            params: Params::new(),
            comment: None,
        }
    }

    pub fn with_comment<S>(mut self, comment: S) -> Self
    where
        S: Into<BytesStr>,
    {
        self.comment = Some(comment.into());
        self
    }
}

impl ConstNamed for RetryAfter {
    const NAME: Name = Name::RETRY_AFTER;
}

impl HeaderParse for RetryAfter {
    fn parse<'i>(src: &'i Bytes, i: &'i str) -> IResult<&'i str, Self> {
        map(
            tuple((
                map_res(digit1, FromStr::from_str),
                Params::<CPS>::parse(src),
                opt(preceded(
                    take_while(whitespace),
                    delimited(tag("("), is_not(")"), tag(")")),
                )),
            )),
            |(value, params, comment)| RetryAfter {
                value,
                params,
                comment: comment.map(|str| BytesStr::from_parse(src, str)),
            },
        )(i)
    }
}

impl ExtendValues for RetryAfter {
    fn extend_values(&self, ctx: PrintCtx<'_>, values: &mut OneOrMore) {
        *values = self.create_values(ctx)
    }

    fn create_values(&self, _: PrintCtx<'_>) -> OneOrMore {
        OneOrMore::One(self.to_string().into())
    }
}

impl fmt::Display for RetryAfter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.value, self.params)?;

        if let Some(comment) = &self.comment {
            write!(f, " ({comment})")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::print::AppendCtx;

    #[test]
    fn retry_after() {
        let input = BytesStr::from_static("120");

        let (rem, retry_after) = RetryAfter::parse(input.as_ref(), &input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(retry_after.value, 120);
        assert!(retry_after.params.is_empty());
        assert!(retry_after.comment.is_none());
    }

    #[test]
    fn retry_after_duration() {
        let input = BytesStr::from_static("120;duration=60");

        let (rem, retry_after) = RetryAfter::parse(input.as_ref(), &input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(retry_after.value, 120);

        let duration = retry_after.params.get_val("duration").unwrap();
        assert_eq!(duration, "60");

        assert!(retry_after.comment.is_none());
    }

    #[test]
    fn retry_after_duration_comment() {
        let input = BytesStr::from_static("120;duration=60 (Some Comment about being busy)");

        let (rem, retry_after) = RetryAfter::parse(input.as_ref(), &input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(retry_after.value, 120);

        let duration = retry_after.params.get_val("duration").unwrap();
        assert_eq!(duration, "60");

        assert!(
            matches!(retry_after.comment, Some(comment) if comment == "Some Comment about being busy")
        );
    }

    #[test]
    fn retry_after_print() {
        let retry_after = RetryAfter::new(120);

        assert_eq!(retry_after.default_print_ctx().to_string(), "120");
    }

    #[test]
    fn retry_after_comment_print() {
        let retry_after = RetryAfter::new(120).with_comment("Some Comment");

        assert_eq!(
            retry_after.default_print_ctx().to_string(),
            "120 (Some Comment)"
        );
    }
}
