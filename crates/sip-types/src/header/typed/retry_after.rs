use crate::header::name::Name;
use crate::parse::{whitespace, ParseCtx};
use crate::print::{Print, PrintCtx};
use crate::uri::params::{Params, CPS};
use bytesstr::BytesStr;
use nom::bytes::complete::{is_not, tag, take_while};
use nom::character::complete::digit1;
use nom::combinator::{map, map_res, opt};
use nom::sequence::{delimited, preceded, tuple};
use nom::IResult;
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

    pub(crate) fn parse(ctx: ParseCtx<'_>) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            map(
                tuple((
                    map_res(digit1, FromStr::from_str),
                    Params::<CPS>::parse(ctx),
                    opt(preceded(
                        take_while(whitespace),
                        delimited(tag("("), is_not(")"), tag(")")),
                    )),
                )),
                |(value, params, comment)| RetryAfter {
                    value,
                    params,
                    comment: comment.map(|str| BytesStr::from_parse(ctx.src, str)),
                },
            )(i)
        }
    }
}

impl Print for RetryAfter {
    fn print(&self, f: &mut fmt::Formatter<'_>, _: PrintCtx<'_>) -> fmt::Result {
        write!(f, "{}{}", self.value, self.params)?;

        if let Some(comment) = &self.comment {
            write!(f, " ({})", comment)?;
        }

        Ok(())
    }
}

__impl_header!(RetryAfter, Single, Name::RETRY_AFTER);

#[cfg(test)]
mod test {
    use super::*;
    use crate::print::AppendCtx;

    #[test]
    fn retry_after() {
        let input = BytesStr::from_static("120");

        let (rem, retry_after) = RetryAfter::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(retry_after.value, 120);
        assert!(retry_after.params.is_empty());
        assert!(retry_after.comment.is_none());
    }

    #[test]
    fn retry_after_duration() {
        let input = BytesStr::from_static("120;duration=60");

        let (rem, retry_after) = RetryAfter::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(retry_after.value, 120);

        let duration = retry_after.params.get_val("duration").unwrap();
        assert_eq!(duration, "60");

        assert!(retry_after.comment.is_none());
    }

    #[test]
    fn retry_after_duration_comment() {
        let input = BytesStr::from_static("120;duration=60 (Some Comment about being busy)");

        let (rem, retry_after) = RetryAfter::parse(ParseCtx::default(&input))(&input).unwrap();

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
