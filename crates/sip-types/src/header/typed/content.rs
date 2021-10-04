use crate::header::name::Name;
use crate::parse::text::{CsvTextSpec, Text};
use crate::parse::ParseCtx;
use crate::print::{Print, PrintCtx};
use bytesstr::BytesStr;
use nom::combinator::map;
use nom::IResult;
use std::fmt;

// Content Length

decl_from_str_header!(
    /// `Content-Length` header
    ContentLength,
    usize,
    Single,
    Name::CONTENT_LENGTH
);

// Content-Type

/// `Content-Type` header
#[derive(Debug, Clone, PartialEq)]
pub struct ContentType(pub BytesStr);

impl ContentType {
    pub fn parse(ctx: ParseCtx<'_>) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| map(Text::<CsvTextSpec>::parse(ctx), ContentType)(i)
    }
}

impl Print for ContentType {
    fn print(&self, f: &mut fmt::Formatter<'_>, _: PrintCtx<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

__impl_header!(ContentType, Single, Name::CONTENT_TYPE);

#[cfg(test)]
mod test {
    use super::*;
    use crate::print::AppendCtx;

    #[test]
    fn content_length() {
        let input = BytesStr::from_static("240");

        let (rem, content_length) =
            ContentLength::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(content_length.0, 240);
    }

    #[test]
    fn content_length_spaces() {
        let input = BytesStr::from_static("    240     ");

        let (rem, content_length) =
            ContentLength::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(content_length.0, 240);
    }

    #[test]
    fn content_length_print() {
        let content_length = ContentLength(700);

        assert_eq!(content_length.default_print_ctx().to_string(), "700");
    }

    #[test]
    fn content_type() {
        let input = BytesStr::from_static("application/sdp");

        let (rem, content_length) = ContentType::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(content_length.0, "application/sdp");
    }

    #[test]
    fn content_type_spaces() {
        let input = BytesStr::from_static("        application/sdp   ");

        let (rem, content_type) = ContentType::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(content_type.0, "application/sdp");
    }

    #[test]
    fn content_type_print() {
        let content_type = ContentType(BytesStr::from_static("application/sdp"));

        assert_eq!(
            content_type.default_print_ctx().to_string(),
            "application/sdp"
        );
    }
}
