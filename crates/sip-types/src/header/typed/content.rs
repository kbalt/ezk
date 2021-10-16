use crate::header::headers::OneOrMore;
use crate::header::name::Name;
use crate::header::{ConstNamed, ExtendValues, HeaderParse};
use crate::parse::ParseCtx;
use crate::print::PrintCtx;
use anyhow::Result;
use bytesstr::BytesStr;

from_str_header! {
    /// `Content-Length` header
    ContentLength,
    Name::CONTENT_LENGTH,
    usize
}

/// `Content-Type` header
#[derive(Debug, Clone, PartialEq)]
pub struct ContentType(pub BytesStr);

impl ConstNamed for ContentType {
    const NAME: Name = Name::CONTENT_TYPE;
}

impl HeaderParse for ContentType {
    fn parse<'i>(ctx: ParseCtx, i: &'i str) -> Result<(&'i str, Self)> {
        Ok(("", Self(BytesStr::from_parse(ctx.src, i.trim()))))
    }
}

impl ExtendValues for ContentType {
    fn extend_values(&self, ctx: PrintCtx<'_>, values: &mut OneOrMore) {
        *values = self.create_values(ctx)
    }

    fn create_values(&self, _: PrintCtx<'_>) -> OneOrMore {
        OneOrMore::One(self.0.as_str().into())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Headers;

    #[test]
    fn print_content_length() {
        let mut headers = Headers::new();
        headers.insert_named(&ContentLength(120));
        let headers = headers.to_string();

        assert_eq!(headers, "Content-Length: 120\r\n");
    }

    #[test]
    fn print_content_type() {
        let mut headers = Headers::new();
        headers.insert_named(&ContentType(BytesStr::from_static("application/sdp")));
        let headers = headers.to_string();

        assert_eq!(headers, "Content-Type: application/sdp\r\n");
    }

    #[test]
    fn parse_content_length() {
        let mut headers = Headers::new();
        headers.insert(Name::CONTENT_LENGTH, "120");

        let clen: ContentLength = headers.get_named().unwrap();
        assert_eq!(clen.0, 120);
    }

    #[test]
    fn parse_content_type() {
        let mut headers = Headers::new();
        headers.insert(Name::CONTENT_TYPE, "application/sdp");

        let ctype: ContentType = headers.get_named().unwrap();
        assert_eq!(ctype.0, "application/sdp");
    }
}
