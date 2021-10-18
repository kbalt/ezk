use crate::header::headers::OneOrMore;
use crate::header::{ConstNamed, ExtendValues, HeaderParse};
use crate::parse::ParseCtx;
use crate::print::PrintCtx;
use crate::Name;
use anyhow::Result;
use bytesstr::BytesStr;

/// `Call-ID`header
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CallID(pub BytesStr);

impl CallID {
    pub fn new<B>(id: B) -> Self
    where
        B: Into<BytesStr>,
    {
        CallID(id.into())
    }
}

impl ConstNamed for CallID {
    const NAME: Name = Name::CALL_ID;
}

impl HeaderParse for CallID {
    fn parse<'i>(ctx: ParseCtx, i: &'i str) -> Result<(&'i str, Self)> {
        Ok(("", Self(BytesStr::from_parse(ctx.src, i.trim()))))
    }
}

impl ExtendValues for CallID {
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

    const CALL_ID: CallID = CallID(BytesStr::from_static("SomeCallID"));

    #[test]
    fn print_call_id() {
        let mut headers = Headers::new();
        headers.insert_named(&CALL_ID);
        let headers = headers.to_string();

        assert_eq!(headers, "Call-ID: SomeCallID\r\n");
    }

    #[test]
    fn parse_call_id() {
        let mut headers = Headers::new();
        headers.insert(Name::CALL_ID, "SomeCallID");

        let accept: CallID = headers.get_named().unwrap();
        assert_eq!(accept, CALL_ID);
    }
}
