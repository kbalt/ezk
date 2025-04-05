use crate::header::headers::OneOrMore;
use crate::header::name::Name;
use crate::header::{ConstNamed, ExtendValues, HeaderParse};
use crate::print::PrintCtx;
use bytes::Bytes;
use bytesstr::BytesStr;
use internal::{identity, IResult};
use nom::combinator::map;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Event(pub BytesStr);

impl Event {
    pub fn new<B>(ev: B) -> Self
    where
        B: Into<BytesStr>,
    {
        Event(ev.into())
    }
}

impl ConstNamed for Event {
    const NAME: Name = Name::EVENT;
}

impl HeaderParse for Event {
    fn parse<'i>(src: &'i Bytes, i: &'i str) -> IResult<&'i str, Self> {
        map(identity(), |i| Self(BytesStr::from_parse(src, i.trim())))(i)
    }
}

impl ExtendValues for Event {
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

    const EVENT_DIALOG: Event = Event(BytesStr::from_static("dialog"));

    #[test]
    fn print_event_single() {
        let mut headers = Headers::new();
        headers.insert_named(&EVENT_DIALOG);
        let headers = headers.to_string();

        assert_eq!(headers, "Event: dialog\r\n");
    }

    #[test]
    fn parse_event() {
        let mut headers = Headers::new();
        headers.insert(Name::EVENT, "dialog");

        let event: Event = headers.get_named().unwrap();
        assert_eq!(event, EVENT_DIALOG)
    }
}
