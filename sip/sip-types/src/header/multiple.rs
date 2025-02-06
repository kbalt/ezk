use super::headers::OneOrMore;
use super::{ConstNamed, DecodeValues, ExtendValues, HeaderParse};
use crate::header::name::Name;
use crate::parse::{ParseCtx, Parser};
use crate::print::PrintCtx;
use bytesstr::BytesStr;
use internal::IResult;

impl<H: ConstNamed> ConstNamed for Vec<H> {
    const NAME: Name = H::NAME;
}

impl<H: HeaderParse> DecodeValues for Vec<H> {
    fn decode<'i, I>(parser: Parser, values: &mut I) -> IResult<&'i str, Self>
    where
        I: Iterator<Item = &'i BytesStr>,
    {
        let mut items = Vec::new();

        for value in values {
            let ctx = ParseCtx {
                src: value.as_ref(),
                parser,
            };

            let mut i = value.as_str();

            while let Ok((remaining, hdr)) = H::parse(ctx, i) {
                items.push(hdr);

                let remaining = remaining.trim_start_matches(char::is_whitespace);

                if remaining.starts_with(',') {
                    i = remaining.trim_start_matches(|c: char| c == ',' || c.is_whitespace());
                } else {
                    break;
                }
            }
        }

        Ok(("", items))
    }
}

impl<H: ExtendValues> ExtendValues for Vec<H> {
    fn extend_values(&self, ctx: PrintCtx<'_>, values: &mut OneOrMore) {
        for item in self.iter() {
            item.extend_values(ctx, values);
        }
    }

    fn create_values(&self, ctx: PrintCtx<'_>) -> OneOrMore {
        let mut iter = self.iter();

        let first = iter.next().expect("tried to use empty vector");

        let mut values = first.create_values(ctx);

        for item in iter {
            item.extend_values(ctx, &mut values);
        }

        values
    }
}
