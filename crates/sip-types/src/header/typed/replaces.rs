//! [RFC3891](https://datatracker.ietf.org/doc/html/rfc3891)

use crate::header::headers::OneOrMore;
use crate::header::{ConstNamed, ExtendValues, HeaderParse};
use crate::parse::ParseCtx;
use crate::print::PrintCtx;
use crate::uri::params::{Params, CPS};
use crate::Name;
use anyhow::{Context, Result};
use bytesstr::BytesStr;
use internal::{ws, ParseError};
use nom::bytes::complete::take_while1;
use nom::combinator::map_res;
use nom::Finish;
use std::fmt;

#[derive(Debug, Clone, PartialEq)]
pub struct Replaces {
    pub call_id: BytesStr,
    pub from_tag: BytesStr,
    pub to_tag: BytesStr,
    pub early_only: bool,
}

impl ConstNamed for Replaces {
    const NAME: Name = Name::REPLACES;
}

impl HeaderParse for Replaces {
    fn parse<'i>(ctx: ParseCtx<'_>, i: &'i str) -> Result<(&'i str, Self)> {
        let (rem, replaces) = map_res(
            ws((take_while1(|b| b != ';'), Params::<CPS>::parse(ctx))),
            |(call_id, mut params)| -> Result<Self, ParseError> {
                Ok(Self {
                    call_id: BytesStr::from_parse(ctx.src, call_id),
                    from_tag: params.take("from-tag").context("missing from-tag")?,
                    to_tag: params.take("to-tag").context("missing to-tag")?,
                    early_only: params.get("early-only").is_some(),
                })
            },
        )(i)
        .finish()?;

        Ok((rem, replaces))
    }
}

impl ExtendValues for Replaces {
    fn extend_values(&self, ctx: PrintCtx<'_>, values: &mut OneOrMore) {
        *values = self.create_values(ctx)
    }

    fn create_values(&self, _: PrintCtx<'_>) -> OneOrMore {
        OneOrMore::One(self.to_string().into())
    }
}

impl fmt::Display for Replaces {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{};from-tag={};to-tag={}",
            self.call_id, self.from_tag, self.to_tag
        )?;

        if self.early_only {
            write!(f, ";early-only")?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Headers;

    const REPLACES: Replaces = Replaces {
        call_id: BytesStr::from_static("SomeCallID"),
        from_tag: BytesStr::from_static("SomeFromTag"),
        to_tag: BytesStr::from_static("SomeToTag"),
        early_only: true,
    };

    #[test]
    fn print_replaces() {
        let mut headers = Headers::new();
        headers.insert_named(&REPLACES);
        let headers = headers.to_string();

        assert_eq!(
            headers,
            "Replaces: SomeCallID;from-tag=SomeFromTag;to-tag=SomeToTag;early-only\r\n"
        );
    }

    #[test]
    fn parse_replaces() {
        let mut headers = Headers::new();
        headers.insert(
            Name::REPLACES,
            "\
        SomeCallID;\r\n \
         ;from-tag=SomeFromTag\r\n \
         ;to-tag=SomeToTag\r\n \
         ;early-only",
        );

        let replaces: Replaces = headers.get_named().unwrap();

        assert_eq!(replaces, REPLACES);
    }
}
