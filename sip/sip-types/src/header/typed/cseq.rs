use crate::header::headers::OneOrMore;
use crate::header::name::Name;
use crate::header::{ConstNamed, ExtendValues, HeaderParse};
use crate::method::Method;
use crate::parse::{whitespace, ParseCtx};
use crate::print::PrintCtx;
use anyhow::Result;
use internal::IResult;
use nom::bytes::complete::take_while;
use nom::character::complete::digit1;
use nom::combinator::map_res;
use nom::sequence::separated_pair;
use std::num::ParseIntError;
use std::str::FromStr;

/// `CSeq` header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CSeq {
    pub cseq: u32,
    pub method: Method,
}

impl CSeq {
    #[inline]
    pub const fn new(cseq: u32, method: Method) -> CSeq {
        CSeq { cseq, method }
    }
}

impl ConstNamed for CSeq {
    const NAME: Name = Name::CSEQ;
}

impl HeaderParse for CSeq {
    fn parse<'i>(ctx: ParseCtx, i: &'i str) -> IResult<&'i str, Self> {
        map_res(
            separated_pair(
                map_res(digit1, FromStr::from_str),
                take_while(whitespace),
                Method::parse(ctx),
            ),
            |(cseq, method)| -> Result<_, ParseIntError> { Ok(CSeq { cseq, method }) },
        )(i)
    }
}

impl ExtendValues for CSeq {
    fn extend_values(&self, ctx: PrintCtx<'_>, values: &mut OneOrMore) {
        *values = self.create_values(ctx)
    }

    fn create_values(&self, _: PrintCtx<'_>) -> OneOrMore {
        OneOrMore::One(format!("{} {}", self.cseq, self.method).into())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Headers;

    const CSEQ: CSeq = CSeq {
        cseq: 123,
        method: Method::INVITE,
    };

    #[test]
    fn print_cseq() {
        let mut headers = Headers::new();
        headers.insert_named(&CSEQ);
        let headers = headers.to_string();

        assert_eq!(headers, "CSeq: 123 INVITE\r\n");
    }

    #[test]
    fn parse_cseq() {
        let mut headers = Headers::new();
        headers.insert(Name::CSEQ, "123 INVITE");

        let cseq: CSeq = headers.get_named().unwrap();
        assert_eq!(cseq, CSEQ);
    }
}
