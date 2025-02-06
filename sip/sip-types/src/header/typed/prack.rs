use crate::header::headers::OneOrMore;
use crate::header::{ConstNamed, ExtendValues, HeaderParse};
use crate::method::Method;
use crate::parse::ParseCtx;
use crate::print::PrintCtx;
use crate::Name;
use internal::{ws, IResult};
use nom::character::complete::digit1;
use nom::combinator::{map, map_res};
use std::fmt;
use std::str::FromStr;

from_str_header! {
    /// `RSeq` header
    RSeq,
    Name::RSEQ,
    u32
}

/// `RAck` header
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RAck {
    pub rack: u32,
    pub cseq: u32,
    pub method: Method,
}

impl RAck {
    #[inline]
    pub const fn new(rack: u32, cseq: u32, method: Method) -> RAck {
        RAck { rack, cseq, method }
    }
}

impl ConstNamed for RAck {
    const NAME: Name = Name::RACK;
}

impl HeaderParse for RAck {
    fn parse<'i>(ctx: ParseCtx, i: &'i str) -> IResult<&'i str, Self> {
        map(
            ws((
                map_res(digit1, FromStr::from_str),
                map_res(digit1, FromStr::from_str),
                Method::parse(ctx),
            )),
            |(rack, cseq, method)| RAck { rack, cseq, method },
        )(i)
    }
}

impl ExtendValues for RAck {
    fn extend_values(&self, ctx: PrintCtx<'_>, values: &mut OneOrMore) {
        *values = self.create_values(ctx)
    }

    fn create_values(&self, _: PrintCtx<'_>) -> OneOrMore {
        OneOrMore::One(self.to_string().into())
    }
}

impl fmt::Display for RAck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.rack, self.cseq, self.method)
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Headers;

    const RACK: RAck = RAck {
        rack: 123,
        cseq: 321,
        method: Method::INVITE,
    };

    #[test]
    fn print_rack() {
        let mut headers = Headers::new();
        headers.insert_named(&RACK);
        let headers = headers.to_string();

        assert_eq!(headers, "RAck: 123 321 INVITE\r\n");
    }

    #[test]
    fn parse_rack() {
        let mut headers = Headers::new();
        headers.insert(Name::RACK, "123 321 INVITE");

        let rack: RAck = headers.get_named().unwrap();
        assert_eq!(rack, RACK);
    }
}
