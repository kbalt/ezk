use crate::header::name::Name;
use crate::method::Method;
use crate::parse::{whitespace, ParseCtx};
use crate::print::{Print, PrintCtx};
use nom::bytes::complete::take_while;
use nom::character::complete::digit1;
use nom::combinator::map_res;
use nom::sequence::separated_pair;
use nom::IResult;
use std::fmt;
use std::num::ParseIntError;
use std::str::FromStr;

/// `CSeq` header
#[derive(Debug, Clone)]
pub struct CSeq {
    pub cseq: u32,
    pub method: Method,
}

impl CSeq {
    #[inline]
    pub const fn new(cseq: u32, method: Method) -> CSeq {
        CSeq { cseq, method }
    }

    pub fn parse(ctx: ParseCtx<'_>) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
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
}

impl Print for CSeq {
    fn print(&self, f: &mut fmt::Formatter<'_>, _: PrintCtx<'_>) -> fmt::Result {
        write!(f, "{} {}", self.cseq, self.method)
    }
}

__impl_header!(CSeq, Single, Name::CSEQ);

#[cfg(test)]
mod test {
    use super::*;
    use crate::print::AppendCtx;
    use bytesstr::BytesStr;

    #[test]
    fn cseq() {
        let input = BytesStr::from_static("43287 INVITE");

        let (rem, cseq) = CSeq::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(cseq.cseq, 43287);
        assert_eq!(cseq.method, Method::INVITE);
    }

    #[test]
    fn cseq_more_spaces() {
        let input = BytesStr::from_static("43287        INVITE");

        let (rem, cseq) = CSeq::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(cseq.cseq, 43287);
        assert_eq!(cseq.method, Method::INVITE);
    }

    #[test]
    fn cseq_print() {
        let cseq = CSeq::new(3487, Method::INVITE);

        assert_eq!(cseq.default_print_ctx().to_string(), "3487 INVITE");
    }
}
