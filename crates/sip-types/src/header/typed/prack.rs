use crate::method::Method;
use crate::parse::ParseCtx;
use crate::print::{Print, PrintCtx};
use crate::Name;
use internal::ws;
use nom::character::complete::digit1;
use nom::combinator::map_res;
use nom::IResult;
use std::fmt;
use std::num::ParseIntError;
use std::str::FromStr;

decl_from_str_header!(
    /// `RSeq` header
    #[derive(Eq, PartialEq)]
    RSeq,
    u32,
    Single,
    Name::RSEQ
);

/// `RAck` header
#[derive(Debug, Clone)]
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

    pub fn parse(ctx: ParseCtx<'_>) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            map_res(
                ws((
                    map_res(digit1, FromStr::from_str),
                    map_res(digit1, FromStr::from_str),
                    Method::parse(ctx),
                )),
                |(rack, cseq, method)| -> Result<_, ParseIntError> {
                    Ok(RAck { rack, cseq, method })
                },
            )(i)
        }
    }
}

impl Print for RAck {
    fn print(&self, f: &mut fmt::Formatter<'_>, _: PrintCtx<'_>) -> fmt::Result {
        write!(f, "{} {} {}", self.rack, self.cseq, self.method)
    }
}

__impl_header!(RAck, Single, Name::RACK);
