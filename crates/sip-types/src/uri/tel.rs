use super::params::{Params, ParamsSpec};
use crate::parse::ParseCtx;
use bytesstr::BytesStr;
use internal::IResult;
use nom::branch::alt;
use nom::bytes::complete::{tag, take_while1};
use nom::character::complete::char;
use nom::combinator::{map, map_res};
use nom::sequence::{preceded, tuple};
use percent_encoding::AsciiSet;
use std::fmt;

#[derive(Debug, thiserror::Error)]
pub enum TelUriParseError {}

#[derive(Clone)]

pub struct TelUri {
    pub number: BytesStr,
    pub is_global: bool,
    pub params: Params<TelUriParamSpec>,
}

impl TelUri {
    pub fn parse(ctx: ParseCtx<'_>) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            map_res(
                preceded(
                    tag("tel:"),
                    tuple((
                        alt((
                            map(preceded(char('+'), take_while1(phonedigit)), |x| (true, x)),
                            map(take_while1(phonedigit_hex), |x| (false, x)),
                        )),
                        Params::parse(ctx),
                    )),
                ),
                |((is_global, number), params)| -> Result<Self, TelUriParseError> {
                    Ok(Self {
                        number: BytesStr::from_parse(ctx.src, number),
                        is_global,
                        params,
                    })
                },
            )(i)
        }
    }
}

impl fmt::Display for TelUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_global {
            write!(f, "tel:+{}{}", self.number, self.params)
        } else {
            write!(f, "tel:{}{}", self.number, self.params)
        }
    }
}

fn phonedigit(c: char) -> bool {
    lookup_table!(c => num;
        '-', '.', '(', ')'
    )
}

fn phonedigit_hex(c: char) -> bool {
    lookup_table!(c => num;
        'A', 'B', 'C', 'D', 'E', 'F',
        'a', 'b', 'c', 'd', 'e', 'f',
        '-', '.', '(', ')'
    )
}

fn pname(c: char) -> bool {
    lookup_table!(c => alpha; num; '-')
}

fn pvalue(c: char) -> bool {
    lookup_table!(c => alpha; num;
        '[', ']' , '/' , ':' , '&' , '+' , '$',
        '-' , '_' , '.' , '!' , '~', '*', '\'',  '(' , ')',
        '%'
    )
}

encode_set!(pvalue, PVALUE_SET);

#[derive(Debug, Clone)]
pub enum TelUriParamSpec {}

impl ParamsSpec for TelUriParamSpec {
    const FIRST_DELIMITER: &'static str = ";";
    const DELIMITER: &'static str = ";";
    const NAME_CHAR_SPEC: fn(char) -> bool = pname;
    const VALUE_CHAR_SPEC: fn(char) -> bool = pvalue;
    const VALUE_ENCODE_SET: fn() -> &'static AsciiSet = || &PVALUE_SET;
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn parse_global() {
        let input = BytesStr::from_static("tel:+1-201-555-0123");

        let (rem, tel) = TelUri::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        assert!(tel.is_global);
        assert_eq!(tel.number, "1-201-555-0123");
    }

    #[test]
    fn parse_local() {
        let input = BytesStr::from_static("tel:7042;phone-context=example.com");

        let (rem, tel) = TelUri::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        assert!(!tel.is_global);
        assert_eq!(tel.number, "7042");
        assert_eq!(tel.params.get_val("phone-context").unwrap(), "example.com");
    }
}
