use crate::parse::ParseCtx;
use bytesstr::BytesStr;
use nom::bytes::complete::take_while1;
use nom::combinator::map;
use nom::IResult;
use std::marker::PhantomData;

pub trait TextSpec {
    const SPEC: fn(char) -> bool;
}

pub enum CsvTextSpec {}

impl TextSpec for CsvTextSpec {
    const SPEC: fn(char) -> bool = |c| c != ',';
}

pub enum SingleTextSpec {}

impl TextSpec for SingleTextSpec {
    const SPEC: fn(char) -> bool = |c| !c.is_ascii_whitespace();
}

pub struct Text<S> {
    m: PhantomData<S>,
}

impl<S: TextSpec> Text<S> {
    pub fn parse(ctx: ParseCtx<'_>) -> impl Fn(&str) -> IResult<&str, BytesStr> + '_ {
        move |i| {
            map(take_while1(S::SPEC), move |slice| {
                BytesStr::from_parse(ctx.src, str::trim(slice))
            })(i)
        }
    }
}
