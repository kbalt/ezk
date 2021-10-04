//! [RFC3891](https://datatracker.ietf.org/doc/html//rfc3891)

use crate::parse::ParseCtx;
use crate::print::{Print, PrintCtx};
use crate::uri::params::{Params, CPS};
use crate::Name;
use anyhow::{Context, Result};
use bytesstr::BytesStr;
use internal::ws;
use nom::combinator::map_res;
use nom::{bytes::complete::take_while1, IResult};
use std::fmt;

#[derive(Debug)]
pub struct Replaces {
    pub call_id: BytesStr,
    pub to_tag: BytesStr,
    pub from_tag: BytesStr,
    pub early_only: bool,
}

impl Replaces {
    pub fn parse<'p>(ctx: ParseCtx<'p>) -> impl Fn(&'p str) -> IResult<&'p str, Self> + 'p {
        move |i| {
            map_res(
                ws((take_while1(|b| b != ';'), Params::<CPS>::parse(ctx))),
                |(call_id, mut params)| -> Result<Self> {
                    Ok(Self {
                        call_id: BytesStr::from_parse(ctx.src, call_id),
                        to_tag: params.take("to-tag").context("missing to-tag")?,
                        from_tag: params.take("from-tag").context("missing from-tag")?,
                        early_only: params.get("early-only").is_some(),
                    })
                },
            )(i)
        }
    }
}

impl Print for Replaces {
    fn print(&self, f: &mut fmt::Formatter<'_>, _: PrintCtx<'_>) -> fmt::Result {
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

__impl_header!(Replaces, Single, Name::REPLACES);
