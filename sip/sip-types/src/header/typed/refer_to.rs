use crate::{
    Name,
    header::{ConstNamed, ExtendValues, HeaderParse, headers::OneOrMore},
    print::{AppendCtx, Print, PrintCtx},
    uri::{
        NameAddr,
        params::{CPS, Params},
    },
};
use bytes::Bytes;
use core::fmt;
use internal::IResult;
use nom::{combinator::map, sequence::tuple};

/// Refer-To Header
///
/// See https://www.rfc-editor.org/rfc/rfc3515#section-2.1
pub struct ReferTo {
    pub uri: NameAddr,
    pub params: Params<CPS>,
}

impl ConstNamed for ReferTo {
    const NAME: Name = Name::REFER_TO;
}

impl HeaderParse for ReferTo {
    fn parse<'i>(src: &'i Bytes, i: &'i str) -> IResult<&'i str, Self> {
        map(
            tuple((NameAddr::parse_no_params(src), Params::<CPS>::parse(src))),
            |(uri, params)| ReferTo { uri, params },
        )(i)
    }
}

impl ExtendValues for ReferTo {
    fn extend_values(&self, ctx: PrintCtx<'_>, values: &mut OneOrMore) {
        let value = match values {
            OneOrMore::One(value) => value,
            OneOrMore::More(values) => values.last_mut().expect("empty OneOrMore::More variant"),
        };

        *value = format!("{}, {}", value, self.print_ctx(ctx)).into();
    }

    fn create_values(&self, ctx: PrintCtx<'_>) -> OneOrMore {
        OneOrMore::One(self.print_ctx(ctx).to_string().into())
    }
}

impl Print for ReferTo {
    fn print(&self, f: &mut fmt::Formatter<'_>, ctx: PrintCtx<'_>) -> fmt::Result {
        write!(f, "{}{}", self.uri.print_ctx(ctx), self.params)?;
        Ok(())
    }
}
