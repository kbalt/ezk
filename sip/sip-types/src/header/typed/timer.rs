use crate::header::{ConstNamed, ExtendValues, HeaderParse, OneOrMore};
use crate::print::{AppendCtx, Print, PrintCtx};
use crate::uri::params::{Params, CPS};
use crate::Name;
use bytes::Bytes;
use internal::{ws, IResult};
use nom::character::complete::alphanumeric1;
use nom::combinator::{map, map_res};
use std::fmt;
use std::str::FromStr;

from_str_header! {
    /// `Min-SE` header
    MinSe,
    Name::MIN_SE,
    u32
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refresher {
    Unspecified,
    Uas,
    Uac,
}

/// Session-Expires header
#[derive(Debug, Clone, Copy)]
pub struct SessionExpires {
    pub delta_secs: u32,
    pub refresher: Refresher,
}

impl ConstNamed for SessionExpires {
    const NAME: Name = Name::SESSION_EXPIRES;
}

impl HeaderParse for SessionExpires {
    fn parse<'i>(src: &'i Bytes, i: &'i str) -> IResult<&'i str, Self> {
        map(
            ws((
                map_res(alphanumeric1, FromStr::from_str),
                Params::<CPS>::parse(src),
            )),
            |(delta_secs, mut params)| -> Self {
                let refresher = if let Some(param) = params.take("refresher") {
                    match param.as_str() {
                        "uas" => Refresher::Uas,
                        "uac" => Refresher::Uac,
                        _ => Refresher::Unspecified,
                    }
                } else {
                    Refresher::Unspecified
                };

                Self {
                    delta_secs,
                    refresher,
                }
            },
        )(i)
    }
}

impl ExtendValues for SessionExpires {
    fn extend_values(&self, ctx: PrintCtx<'_>, values: &mut OneOrMore) {
        *values = self.create_values(ctx)
    }

    fn create_values(&self, ctx: PrintCtx<'_>) -> OneOrMore {
        OneOrMore::One(self.print_ctx(ctx).to_string().into())
    }
}

impl Print for SessionExpires {
    fn print(&self, f: &mut fmt::Formatter<'_>, _: PrintCtx<'_>) -> fmt::Result {
        write!(f, "{}", self.delta_secs)?;

        match self.refresher {
            Refresher::Unspecified => {}
            Refresher::Uas => write!(f, ";refresher=uas")?,
            Refresher::Uac => write!(f, ";refresher=uac")?,
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use bytesstr::BytesStr;

    #[test]
    fn min_se() {
        let input = BytesStr::from_static("160");

        let (rem, min_se) = MinSe::parse(input.as_ref(), &input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(min_se.0, 160);
    }

    #[test]
    fn session_expires() {
        let input = BytesStr::from_static("1000");

        let (rem, se) = SessionExpires::parse(input.as_ref(), &input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(se.delta_secs, 1000);
        assert_eq!(se.refresher, Refresher::Unspecified);
    }

    #[test]
    fn session_expires_refresher_uac() {
        let input = BytesStr::from_static("1000;refresher=uac");

        let (rem, se) = SessionExpires::parse(input.as_ref(), &input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(se.delta_secs, 1000);
        assert_eq!(se.refresher, Refresher::Uac);
    }

    #[test]
    fn session_expires_refresher_uas() {
        let input = BytesStr::from_static("1000;refresher=uas");

        let (rem, se) = SessionExpires::parse(input.as_ref(), &input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(se.delta_secs, 1000);
        assert_eq!(se.refresher, Refresher::Uas);
    }
}
