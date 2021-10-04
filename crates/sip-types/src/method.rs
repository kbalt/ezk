use crate::parse::{token, ParseCtx};
use bytes::Bytes;
use bytesstr::BytesStr;
use nom::branch::alt;
use nom::bytes::complete::{tag_no_case, take_while};
use nom::combinator::map;
use nom::IResult;
use std::fmt;

/// Represents a SIP-Method.
///
/// To construct a known method use the constants:
///
/// # Example
///
/// ```
/// use ezk_sip_types::Method;
///
/// // well known methods should be implemented as constants
/// let _invite_method = Method::INVITE;
///
/// // custom methods can be also used:
/// let _custom_method = Method::from("HELLO");
/// ```
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct Method(Repr);

macro_rules! methods {
    ($($(#[$comments:meta])* $print:literal, $ident:ident;)+) => {

        #[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
        #[allow(clippy::upper_case_acronyms)]
        enum Repr {
            $($ident,)+
            Other(BytesStr),
        }

        impl Method {
            $(pub const $ident : Self = Self(Repr :: $ident );)+

            fn from_parse(src: &Bytes, slice: &str) -> Self {
                if let Ok((_, repr)) = alt((
                   $(
                   map(tag_no_case($print), |_| Repr::$ident),
                   )*
                ))(slice) as IResult<&str, Repr> {
                    Self(repr)
                } else {
                    Self(Repr::Other(BytesStr::from_parse(src, slice)))
                }
            }
        }

        impl fmt::Display for Method {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match &self.0 {
                   $(Repr:: $ident => f.write_str($print),)+
                    Repr::Other(other) => f.write_str(&other),
                }
            }
        }
    };
}

methods! {
    "INVITE",      INVITE;
    "ACK",         ACK;
    "CANCEL",      CANCEL;
    "BYE",         BYE;
    "REGISTER",    REGISTER;
    "MESSAGE",     MESSAGE;
    "UPDATE",      UPDATE;
    "PRACK",       PRACK;
    "OPTIONS",     OPTIONS;
}

impl Method {
    /// returns an nom-compatible method-parser
    pub fn parse(ctx: ParseCtx<'_>) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| map(take_while(token), |slice| Self::from_parse(ctx.src, slice))(i)
    }
}

impl From<&str> for Method {
    fn from(s: &str) -> Self {
        let s = BytesStr::from(s);

        Self::from_parse(s.as_ref(), s.as_ref())
    }
}

#[cfg(test)]
mod test {
    use super::Method;
    use crate::method::Repr;
    use crate::parse::ParseCtx;
    use bytesstr::BytesStr;

    #[test]
    fn invite_method() {
        let input = BytesStr::from_static("INVITE");

        assert_eq!(
            Method::parse(ParseCtx::default(&input))(&input[..]).unwrap(),
            ("", Method::INVITE)
        );

        assert_eq!(Method::INVITE.to_string(), "INVITE");
    }

    #[test]
    fn other_method() {
        let input = BytesStr::from_static("SOMEOBSCUREMETHOD");

        let (rem, method) = Method::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());
        assert_eq!(method, Method(Repr::Other("SOMEOBSCUREMETHOD".into())));

        assert_eq!(method.to_string(), "SOMEOBSCUREMETHOD");
    }
}
