use crate::header::name::Name;
use crate::parse::ParseCtx;
use crate::print::{Print, PrintCtx};
use bytesstr::BytesStr;
use nom::IResult;
use std::fmt;

/// `Call-ID`header
#[derive(Debug, Clone)]
pub struct CallID(pub BytesStr);

impl CallID {
    /// Returns a new Call-ID header
    pub fn new<B>(id: B) -> Self
    where
        B: Into<BytesStr>,
    {
        CallID(id.into())
    }

    pub(crate) fn parse(ctx: ParseCtx<'_>) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| Ok(("", CallID(BytesStr::from_parse(ctx.src, i.trim()))))
    }
}

impl Print for CallID {
    fn print(&self, f: &mut fmt::Formatter<'_>, _: PrintCtx<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

__impl_header!(CallID, Single, Name::CALL_ID);

#[cfg(test)]
mod test {
    use super::*;
    use crate::print::AppendCtx;

    #[test]
    fn call_id() {
        let input = BytesStr::from_static("«SomeTestBytes»");

        let (rem, cid) = CallID::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(cid.0, "«SomeTestBytes»")
    }

    #[test]
    fn call_id_trim() {
        let input = BytesStr::from_static("   «SomeTestBytes»    ");

        let (rem, cid) = CallID::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(cid.0, "«SomeTestBytes»")
    }

    #[test]
    fn call_id_print() {
        let cid = CallID::new("abc123");

        assert_eq!(cid.default_print_ctx().to_string(), "abc123");
    }
}
