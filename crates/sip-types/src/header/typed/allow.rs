use crate::header::name::Name;
use crate::method::Method;

impl_wrap_header!(
    /// `Allow` header, contains only one method. To get all allowed methods use [`Vec`].
    #[derive(PartialEq)]
    Method,
    Allow,
    CSV,
    Name::ALLOW
);

#[cfg(test)]
mod test {
    use super::*;
    use crate::parse::ParseCtx;
    use crate::print::AppendCtx;
    use bytesstr::BytesStr;

    #[test]
    fn allow() {
        let input = BytesStr::from_static("INVITE");

        let (rem, allow) = Allow::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(allow.0, Method::INVITE);
    }

    #[test]
    fn allow_print() {
        assert_eq!(
            Allow::from(Method::INVITE).default_print_ctx().to_string(),
            "INVITE"
        );
    }
}
