use crate::header::name::Name;

decl_from_str_header!(
    /// `Expires` header
    #[derive(Eq, PartialEq)]
    Expires,
    u32,
    Single,
    Name::EXPIRES
);

#[cfg(test)]
mod test {
    use super::*;
    use crate::parse::ParseCtx;
    use crate::print::AppendCtx;
    use bytesstr::BytesStr;

    #[test]
    fn expires() {
        let input = BytesStr::from_static("240");

        let (rem, content_length) = Expires::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(content_length.0, 240);
    }

    #[test]
    fn expires_spaces() {
        let input = BytesStr::from_static("   240   ");

        let (rem, expires) = Expires::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(expires.0, 240);
    }

    #[test]
    fn expires_print() {
        assert_eq!(Expires(30).default_print_ctx().to_string(), "30");
    }
}
