use crate::header::name::Name;

decl_from_str_header!(
    /// `Max-Forwards` header
    MaxForwards,
    u32,
    Single,
    Name::MAX_FORWARDS
);

#[cfg(test)]
mod test {
    use super::*;
    use crate::parse::ParseCtx;
    use crate::print::AppendCtx;
    use bytesstr::BytesStr;

    #[test]
    fn max_fwd() {
        let input = BytesStr::from_static("70");

        let (rem, content_length) = MaxForwards::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(content_length.0, 70);
    }

    #[test]
    fn max_fwd_spaces() {
        let input = BytesStr::from_static("   70   ");

        let (rem, content_length) = MaxForwards::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(content_length.0, 70);
    }

    #[test]
    fn max_fwd_print() {
        let max_fwd = MaxForwards(70);

        assert_eq!(max_fwd.default_print_ctx().to_string(), "70");
    }
}
