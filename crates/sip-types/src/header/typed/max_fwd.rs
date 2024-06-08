use anyhow::Result;

use crate::Name;

from_str_header! {
    /// `Max-Forwards` header
    MaxForwards,
    Name::MAX_FORWARDS,
    u32
}

#[cfg(test)]
mod test {
    use bytesstr::BytesStr;

    use crate::header::HeaderParse;
    use crate::parse::ParseCtx;

    use super::*;

    #[test]
    fn max_fwd() {
        let input = BytesStr::from_static("70");

        let (rem, content_length) = MaxForwards::parse(ParseCtx::default(&input), &input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(content_length.0, 70);
    }

    #[test]
    fn max_fwd_spaces() {
        let input = BytesStr::from_static("   70   ");

        let (rem, content_length) = MaxForwards::parse(ParseCtx::default(&input), &input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(content_length.0, 70);
    }
}
