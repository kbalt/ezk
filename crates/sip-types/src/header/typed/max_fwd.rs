use crate::Name;
use anyhow::{Error, Result};

from_str_header! {
    /// `Max-Forwards` header
    MaxForwards,
    Name::MAX_FORWARDS,
    u32
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::parse::ParseCtx;
    use crate::header::HeaderParse;
    use bytesstr::BytesStr;

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
