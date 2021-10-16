use crate::header::headers::OneOrMore;
use crate::header::{ConstNamed, ExtendValues, HeaderParse};
use crate::parse::ParseCtx;
use crate::print::PrintCtx;
use crate::Name;
use anyhow::Result;

from_str_header! {
    /// `Expires` header
    Expires,
    Name::EXPIRES,
    u32
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Headers;

    const EXPIRES: Expires = Expires(300);

    #[test]
    fn print_expires() {
        let mut headers = Headers::new();
        headers.insert_named(&EXPIRES);
        let headers = headers.to_string();

        assert_eq!(headers, "Expires: 300\r\n");
    }

    #[test]
    fn parse_expires() {
        let mut headers = Headers::new();
        headers.insert(Name::EXPIRES, "300");

        let expires: Expires = headers.get_named().unwrap();
        assert_eq!(expires, EXPIRES);
    }
}
