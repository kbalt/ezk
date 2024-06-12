use crate::Name;
use anyhow::{Error, Result};

from_str_header! {
    /// `Expires` header
    Expires,
    Name::EXPIRES,
    u32
}

from_str_header! {
    /// `Min-Expires` header
    MinExpires,
    Name::MIN_EXPIRES,
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

    const MIN_EXPIRES: MinExpires = MinExpires(300);

    #[test]
    fn print_min_expires() {
        let mut headers = Headers::new();
        headers.insert_named(&MIN_EXPIRES);
        let headers = headers.to_string();

        assert_eq!(headers, "Min-Expires: 300\r\n");
    }

    #[test]
    fn parse_min_expires() {
        let mut headers = Headers::new();
        headers.insert(Name::MIN_EXPIRES, "300");

        let min_expires: MinExpires = headers.get_named().unwrap();
        assert_eq!(min_expires, MIN_EXPIRES);
    }
}
