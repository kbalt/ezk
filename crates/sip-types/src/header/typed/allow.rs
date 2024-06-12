use anyhow::{Error, Result};

use crate::header::name::Name;
use crate::method::Method;

csv_header! {
    /// `Allow` header, contains only one method.
    /// To get all allowed methods use [`Vec`].
    Allow,
    Method,
    Name::ALLOW
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Headers;

    const ALLOW_INVITE: Allow = Allow(Method::INVITE);
    const ALLOW_CANCEL: Allow = Allow(Method::CANCEL);

    #[test]
    fn print_allow_single() {
        let mut headers = Headers::new();
        headers.insert_named(&ALLOW_INVITE);
        let headers = headers.to_string();

        assert_eq!(headers, "Allow: INVITE\r\n");
    }

    #[test]
    fn print_allow_multiple_vec() {
        let allow = vec![ALLOW_INVITE, ALLOW_CANCEL];

        let mut headers = Headers::new();
        headers.insert_named(&allow);
        let headers = headers.to_string();

        assert_eq!(headers, "Allow: INVITE, CANCEL\r\n");
    }

    #[test]
    fn print_allow_multiple_insert() {
        let mut headers = Headers::new();
        headers.insert_named(&ALLOW_INVITE);
        headers.insert_named(&ALLOW_CANCEL);
        let headers = headers.to_string();

        assert_eq!(headers, "Allow: INVITE, CANCEL\r\n");
    }

    #[test]
    fn parse_allow_single() {
        let mut headers = Headers::new();
        headers.insert(Name::ALLOW, "INVITE");

        let allow: Allow = headers.get_named().unwrap();
        assert_eq!(allow, ALLOW_INVITE)
    }

    #[test]
    fn parse_allow_multiple_vec() {
        let mut headers = Headers::new();
        headers.insert(Name::ALLOW, "INVITE, CANCEL");

        let allow: Vec<Allow> = headers.get_named().unwrap();
        assert_eq!(allow, vec![ALLOW_INVITE, ALLOW_CANCEL])
    }
}
