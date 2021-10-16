use crate::header::headers::OneOrMore;
use crate::header::name::Name;
use crate::header::{ConstNamed, ExtendValues, HeaderParse};
use crate::parse::ParseCtx;
use crate::print::PrintCtx;
use anyhow::Result;
use bytesstr::BytesStr;

csv_header! {
    /// `Accept` header, contains only one supported format.
    /// To get all supported extension use [`Vec`].
    Accept,
    BytesStr,
    Name::ACCEPT
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Headers;

    const ACCEPT_SDP: Accept = Accept(BytesStr::from_static("application/sdp"));
    const ACCEPT_TEXT: Accept = Accept(BytesStr::from_static("text/plain"));

    #[test]
    fn print_accept_single() {
        let mut headers = Headers::new();
        headers.insert_named(&ACCEPT_SDP);
        let headers = headers.to_string();

        assert_eq!(headers, "Accept: application/sdp\r\n");
    }

    #[test]
    fn print_accept_multiple_vec() {
        let accept = vec![ACCEPT_SDP, ACCEPT_TEXT];

        let mut headers = Headers::new();
        headers.insert_named(&accept);
        let headers = headers.to_string();

        assert_eq!(headers, "Accept: application/sdp, text/plain\r\n");
    }

    #[test]
    fn print_accept_multiple_insert() {
        let mut headers = Headers::new();
        headers.insert_named(&ACCEPT_SDP);
        headers.insert_named(&ACCEPT_TEXT);
        let headers = headers.to_string();

        assert_eq!(headers, "Accept: application/sdp, text/plain\r\n");
    }

    #[test]
    fn parse_accept_single() {
        let mut headers = Headers::new();
        headers.insert(Name::ACCEPT, "application/sdp");

        let accept: Accept = headers.get_named().unwrap();
        assert_eq!(accept, ACCEPT_SDP)
    }

    #[test]
    fn parse_accept_multiple_vec() {
        let mut headers = Headers::new();
        headers.insert(Name::ACCEPT, "application/sdp, text/plain");

        let accept: Vec<Accept> = headers.get_named().unwrap();
        assert_eq!(accept, vec![ACCEPT_SDP, ACCEPT_TEXT])
    }
}
