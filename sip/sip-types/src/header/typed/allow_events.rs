use crate::header::name::Name;
use bytesstr::BytesStr;

csv_header! {
    /// `Allow-Events` header, contains only one event.
    /// To get all allowed events use [`Vec`].
    AllowEvents,
    BytesStr,
    Name::ALLOW_EVENTS
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::Headers;

    const ALLOW_EVENTS_DIALOG: AllowEvents = AllowEvents(BytesStr::from_static("dialog"));
    const ALLOW_EVENTS_MESSAGE_SUMMARY: AllowEvents =
        AllowEvents(BytesStr::from_static("message-summary"));

    #[test]
    fn print_allow_single() {
        let mut headers = Headers::new();
        headers.insert_named(&ALLOW_EVENTS_DIALOG);
        let headers = headers.to_string();

        assert_eq!(headers, "Allow-Events: dialog\r\n");
    }

    #[test]
    fn print_allow_multiple_vec() {
        let allow = vec![ALLOW_EVENTS_DIALOG, ALLOW_EVENTS_MESSAGE_SUMMARY];

        let mut headers = Headers::new();
        headers.insert_named(&allow);
        let headers = headers.to_string();

        assert_eq!(headers, "Allow-Events: dialog, message-summary\r\n");
    }

    #[test]
    fn print_allow_multiple_insert() {
        let mut headers = Headers::new();
        headers.insert_named(&ALLOW_EVENTS_DIALOG);
        headers.insert_named(&ALLOW_EVENTS_MESSAGE_SUMMARY);
        let headers = headers.to_string();

        assert_eq!(headers, "Allow-Events: dialog, message-summary\r\n");
    }

    #[test]
    fn parse_allow_single() {
        let mut headers = Headers::new();
        headers.insert(Name::ALLOW_EVENTS, "dialog");

        let allow_events: AllowEvents = headers.get_named().unwrap();
        assert_eq!(allow_events, ALLOW_EVENTS_DIALOG)
    }

    #[test]
    fn parse_allow_multiple_vec() {
        let mut headers = Headers::new();
        headers.insert(Name::ALLOW_EVENTS, "dialog, message-summary");

        let allow: Vec<AllowEvents> = headers.get_named().unwrap();
        assert_eq!(
            allow,
            vec![ALLOW_EVENTS_DIALOG, ALLOW_EVENTS_MESSAGE_SUMMARY]
        )
    }
}
