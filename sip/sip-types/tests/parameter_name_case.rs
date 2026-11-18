use ezk_sip_types::header::typed::{
    Contact, FromTo, Refresher, Replaces, SessionExpires, SubscriptionState,
};
use ezk_sip_types::print::{AppendCtx, PrintCtx, UriContext};
use ezk_sip_types::uri::SipUri;
use ezk_sip_types::{Headers, Method, Name};

#[test]
fn from_to_tag_names_ignore_case_but_values_do_not() {
    for name in [Name::FROM, Name::TO] {
        let mut headers = Headers::new();
        headers.insert(name.clone(), "<sip:alice@example.com>;TaG=AbC");
        let parsed: FromTo = headers.get(name).unwrap();
        assert_eq!(parsed.tag.as_deref(), Some("AbC"));
        assert!(parsed.params.is_empty());
    }
}

#[test]
fn replaces_parameter_names_ignore_case() {
    let mut headers = Headers::new();
    headers.insert(Name::REPLACES, "CallID;From-Tag=AbC;TO-TAG=dEf;Early-Only");
    let parsed: Replaces = headers.get_named().unwrap();
    assert_eq!(parsed.call_id, "CallID");
    assert_eq!(parsed.from_tag, "AbC");
    assert_eq!(parsed.to_tag, "dEf");
    assert!(parsed.early_only);
}

#[test]
fn subscription_and_timer_parameter_names_ignore_case() {
    let mut headers = Headers::new();
    headers.insert(
        Name::SUBSCRIPTION_STATE,
        "terminated;Reason=timeout;EXPIRES=60;Retry-After=30",
    );
    let parsed: SubscriptionState = headers.get_named().unwrap();
    assert_eq!(parsed.reason.unwrap().to_string(), "timeout");
    assert_eq!(parsed.expires, Some(60));
    assert_eq!(parsed.retry_after, Some(30));
    assert!(parsed.params.is_empty());
    headers.insert(Name::SESSION_EXPIRES, "90;ReFrEsHeR=uas");
    let timer: SessionExpires = headers.get_named().unwrap();
    assert_eq!(timer.refresher, Refresher::Uas);
}

#[test]
fn parameter_builder_updates_existing_mixed_case_name() {
    let mut headers = Headers::new();
    headers.insert(Name::CONTACT, "<sip:alice@example.com>;ExPiReS=10");
    let contact: Contact = headers.get_named().unwrap();
    let contact = contact.with_value_param("expires", "20");
    assert_eq!(
        contact.default_print_ctx().to_string(),
        "<sip:alice@example.com>;ExPiReS=20"
    );
}

#[test]
fn uri_context_filtering_ignores_parameter_name_case() {
    let uri: SipUri =
        "sip:alice@example.com;MADDR=proxy.example.com;TTL=5;Transport=tcp;LR;X-Custom=AbC"
            .parse()
            .unwrap();
    for (context, method, expected) in [
        (
            UriContext::FromTo,
            None,
            "sip:alice@example.com;X-Custom=AbC",
        ),
        (
            UriContext::Contact,
            Some(&Method::REGISTER),
            "sip:alice@example.com;MADDR=proxy.example.com;TTL=5;Transport=tcp;X-Custom=AbC",
        ),
        (
            UriContext::Routing,
            None,
            "sip:alice@example.com;MADDR=proxy.example.com;Transport=tcp;LR;X-Custom=AbC",
        ),
        (
            UriContext::Contact,
            None,
            "sip:alice@example.com;MADDR=proxy.example.com;Transport=tcp;LR;X-Custom=AbC",
        ),
    ] {
        assert_eq!(
            uri.print_ctx(PrintCtx {
                uri: Some(context),
                method
            })
            .to_string(),
            expected
        );
    }
}
