//! Exercise the Contact parsing and URI predicate used by registration response
//! selection, without depending on the sip-ua registration state machine.
use ezk_sip_types::header::typed::Contact;
use ezk_sip_types::uri::SipUri;
use ezk_sip_types::{Headers, Name};

#[test]
fn select_matching_registration_contact_not_first_same_address() {
    for (registered, contacts, expires) in [
        (
            "sip:alice@example.com;transport=tcp",
            "<sip:alice@example.com;transport=udp>;expires=10, <sip:alice@EXAMPLE.COM;Transport=TCP>;expires=120",
            "120",
        ),
        (
            "sip:alice@example.com",
            "<sip:alice@example.com:5060>;expires=10, <sip:alice@EXAMPLE.COM>;expires=180",
            "180",
        ),
        (
            "sip:alice@example.com?subject=right",
            "<sip:alice@example.com?subject=wrong>;expires=10, <sip:alice@example.com?Subject=right>;expires=240",
            "240",
        ),
    ] {
        let registered: SipUri = registered.parse().unwrap();
        let mut headers = Headers::new();
        headers.insert(Name::CONTACT, contacts);
        let contacts: Vec<Contact> = headers.get_named().unwrap();
        let selected = contacts
            .iter()
            .find(|contact| contact.uri.uri.compare(&registered))
            .unwrap();
        assert_eq!(selected.params.get_val("expires").unwrap(), expires);
    }
}
