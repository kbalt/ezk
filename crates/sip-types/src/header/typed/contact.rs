use crate::header::headers::OneOrMore;
use crate::header::name::Name;
use crate::header::{ConstNamed, ExtendValues, HeaderParse};
use crate::parse::ParseCtx;
use crate::print::{AppendCtx, Print, PrintCtx, UriContext};
use crate::uri::params::{Params, CPS};
use crate::uri::NameAddr;
use anyhow::Result;
use nom::combinator::map;
use nom::sequence::tuple;
use nom::Finish;
use std::fmt;

/// `Contact` header
#[derive(Debug, Clone)]
pub struct Contact {
    pub uri: NameAddr,
    pub params: Params<CPS>,
}

impl Contact {
    #[inline]
    pub fn new(uri: NameAddr) -> Contact {
        Contact {
            uri,
            params: Params::new(),
        }
    }

    impl_with_params!(params, with_key_param, with_value_param);
}

impl ConstNamed for Contact {
    const NAME: Name = Name::CONTACT;
}

impl HeaderParse for Contact {
    fn parse<'i>(ctx: ParseCtx<'_>, i: &'i str) -> Result<(&'i str, Self)> {
        let (rem, contact) = map(
            tuple((NameAddr::parse_no_params(ctx), Params::<CPS>::parse(ctx))),
            |(uri, params)| Contact { uri, params },
        )(i)
        .finish()?;

        Ok((rem, contact))
    }
}

impl ExtendValues for Contact {
    fn extend_values(&self, ctx: PrintCtx<'_>, values: &mut OneOrMore) {
        let value = match values {
            OneOrMore::One(value) => value,
            OneOrMore::More(values) => values.last_mut().expect("empty OneOrMore::More variant"),
        };

        *value = format!("{}, {}", value, self.print_ctx(ctx)).into();
    }

    fn create_values(&self, ctx: PrintCtx<'_>) -> OneOrMore {
        OneOrMore::One(self.print_ctx(ctx).to_string().into())
    }
}

impl Print for Contact {
    fn print(&self, f: &mut fmt::Formatter<'_>, mut ctx: PrintCtx<'_>) -> fmt::Result {
        ctx.uri = Some(UriContext::Contact);
        write!(f, "{}{}", self.uri.print_ctx(ctx), self.params)?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::uri::sip::SipUri;
    use crate::Headers;

    fn test_contact() -> Contact {
        let uri: SipUri = "sip:example.org".parse().unwrap();

        Contact {
            uri: NameAddr::uri(uri),
            params: Params::new(),
        }
    }

    #[test]
    fn print_contact_single() {
        let mut headers = Headers::new();
        headers.insert_named(&test_contact());
        let headers = headers.to_string();

        assert_eq!(headers, "Contact: <sip:example.org>\r\n")
    }

    #[test]
    fn print_contact_multiple_vec() {
        let mut headers = Headers::new();
        headers.insert_named(&vec![test_contact(), test_contact()]);
        let headers = headers.to_string();

        assert_eq!(headers, "Contact: <sip:example.org>, <sip:example.org>\r\n")
    }

    #[test]
    fn print_contact_multiple_insert() {
        let mut headers = Headers::new();
        headers.insert_named(&test_contact());
        headers.insert_named(&test_contact());
        let headers = headers.to_string();

        assert_eq!(headers, "Contact: <sip:example.org>, <sip:example.org>\r\n")
    }

    #[test]
    fn parse_contact_single() {
        let mut headers = Headers::new();
        headers.insert(Name::CONTACT, "<sip:example.org>");

        let contact: Contact = headers.get_named().unwrap();
        assert_eq!(&contact.uri.uri, &test_contact().uri.uri);
        assert!(contact.params.is_empty());
        assert_eq!(contact.uri.name, None)
    }

    #[test]
    fn parse_multiple_vec() {
        let mut headers = Headers::new();
        headers.insert(Name::CONTACT, "<sip:example.org>, <sip:example.org>");

        let contact: Vec<Contact> = headers.get_named().unwrap();

        assert_eq!(contact.len(), 2);

        assert_eq!(&contact[0].uri.uri, &test_contact().uri.uri);
        assert!(contact[0].params.is_empty());
        assert_eq!(contact[0].uri.name, None);

        assert_eq!(&contact[1].uri.uri, &test_contact().uri.uri);
        assert!(contact[1].params.is_empty());
        assert_eq!(contact[1].uri.name, None)
    }
}
