use crate::header::name::Name;
use crate::parse::ParseCtx;
use crate::print::{AppendCtx, Print, PrintCtx, UriContext};
use crate::uri::params::{Params, CPS};
use crate::uri::NameAddr;
use nom::combinator::map;
use nom::sequence::tuple;
use nom::IResult;
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

    #[inline]
    pub fn parse<'p>(ctx: ParseCtx<'p>) -> impl Fn(&'p str) -> IResult<&'p str, Self> + 'p {
        move |i| {
            map(
                tuple((NameAddr::parse_no_params(ctx), Params::<CPS>::parse(ctx))),
                |(uri, params)| Contact { uri, params },
            )(i)
        }
    }
}

impl Print for Contact {
    fn print(&self, f: &mut fmt::Formatter<'_>, mut ctx: PrintCtx<'_>) -> fmt::Result {
        ctx.uri = Some(UriContext::Contact);
        write!(f, "{}{}", self.uri.print_ctx(ctx), self.params)?;
        Ok(())
    }
}

__impl_header!(Contact, Single, Name::CONTACT);

#[cfg(test)]
mod test {
    use super::*;
    use crate::host::HostPort;
    use crate::uri::sip::SipUri;
    use bytesstr::BytesStr;

    #[test]
    fn contact() {
        let input = BytesStr::from_static("Bob <sip:bob@example.com> ; lr ; expires=30");

        let (rem, contact) = Contact::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        let lr = contact.params.get("lr").unwrap();
        assert_eq!(lr.name, "lr");
        assert_eq!(lr.value, None);

        let expires = contact.params.get_val("expires").unwrap();
        assert_eq!(expires, "30");
    }

    #[test]
    fn contact_print() {
        let contact = Contact::new(NameAddr::new(
            "Bob",
            SipUri::new(HostPort::host_name("example.com")),
        ))
        .with_value_param("expires", "90");

        assert_eq!(
            contact.default_print_ctx().to_string(),
            "\"Bob\"<sip:example.com>;expires=90"
        )
    }
}
