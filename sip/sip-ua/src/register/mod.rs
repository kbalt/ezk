use crate::util::{random_sequence_number, random_string};
use sip_core::Request;
use sip_core::transaction::TsxResponse;
use sip_types::header::typed::{CSeq, CallID, Contact, Expires, FromTo, MinExpires};
use sip_types::uri::{NameAddr, SipUri};
use sip_types::{CodeKind, Headers, Method, Name};
use std::time::Duration;
use tokio::time::{Instant, Interval, interval_at};

pub struct Registration {
    registrar: SipUri,

    to: FromTo,
    from: FromTo,

    cseq: u32,
    call_id: CallID,
    contact: Contact,

    /// Duration until the registration expires
    expires: Duration,

    /// Re-registration interval, leaving a margin before expiry.
    register_interval: Interval,
}

impl Registration {
    pub fn new(id: NameAddr, contact: Contact, registrar: SipUri, expiry: Duration) -> Self {
        Self {
            registrar,
            to: FromTo::new(id.clone(), None),
            from: FromTo::new(id, Some(random_string())),
            cseq: random_sequence_number(),
            call_id: CallID::new(random_string()),
            contact,

            expires: expiry,
            register_interval: create_reg_interval(expiry),
        }
    }

    /// Create a new REGISTER request.
    ///
    /// `remove_binding` must be `false` to create a new binding on the registrar.
    /// If the value is `true` the REGISTER request will remove any active bindings.
    pub fn create_register(&mut self, remove_binding: bool) -> Request {
        let mut request = Request::new(Method::REGISTER, self.registrar.clone());

        request.headers.insert_type(Name::FROM, &self.from);
        request.headers.insert_type(Name::TO, &self.to);
        request.headers.insert_named(&self.call_id);

        self.cseq += 1;
        let cseq = CSeq::new(self.cseq, Method::REGISTER);

        request.headers.insert_named(&cseq);

        let expires = if remove_binding {
            Expires(0)
        } else {
            Expires(self.expires.as_secs() as u32)
        };

        request.headers.insert_named(&expires);
        request.headers.insert_named(&self.contact);

        request
    }

    /// Handle the success response received from a registrar
    ///
    /// Updates internal re-registration timer.
    /// [`Self::wait_for_expiry`] should be used to wait until refreshing the binding with the registrar.
    /// The matching Contact's `expires` parameter takes precedence over Expires.
    pub fn receive_success_response(&mut self, response: TsxResponse) {
        assert_eq!(response.line.code.kind(), CodeKind::Success);

        self.update_expiry(&response.headers);
    }

    fn update_expiry(&mut self, headers: &Headers) {
        // RFC 3261 section 10.2.4: a registrar returns all bindings, with each
        // binding's lifetime on its Contact. Only use the one we registered.
        let contact_expiry = headers
            .get_named::<Vec<Contact>>()
            .ok()
            .and_then(|contacts| {
                contacts
                    .into_iter()
                    .find(|contact| contact.uri.uri.compare(&self.contact.uri.uri))
            })
            .and_then(|contact| contact.params.get_val_ignore_ascii_case("expires").cloned());
        let expires = match contact_expiry {
            Some(expires) => expires.parse::<u32>().ok(),
            None => headers.get_named::<Expires>().ok().map(|expires| expires.0),
        };

        if let Some(expires) = expires {
            let expires = Duration::from_secs(expires.into());
            if self.expires != expires {
                self.register_interval = create_reg_interval(expires);
                self.expires = expires;
            }
        }
    }

    /// Handle an error response received from a registrar
    ///
    /// Returns whether or not to retry the registration
    pub fn receive_error_response(&mut self, response: TsxResponse) -> bool {
        if !matches!(response.line.code.kind(), CodeKind::RequestFailure) {
            return false;
        }

        let Ok(expires) = response.headers.get_named::<MinExpires>() else {
            return false;
        };

        self.expires = Duration::from_secs(expires.0 as _);
        self.register_interval = create_reg_interval(self.expires);

        true
    }

    /// Reset the expiry timer. This will cause `wait_for_expiry` to finish immediately on the next call.
    pub fn reset_expiry_timer(&mut self) {
        self.register_interval.reset_immediately();
    }

    /// Returns when a new REGISTER request must be sent to refresh the binding on the registrar.
    pub async fn wait_for_expiry(&mut self) {
        self.register_interval.tick().await;
    }
}

fn create_reg_interval(expiry: Duration) -> Interval {
    // Keep the existing ten-second margin for long bindings, but refresh
    // halfway through short bindings instead of waiting until they expire.
    let period = if expiry.is_zero() {
        // Preserve the existing zero-lifetime timer behavior.
        Duration::from_secs(10)
    } else {
        expiry - Duration::from_secs(10).min(expiry / 2)
    };

    let next = Instant::now() + period;
    let mut register_interval = interval_at(next, period);
    register_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    register_interval
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registration() -> Registration {
        Registration::new(
            NameAddr::uri("sip:alice@example.com".parse().unwrap()),
            Contact::new(NameAddr::uri("sip:alice@127.0.0.1:5060".parse().unwrap())),
            "sip:example.com".parse().unwrap(),
            Duration::from_secs(300),
        )
    }

    #[tokio::test(start_paused = true)]
    async fn selects_matching_contact_expiry_before_header_fallback() {
        for (contacts, expires, expected) in [
            (Some("<sip:alice@127.0.0.1:5060>;expires=10"), None, 10),
            (Some("<sip:alice@127.0.0.1:5060>;expires=10"), Some(300), 10),
            (
                Some("<sip:bob@127.0.0.1:5060>;expires=1, <sip:alice@127.0.0.1:5060>;expires=12"),
                None,
                12,
            ),
            (
                Some("<sip:alice@127.0.0.1:5061>;expires=1, <sip:alice@127.0.0.1:5060>;expires=14"),
                None,
                14,
            ),
            (Some("<sip:alice@127.0.0.2:5060>;expires=1"), Some(20), 20),
            (Some("<sip:bob@127.0.0.1:5060>;expires=1"), None, 300),
            (Some("<sip:alice@127.0.0.1:5060>"), Some(20), 20),
            (Some("<sip:alice@127.0.0.1:5060>"), None, 300),
            (
                Some("<sip:alice@127.0.0.1:5060>;expires=invalid"),
                Some(20),
                300,
            ),
            (
                Some("<sip:alice@127.0.0.1:5060>;expires=4294967296"),
                None,
                300,
            ),
            (None, Some(20), 20),
            (None, None, 300),
        ] {
            let mut registration = registration();
            let mut headers = Headers::new();
            if let Some(contacts) = contacts {
                headers.insert(Name::CONTACT, contacts);
            }
            if let Some(expires) = expires {
                headers.insert_named(&Expires(expires));
            }
            registration.update_expiry(&headers);
            assert_eq!(
                registration.expires.as_secs(),
                expected,
                "{contacts:?}, {expires:?}"
            );
        }
    }

    #[tokio::test(start_paused = true)]
    async fn contact_expiry_name_is_case_insensitive() {
        for name in ["expires", "Expires", "ExPiReS"] {
            for header_expiry in [None, Some(300)] {
                let mut registration = registration();
                let mut headers = Headers::new();
                headers.insert(
                    Name::CONTACT,
                    format!("<sip:alice@127.0.0.1:5060>;{name}=10"),
                );
                if let Some(expires) = header_expiry {
                    headers.insert_named(&Expires(expires));
                }

                registration.update_expiry(&headers);

                assert_eq!(registration.expires, Duration::from_secs(10), "{name}");
                let start = Instant::now();
                registration.wait_for_expiry().await;
                assert_eq!(start.elapsed(), Duration::from_secs(5), "{name}");
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn finds_matching_contact_across_separate_headers() {
        let mut registration = registration();
        let mut headers = Headers::new();
        headers.insert(Name::CONTACT, "<sip:bob@127.0.0.1:5060>;expires=1");
        headers.insert(Name::CONTACT, "<sip:alice@127.0.0.1:5060>;expires=10");
        registration.update_expiry(&headers);
        assert_eq!(registration.expires, Duration::from_secs(10));
    }

    #[tokio::test(start_paused = true)]
    async fn short_bindings_refresh_before_expiry() {
        for (expiry, expected_period) in [
            (1, 0.5),
            (2, 1.0),
            (10, 5.0),
            (20, 10.0),
            (21, 11.0),
            (300, 290.0),
        ] {
            let expiry = Duration::from_secs(expiry);
            let mut interval = create_reg_interval(expiry);
            let start = Instant::now();
            interval.tick().await;
            assert_eq!(start.elapsed(), Duration::from_secs_f64(expected_period));
            assert!(start.elapsed() < expiry);
        }
    }
}
