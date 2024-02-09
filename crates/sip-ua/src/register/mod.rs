use crate::util::{random_sequence_number, random_string};
use sip_core::transaction::TsxResponse;
use sip_core::Request;
use sip_types::header::typed::{CSeq, CallID, Contact, Expires, FromTo, MinExpires};
use sip_types::uri::{NameAddr, Uri};
use sip_types::{CodeKind, Method, Name};
use std::time::Duration;
use tokio::time::{interval_at, Instant, Interval};

pub struct Registration {
    registrar: Box<dyn Uri>,

    to: FromTo,
    from: FromTo,

    cseq: u32,
    call_id: CallID,
    contact: Contact,

    /// Amount of seconds until the registration expires
    expires: Duration,

    /// Re-registration interval, is set to `expires - 10`
    register_interval: Interval,
}

impl Registration {
    pub fn new(id: NameAddr, contact: NameAddr, registrar: Box<dyn Uri>, expiry: Duration) -> Self {
        Self {
            registrar,
            to: FromTo::new(id.clone(), None),
            from: FromTo::new(id, Some(random_string())),
            cseq: random_sequence_number(),
            call_id: CallID::new(random_string()),
            contact: Contact::new(contact),

            expires: expiry,
            register_interval: create_reg_interval(expiry),
        }
    }

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

    pub fn receive_success_response(&mut self, response: TsxResponse) {
        assert_eq!(response.line.code.kind(), CodeKind::Success);

        if let Ok(expires) = response.headers.get_named::<Expires>() {
            let expires = Duration::from_secs(expires.0 as _);

            if self.expires != expires {
                self.register_interval = create_reg_interval(expires);
                self.expires = expires;
            }
        }

        if self.to.tag.is_none() {
            self.to.tag = response.base_headers.to.tag;
        }
    }

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

    pub async fn wait_for_expiry(&mut self) {
        self.register_interval.tick().await;
    }
}

fn create_reg_interval(period: Duration) -> Interval {
    let period = period - Duration::from_secs(10);

    let next = Instant::now() + period;
    let mut register_interval = interval_at(next, period);
    register_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    register_interval
}
