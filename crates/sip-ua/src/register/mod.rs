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
    expires: u32,

    /// Re-registration interval, is set to `expires - 10`
    register_interval: Interval,
}

impl Registration {
    pub fn new(id: NameAddr, registrar: Box<dyn Uri>) -> Self {
        let duration_secs = 300;

        Self {
            registrar,
            to: FromTo::new(id.clone(), None),
            from: FromTo::new(id.clone(), Some(random_string())),
            cseq: random_sequence_number(),
            call_id: CallID::new(random_string()),
            contact: Contact::new(id),

            expires: duration_secs,
            register_interval: create_reg_interval(duration_secs),
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
            Expires(self.expires)
        };

        request.headers.insert_named(&expires);
        request.headers.insert_named(&self.contact);

        request
    }

    pub fn receive_success_response(&mut self, response: TsxResponse) {
        assert_eq!(response.line.code.kind(), CodeKind::Success);

        if let Ok(expires) = response.headers.get_named::<Expires>() {
            if self.expires != expires.0 {
                self.register_interval = create_reg_interval(expires.0);
                self.expires = expires.0;
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

        self.expires = expires.0;
        self.register_interval = create_reg_interval(self.expires);

        true
    }

    pub async fn wait_for_expiry(&mut self) {
        self.register_interval.tick().await;
    }
}

fn create_reg_interval(secs: u32) -> Interval {
    let secs = (secs - 10) as u64;
    let duration = Duration::from_secs(secs);

    let next = Instant::now() + duration;
    let mut register_interval = interval_at(next, duration);
    register_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    register_interval
}
