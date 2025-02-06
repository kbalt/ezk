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

    /// Duration until the registration expires
    expires: Duration,

    /// Re-registration interval, is set to `expires - 10`
    register_interval: Interval,
}

impl Registration {
    pub fn new(id: NameAddr, contact: Contact, registrar: Box<dyn Uri>, expiry: Duration) -> Self {
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

    /// Returns when a new REGISTER request must be sent to refresh the binding on the registrar.
    pub async fn wait_for_expiry(&mut self) {
        self.register_interval.tick().await;
    }
}

fn create_reg_interval(period: Duration) -> Interval {
    // Avoid underflow and zero duration intervals by limiting `period` to be at least 20s
    let period = period.max(Duration::from_secs(20));
    let period = period - Duration::from_secs(10);

    let next = Instant::now() + period;
    let mut register_interval = interval_at(next, period);
    register_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    register_interval
}
