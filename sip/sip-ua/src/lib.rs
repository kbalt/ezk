//! # SIP User Agent
//!
//! Provides abstraction for SIP calls & SDP based media backends.
//!
//! Notable types are
//!
//! - [`Registration`] A binding to a SIP registrar with an associated identity
//! - [`Call`] an established and running INVITE session with negotiated SDP
//! - [`OutboundCall`] An attempt to create a `Call`
//! - [`InboundCall`] An incoming INVITE session which can be accepted or declined
//!
//! The modules [`dialog`], [`invite`], [`register`] and [`util`] contain implementation details used inside the top
//! level abstractions and can be used for more specialized use cases.
//!

pub mod dialog;
pub mod invite;
pub mod register;
pub mod util;

mod call;
mod inbound_call;
mod media_backend;
#[cfg(feature = "rtc")]
mod media_rtc;
mod outbound_call;
mod refer;
mod registration;
mod subscription;

pub use call::{Call, CallError, CallEvent, ReferError};
pub use inbound_call::{AcceptCallError, InboundCall, InboundCallFromInviteError, NoMedia};
pub use media_backend::MediaBackend;
#[cfg(feature = "rtc")]
pub use media_rtc::{
    Codec, MediaEvent, RtcMediaBackend, RtcMediaBackendError, RtpReceiver, RtpSender,
};
pub use outbound_call::{MakeCallCompletionError, MakeCallError, OutboundCall};
pub use refer::{ReferEvent, ReferEventFromNotifyError};
pub use registration::{RegisterError, RegistrarConfig, Registration};
pub use subscription::EventSubscriptionReceiver;

fn append_headers(destination: &mut sip_types::Headers, headers: &sip_types::Headers) {
    destination.extend(
        headers
            .iter()
            .map(|(name, value)| (name.clone(), value.clone())),
    );
}

#[cfg(test)]
mod tests {
    use sip_types::{Headers, Name};

    use super::append_headers;

    #[test]
    fn appends_supplied_headers_without_replacing_existing_headers() {
        let mut destination = Headers::new();
        destination.insert(Name::CALL_ID, "generated-call-id");
        let mut supplied = Headers::new();
        supplied.insert("X-Custom-Header", "custom-value");

        append_headers(&mut destination, &supplied);

        assert_eq!(
            destination
                .get_raw(&Name::CALL_ID)
                .next()
                .map(|value| value.as_str()),
            Some("generated-call-id")
        );
        assert_eq!(
            destination
                .get_raw(&Name::from("X-Custom-Header"))
                .next()
                .map(|value| value.as_str()),
            Some("custom-value")
        );
    }
}
