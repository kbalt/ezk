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

pub use call::{Call, CallError, CallEvent};
pub use inbound_call::{AcceptCallError, InboundCall, InboundCallFromInviteError, NoMedia};
pub use media_backend::MediaBackend;
#[cfg(feature = "rtc")]
pub use media_rtc::{
    Codec, MediaEvent, RtcMediaBackend, RtcMediaBackendError, RtpReceiver, RtpSender,
};
pub use outbound_call::{MakeCallCompletionError, MakeCallError, OutboundCall};
pub use registration::{RegisterError, RegistrarConfig, Registration};
