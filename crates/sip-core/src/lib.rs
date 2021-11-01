//! Core part of the EZK SIP Stack
//!
//! Implementing transport and transaction abstractions it can be used to
//! build any kind of stateful SIP Application
//!
//! [__Examples__](https://github.com/kbalt/ezk/tree/main/examples) can be found here

use bytes::Bytes;
use downcast_rs::{impl_downcast, Downcast};
use sip_types::header::typed::{CSeq, CallID, FromTo, Via};
use sip_types::header::HeaderError;
use sip_types::msg::{RequestLine, StatusLine};
use sip_types::print::AppendCtx;
use sip_types::uri::Uri;
use sip_types::{Headers, Method, Name};
use std::fmt;
use transaction::TsxKey;
use transport::MessageTpInfo;

#[macro_use]
mod error;
mod endpoint;
mod may_take;
pub mod transaction;
pub mod transport;

pub use endpoint::Endpoint;
pub use endpoint::EndpointBuilder;
pub use endpoint::LayerKey;
pub use error::{Error, Result, StunError};
pub use may_take::MayTake;

/// Basic Response
#[derive(Debug)]
pub struct Response {
    pub line: StatusLine,
    pub headers: Headers,
    pub body: Bytes,
}

impl fmt::Display for Response {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.line.default_print_ctx().fmt(f)
    }
}

#[derive(Debug)]
/// Basic request
pub struct Request {
    pub line: RequestLine,
    pub headers: Headers,
    pub body: Bytes,
}

impl fmt::Display for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.line.default_print_ctx().fmt(f)
    }
}

impl Request {
    /// Create an empty request
    pub fn new<U>(method: Method, uri: U) -> Self
    where
        U: Into<Box<dyn Uri>>,
    {
        Self {
            line: RequestLine {
                method,
                uri: uri.into(),
            },
            headers: Default::default(),
            body: Bytes::new(),
        }
    }
}

/// Parsed SIP headers that are part of every message, part of [`IncomingRequest`].
#[derive(Debug)]
pub struct BaseHeaders {
    /// All via headers, must be guaranteed to not be empty
    pub via: Vec<Via>,
    pub from: FromTo,
    pub to: FromTo,
    pub call_id: CallID,
    pub cseq: CSeq,
}

impl BaseHeaders {
    fn extract_from(headers: &Headers) -> Result<Self, HeaderError> {
        Ok(BaseHeaders {
            via: headers.get_named()?,
            from: headers.get(Name::FROM)?,
            to: headers.get(Name::TO)?,
            call_id: headers.get_named()?,
            cseq: headers.get_named()?,
        })
    }
}

/// Request received by the endpoint and passed to every layer
#[derive(Debug)]
pub struct IncomingRequest {
    pub tp_info: MessageTpInfo,
    pub tsx_key: TsxKey,

    pub line: RequestLine,
    pub base_headers: BaseHeaders,
    pub headers: Headers,
    pub body: Bytes,
}

impl fmt::Display for IncomingRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.line.default_print_ctx().fmt(f)
    }
}

/// Layers are extensions to the endpoint.
///
/// They can be added to the endpoint in the building stage bay calling
/// [`EndpointBuilder::add_layer`], and later be accessed via [`LayerKey`]s.
#[async_trait::async_trait]
pub trait Layer: Downcast + Send + Sync + 'static {
    /// Return a descriptive and unique name of the layer
    fn name(&self) -> &'static str;

    /// When building the endpoint each layer may make modifications to the [`EndpointBuilder`]
    fn init(&mut self, _endpoint: &mut EndpointBuilder) {}

    /// Whenever the endpoint receives a request which is outside any transaction,
    /// it will call this function on each layer (in insertion order).
    ///
    /// The message is wrapped inside a [`MayTake`] which allows the layer to inspect
    /// and modify the request or take ownership of it. If it takes the request the
    /// endpoint will no longer own the request and thus will not pass the request to
    /// the remaining layers.
    async fn receive(&self, endpoint: &Endpoint, request: MayTake<'_, IncomingRequest>);
}

impl_downcast!(Layer);
