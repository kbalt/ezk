use sip_types::Headers;
use sip_types::msg::{RequestLine, StatusLine};
use std::error::Error;
use std::fmt::Debug;

mod digest;

pub use digest::{DigestAuthenticator, DigestCredentials, DigestError, DigestUser};

/// SIP request authenticator
pub trait ClientAuthenticator {
    type Error: Error + Debug;

    /// Modify a request's header to add the required authorization
    ///
    /// Implementations like Digest will do nothing here before receiving a rejection response
    fn authorize_request(&mut self, request: &mut Headers);

    /// Handle a rejection request
    ///
    /// Must return an error when no more requests should be sent
    fn handle_rejection(
        &mut self,
        rejected_request: RequestParts<'_>,
        reject_response: ResponseParts<'_>,
    ) -> Result<(), Self::Error>;
}

/// Information about the request that has to be authenticated
#[derive(Debug, Clone, Copy)]
pub struct RequestParts<'s> {
    pub line: &'s RequestLine,
    pub headers: &'s Headers,
    pub body: &'s [u8],
}

/// Information about the response that rejection the authentication
pub struct ResponseParts<'s> {
    pub line: &'s StatusLine,
    pub headers: &'s Headers,
    pub body: &'s [u8],
}
