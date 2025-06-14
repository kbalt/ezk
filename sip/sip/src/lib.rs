#![warn(unreachable_pub)]

use async_trait::async_trait;
use bytesstr::BytesStr;
use log::warn;
use sip_auth::{ClientAuthenticator, DigestAuthenticator, DigestCredentials, DigestError};
use sip_core::{Endpoint, IncomingRequest, Layer, MayTake};
use sip_types::{
    header::typed::{Contact, ContentType},
    uri::{NameAddr, SipUri},
    Method, StatusCode,
};

mod call;
mod client_builder;
mod incoming_call;
mod media;
mod outbound_call;
mod registration;

pub use call::{Call, CallError, CallEvent};
pub use client_builder::ClientBuilder;
pub use incoming_call::{IncomingCall, IncomingCallFromInviteError};
pub use media::{
    Codec, MediaBackend, MediaEvent, MediaSession, RtpReceiver, RtpSendError, RtpSender,
};
pub use outbound_call::{MakeCallError, OutboundCall, UnacknowledgedCall};
pub use registration::{RegisterError, RegistrarConfig, Registration};

const CONTENT_TYPE_SDP: ContentType = ContentType(BytesStr::from_static("application/sdp"));

slotmap::new_key_type! {
    struct AccountId;
}

#[derive(Default)]
struct ClientLayer {}

#[async_trait]
impl Layer for ClientLayer {
    fn name(&self) -> &'static str {
        "client"
    }

    async fn receive(&self, endpoint: &Endpoint, request: MayTake<'_, IncomingRequest>) {
        let invite = if request.line.method == Method::INVITE {
            request.take()
        } else {
            return;
        };

        let contact: SipUri = "sip:bob@example.com".parse().unwrap();
        let contact = Contact::new(NameAddr::uri(contact));

        let call = match IncomingCall::from_invite(endpoint.clone(), invite, contact) {
            Ok(call) => call,
            Err(err) => {
                let (mut invite, e) = *err;

                log::warn!("Failed to create incoming call from INVITE, {e}");

                let response = endpoint.create_response(&invite, StatusCode::BAD_REQUEST, None);

                if let Err(e) = endpoint
                    .create_server_inv_tsx(&mut invite)
                    .respond_failure(response)
                    .await
                {
                    log::warn!("Failed to respond with BAD_REQUEST to incoming INVITE, {e}");
                }

                return;
            }
        };

        call.decline(StatusCode::DECLINE, None).await.unwrap();
    }
}

/// High level SIP client, must be constructed using [`ClientBuilder`]
///
/// Can be cheaply cloned.
#[derive(Clone)]
pub struct Client {
    endpoint: Endpoint,
}

impl Client {
    /// Create a [`ClientBuilder`]
    pub fn builder() -> ClientBuilder {
        ClientBuilder::new()
    }

    pub async fn register<A: ClientAuthenticator + Send + 'static>(
        &self,
        config: RegistrarConfig,
        authenticator: A,
    ) -> Result<Registration, RegisterError<A::Error>> {
        Registration::register(self.endpoint.clone(), config, authenticator).await
    }

    pub async fn make_call<M: MediaBackend>(
        &self,
        id: NameAddr,
        contact: Contact,
        target: SipUri,
        media: M,
    ) -> Result<OutboundCall<M>, MakeCallError<M::Error, DigestError>> {
        OutboundCall::make(
            self.endpoint.clone(),
            DigestAuthenticator::new(DigestCredentials::new()),
            id,
            contact,
            target,
            media,
        )
        .await
    }
}
