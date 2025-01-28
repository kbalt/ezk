use crate::{Call, MediaBackend, CONTENT_TYPE_SDP};
use bytesstr::BytesStr;
use rtc::sdp::{ParseSessionDescriptionError, SessionDescription};
use sip_core::{Endpoint, IncomingRequest};
use sip_types::{
    header::{
        typed::{Contact, ContentType},
        HeaderError,
    },
    StatusCode,
};
use sip_ua::{dialog::Dialog, invite::acceptor::InviteAcceptor};
use std::str::Utf8Error;

/// Marks an incoming call that has no media backend
pub struct NoMedia;

/// A incoming call that can be accepted or declined
pub struct IncomingCall<M> {
    acceptor: InviteAcceptor,
    sdp_offer: Option<SessionDescription>,
    media: M,
}

/// Error returned by [`IncomingCall::from_invite`]
#[derive(Debug, thiserror::Error)]
pub enum IncomingCallFromInviteError {
    #[error("INVITE body contains invalid UTF8")]
    InvalidUtf8Body(Utf8Error),
    #[error("Failed to parse SDP in INVITE body")]
    InvalidSDP(ParseSessionDescriptionError),
    #[error("Failed to create dialog from INVITE")]
    CreateDialog(#[source] HeaderError),
}

impl IncomingCall<NoMedia> {
    /// Create an [`IncomingCall`] from an INVITE request
    pub fn from_invite(
        endpoint: Endpoint,
        invite: IncomingRequest,
        contact: Contact,
    ) -> Result<Self, Box<(IncomingRequest, IncomingCallFromInviteError)>> {
        let sdp_offer = if invite
            .headers
            .get_named::<ContentType>()
            .is_ok_and(|content_type| content_type == CONTENT_TYPE_SDP)
        {
            let utf8_body = match BytesStr::from_utf8_bytes(invite.body.clone()) {
                Ok(utf8_body) => utf8_body,
                Err(e) => {
                    return Err(Box::new((
                        invite,
                        IncomingCallFromInviteError::InvalidUtf8Body(e),
                    )))
                }
            };

            let sdp_offer = match SessionDescription::parse(&utf8_body) {
                Ok(sdp_offer) => sdp_offer,
                Err(e) => {
                    return Err(Box::new((
                        invite,
                        IncomingCallFromInviteError::InvalidSDP(e),
                    )));
                }
            };

            Some(sdp_offer)
        } else {
            None
        };

        let dialog = match Dialog::new_server(endpoint.clone(), &invite, contact) {
            Ok(dialog) => dialog,
            Err(e) => {
                return Err(Box::new((
                    invite,
                    IncomingCallFromInviteError::CreateDialog(e),
                )))
            }
        };

        let acceptor = InviteAcceptor::new(dialog, invite);

        Ok(Self {
            acceptor,
            sdp_offer,
            media: NoMedia,
        })
    }

    /// Set the media backend to use for this incoming call
    pub fn with_media<M: MediaBackend>(self, media: M) -> IncomingCall<M> {
        IncomingCall {
            acceptor: self.acceptor,
            sdp_offer: self.sdp_offer,
            media,
        }
    }
}

impl<M> IncomingCall<M> {
    /// Returns if the initial invite contains an SDP offer
    pub fn has_sdp_offer(&self) -> bool {
        self.sdp_offer.is_some()
    }

    /// Returns when the call has been cancelled
    pub async fn cancelled(&mut self) {
        self.acceptor.cancelled().await
    }

    /// Decline the call with the given status code and reason
    pub async fn decline(
        self,
        code: StatusCode,
        reason: Option<BytesStr>,
    ) -> Result<(), sip_ua::invite::acceptor::Error> {
        let response = self.acceptor.create_response(code, reason).await?;
        self.acceptor.respond_failure(response).await?;
        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AcceptCallError<M> {
    #[error(transparent)]
    Core(#[from] sip_core::Error),
    #[error(transparent)]
    Media(M),
    #[error("Missing SDP in ACK")]
    MissingSdp,
    #[error("Failed to parse body as UTF-8, {0}")]
    InvalidUtf8Body(Utf8Error),
    #[error("Failed to parse body as SDP, {0}")]
    InvalidSdp(ParseSessionDescriptionError),
    #[error("Call was canceled by the peer")]
    Cancelled,
}

impl<M> From<sip_ua::invite::acceptor::Error> for AcceptCallError<M> {
    fn from(e: sip_ua::invite::acceptor::Error) -> Self {
        match e {
            sip_ua::invite::acceptor::Error::Core(e) => AcceptCallError::Core(e),
            sip_ua::invite::acceptor::Error::RequestTerminated => AcceptCallError::Cancelled,
        }
    }
}

impl<M: MediaBackend> IncomingCall<M> {
    /// Accept the call and negotiate the media session
    pub async fn accept(mut self) -> Result<Call<M>, AcceptCallError<M::Error>> {
        let mut response = self.acceptor.create_response(StatusCode::OK, None).await?;

        response.msg.headers.insert_named(&CONTENT_TYPE_SDP);

        let invite_session = if let Some(sdp_offer) = self.sdp_offer {
            let sdp_response = match self.media.receive_sdp_offer(sdp_offer).await {
                Ok(sdp_response) => sdp_response,
                Err(e) => {
                    Self::internal_error(self.acceptor).await?;
                    return Err(AcceptCallError::Media(e));
                }
            };

            response.msg.body = sdp_response.to_string().into();

            let (session, _ack) = self.acceptor.respond_success(response).await?;

            session
        } else {
            let sdp_offer = match self.media.create_sdp_offer().await {
                Ok(sdp_offer) => sdp_offer,
                Err(e) => {
                    Self::internal_error(self.acceptor).await?;
                    return Err(AcceptCallError::Media(e));
                }
            };

            response.msg.body = sdp_offer.to_string().into();

            let (mut session, ack) = self.acceptor.respond_success(response).await?;

            let ack_contains_sdp = ack
                .headers
                .get_named::<ContentType>()
                .is_ok_and(|content_type| content_type == CONTENT_TYPE_SDP);

            if !ack_contains_sdp {
                session.terminate().await?;
                return Err(AcceptCallError::MissingSdp);
            }

            let sdp_answer = BytesStr::from_utf8_bytes(ack.body.clone())
                .map_err(AcceptCallError::<M::Error>::InvalidUtf8Body)
                .and_then(|utf8_body| {
                    SessionDescription::parse(&utf8_body).map_err(AcceptCallError::InvalidSdp)
                });

            match sdp_answer {
                Ok(sdp_answer) => {
                    self.media
                        .receive_sdp_answer(sdp_answer)
                        .await
                        .map_err(AcceptCallError::Media)?;
                }
                Err(e) => {
                    let _ = session.terminate().await;
                    return Err(e);
                }
            }

            session
        };

        Ok(Call {
            invite_session,
            media: self.media,
        })
    }

    async fn internal_error(acceptor: InviteAcceptor) -> Result<(), AcceptCallError<M::Error>> {
        let response = acceptor
            .create_response(StatusCode::SERVER_INTERNAL_ERROR, None)
            .await?;
        acceptor.respond_failure(response).await?;
        Ok(())
    }
}
