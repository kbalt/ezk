use crate::invite::session::{
    InviteSession, InviteSessionEvent, ReInviteReceived, SessionRefreshError,
};
use crate::{MediaBackend, media_backend::CONTENT_TYPE_SDP};
use bytes::Bytes;
use bytesstr::BytesStr;
use sdp_types::SessionDescription;
use sip_types::{StatusCode, header::typed::ContentType};
use std::collections::VecDeque;
use std::fmt::Debug;
use std::pin::pin;
use tokio::select;

/// Error returned by [`Call::run`]
#[derive(Debug, thiserror::Error)]
pub enum CallError<M> {
    #[error(transparent)]
    Core(#[from] sip_core::Error),
    #[error("Failed to refresh the INVITE session")]
    RefreshFailed(#[from] SessionRefreshError),
    #[error(transparent)]
    Media(M),
}

/// An established Call with a successfully negotiated SDP media session
///
/// Can only be created using [`OutboundCall`](crate::OutboundCall) or [`InboundCall`](crate::InboundCall).
pub struct Call<M: MediaBackend> {
    invite_session: Option<InviteSession>,
    media: M,

    backlog: VecDeque<CallEvent<M>>,

    terminated: bool,
}

/// Event returned by [`Call::run`]
pub enum CallEvent<M: MediaBackend> {
    /// Internal call event, must be passed back into the call. This odd API allows [`Call::run`] to be cancel-safe.
    Internal(InternalCallEvent),
    /// Media backend specific evet
    Media(M::Event),
    /// Call has been terminated by the peer
    Terminated,
}

/// Internal event, must be passed to [`Call::handle_internal_event`]
pub struct InternalCallEvent {
    event: Box<InviteSessionEvent>,
}

impl<M: MediaBackend> Call<M> {
    pub(crate) fn new(invite_session: InviteSession, media: M) -> Self {
        Self {
            invite_session: Some(invite_session),
            media,
            backlog: VecDeque::new(),
            terminated: false,
        }
    }

    /// Run the SIP & media event loop
    ///
    /// Periodically returns an event.
    ///
    /// > Be aware that any time spent outside this function will be time not spent on potentially handling real time
    /// > media data if the [`MediaBackend`] isn't running on a separate task.
    ///
    /// This functions cancel safe. To accomplish this, it sometimes returns an [`CallEvent::Internal`] which must be passed to
    /// [`Call::handle_internal_event`] which is not cancel safe.
    pub async fn run(&mut self) -> Result<CallEvent<M>, CallError<M::Error>> {
        if let Some(event) = self.backlog.pop_front() {
            return Ok(event);
        }

        let Some(invite_session) = &mut self.invite_session else {
            return Ok(CallEvent::Terminated);
        };

        let event = select! {
            invite_session_event = invite_session.run() => {
                CallEvent::Internal(InternalCallEvent { event: Box::new(invite_session_event?) })
            },
            media_event = self.media.run() => {
                CallEvent::Media(media_event.map_err(CallError::Media)?)
            }
        };

        Ok(event)
    }

    /// Handle an [`CallEvent::Internal`]
    ///
    /// This function is not cancel safe.
    pub async fn handle_internal_event(
        &mut self,
        event: InternalCallEvent,
    ) -> Result<(), CallError<M::Error>> {
        let invite_session = self.invite_session.as_mut().unwrap();

        match *event.event {
            InviteSessionEvent::RefreshNeeded => {
                let refresh = pin!(invite_session.refresh());

                run_media_and_future(&mut self.backlog, &mut self.media, refresh).await?;
            }
            InviteSessionEvent::ReInviteReceived(event) => {
                self.handle_reinvite(event).await?;
            }
            InviteSessionEvent::Bye(event) => {
                invite_session.handle_bye(event).await?;

                self.backlog.push_back(CallEvent::Terminated);
            }
            InviteSessionEvent::Terminated => {
                self.backlog.push_back(CallEvent::Terminated);
            }
        }

        Ok(())
    }

    async fn handle_reinvite(
        &mut self,
        event: ReInviteReceived,
    ) -> Result<(), CallError<M::Error>> {
        let invite_session = self.invite_session.as_mut().unwrap();

        let ReInviteReceived { invite, .. } = &event;

        let invite_contains_sdp = invite
            .headers
            .get_named::<ContentType>()
            .map(|c| c == CONTENT_TYPE_SDP)
            .unwrap_or_default();

        if invite_contains_sdp {
            let Some(sdp_offer) = parse_sdp_body(invite.body.clone()) else {
                respond_failure(invite_session, event, StatusCode::BAD_REQUEST).await?;
                return Ok(());
            };

            let sdp_answer = match self.media.receive_sdp_offer(sdp_offer).await {
                Ok(sdp_answer) => sdp_answer,
                Err(e) => {
                    respond_failure(invite_session, event, StatusCode::SERVER_INTERNAL_ERROR)
                        .await?;
                    return Err(CallError::Media(e));
                }
            };

            let mut response =
                invite_session
                    .dialog
                    .create_response(invite, StatusCode::OK, None)?;

            response.msg.headers.insert_named(&CONTENT_TYPE_SDP);
            response.msg.body = sdp_answer.to_string().into();

            let respond_success = pin!(invite_session.handle_reinvite_success(event, response));

            run_media_and_future(&mut self.backlog, &mut self.media, respond_success).await?;
        } else {
            let sdp_offer = match self.media.create_sdp_offer().await {
                Ok(sdp_answer) => sdp_answer,
                Err(e) => {
                    respond_failure(invite_session, event, StatusCode::SERVER_INTERNAL_ERROR)
                        .await?;
                    return Err(CallError::Media(e));
                }
            };

            let mut response =
                invite_session
                    .dialog
                    .create_response(invite, StatusCode::OK, None)?;
            response.msg.headers.insert_named(&CONTENT_TYPE_SDP);
            response.msg.body = sdp_offer.to_string().into();

            let respond_success = pin!(invite_session.handle_reinvite_success(event, response));

            let ack =
                run_media_and_future(&mut self.backlog, &mut self.media, respond_success).await?;

            let ack_contains_sdp = ack
                .headers
                .get_named::<ContentType>()
                .map(|c| c == CONTENT_TYPE_SDP)
                .unwrap_or_default();

            if !ack_contains_sdp {
                // oh well, no sdp exchange i guess
                return Ok(());
            }

            let Some(sdp_answer) = parse_sdp_body(ack.body) else {
                // TODO: should probably terminate the call here?
                log::warn!("Failed to parse SDP body in ACK");
                return Ok(());
            };

            self.media
                .receive_sdp_answer(sdp_answer)
                .await
                .map_err(CallError::Media)?;
        }

        Ok(())
    }

    /// Returns access to the inner media backend
    pub fn media(&mut self) -> &mut M {
        &mut self.media
    }

    /// Terminate the call
    pub async fn terminate(mut self) -> Result<(), sip_core::Error> {
        self.invite_session.as_mut().unwrap().terminate().await?;
        self.terminated = true;
        Ok(())
    }
}

impl<M: MediaBackend> Drop for Call<M> {
    fn drop(&mut self) {
        if self.terminated {
            return;
        }

        let Some(mut invite_session) = self.invite_session.take() else {
            return;
        };

        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };

        handle.spawn(async move {
            if let Err(e) = invite_session.terminate().await {
                log::warn!("Failed to terminate call {e:?}");
            }
        });
    }
}

async fn respond_failure(
    invite_session: &mut InviteSession,
    event: ReInviteReceived,
    code: StatusCode,
) -> Result<(), sip_core::Error> {
    let response = invite_session
        .dialog
        .create_response(&event.invite, code, None)?;

    event.transaction.respond_failure(response).await
}

fn parse_sdp_body(body: Bytes) -> Option<SessionDescription> {
    SessionDescription::parse(&BytesStr::from_utf8_bytes(body).ok()?).ok()
}

// utility to keep running the media backend while resolving some other future
//
// primarily used for the SIP session refresh, which can sometimes take some time
async fn run_media_and_future<M, F, T, E>(
    backlog: &mut VecDeque<CallEvent<M>>,
    media: &mut M,
    mut future: F,
) -> Result<T, CallError<M::Error>>
where
    M: MediaBackend,
    F: Future<Output = Result<T, E>> + Unpin,
    CallError<M::Error>: From<E>,
{
    loop {
        select! {
            result = &mut future => return Ok(result?),
            media_event = media.run() => {
                backlog.push_back(CallEvent::Media(media_event.map_err(CallError::Media)?));
            }
        }
    }
}
