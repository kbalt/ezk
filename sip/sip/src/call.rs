use crate::{MediaBackend, CONTENT_TYPE_SDP};
use bytes::Bytes;
use bytesstr::BytesStr;
use rtc::sdp::SessionDescription;
use sip_types::{header::typed::ContentType, StatusCode};
use sip_ua::invite::session::{
    InviteSession, InviteSessionEvent, ReInviteReceived, SessionRefreshError,
};
use std::fmt::Debug;
use tokio::select;

#[derive(Debug, thiserror::Error)]
pub enum CallError<M> {
    #[error(transparent)]
    Core(#[from] sip_core::Error),
    #[error(transparent)]
    RefreshFailed(#[from] SessionRefreshError),
    #[error(transparent)]
    Media(M),
}

pub struct Call<M: MediaBackend> {
    pub(crate) invite_session: InviteSession,
    pub(crate) media: M,
}

pub enum CallEvent<M: MediaBackend> {
    Media(M::Event),
    Terminated,
}

impl<M: MediaBackend> Call<M> {
    pub async fn run(&mut self) -> Result<CallEvent<M>, CallError<M::Error>> {
        loop {
            let e = select! {
                e = self.invite_session.drive() => e?,
                e = self.media.run() => {
                    return Ok(CallEvent::Media(e.map_err(CallError::Media)?));
                }
            };

            match e {
                InviteSessionEvent::RefreshNeeded(refresh_needed) => {
                    refresh_needed.process_default().await?;
                }
                InviteSessionEvent::ReInviteReceived(event) => {
                    let media = &mut self.media;

                    handle_reinvite(event, media).await?;
                }
                InviteSessionEvent::Bye(bye_event) => {
                    bye_event.process_default().await?;
                    return Ok(CallEvent::Terminated);
                }
                InviteSessionEvent::Terminated => return Ok(CallEvent::Terminated),
            }
        }
    }

    pub fn media(&mut self) -> &mut M {
        &mut self.media
    }

    pub async fn terminate(mut self) -> Result<(), sip_core::Error> {
        self.invite_session.terminate().await?;

        Ok(())
    }
}

async fn handle_reinvite<M: MediaBackend>(
    event: ReInviteReceived<'_>,
    media: &mut M,
) -> Result<(), CallError<M::Error>> {
    let ReInviteReceived {
        session, invite, ..
    } = &event;

    let invite_contains_sdp = invite
        .headers
        .get_named::<ContentType>()
        .map(|c| c == CONTENT_TYPE_SDP)
        .unwrap_or_default();

    if invite_contains_sdp {
        let Some(sdp_offer) = parse_sdp_body(invite.body.clone()) else {
            respond_failure(event, StatusCode::BAD_REQUEST).await?;
            return Ok(());
        };

        let sdp_answer = match media.receive_sdp_offer(sdp_offer).await {
            Ok(sdp_answer) => sdp_answer,
            Err(e) => {
                respond_failure(event, StatusCode::SERVER_INTERNAL_ERROR).await?;
                return Err(CallError::Media(e));
            }
        };

        let mut response = session
            .dialog
            .create_response(invite, StatusCode::OK, None)?;

        response.msg.headers.insert_named(&CONTENT_TYPE_SDP);
        response.msg.body = sdp_answer.to_string().into();

        event.respond_success(response).await?;
    } else {
        let sdp_offer = match media.create_sdp_offer().await {
            Ok(sdp_answer) => sdp_answer,
            Err(e) => {
                respond_failure(event, StatusCode::SERVER_INTERNAL_ERROR).await?;
                return Err(CallError::Media(e));
            }
        };

        let mut response = session
            .dialog
            .create_response(invite, StatusCode::OK, None)?;
        response.msg.headers.insert_named(&CONTENT_TYPE_SDP);
        response.msg.body = sdp_offer.to_string().into();

        let ack = event.respond_success(response).await?;

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

        media
            .receive_sdp_answer(sdp_answer)
            .await
            .map_err(CallError::Media)?;
    }

    Ok(())
}

async fn respond_failure(
    event: ReInviteReceived<'_>,
    code: StatusCode,
) -> Result<(), sip_core::Error> {
    let response = event
        .session
        .dialog
        .create_response(&event.invite, code, None)?;

    event.transaction.respond_failure(response).await
}

fn parse_sdp_body(body: Bytes) -> Option<SessionDescription> {
    SessionDescription::parse(&BytesStr::from_utf8_bytes(body).ok()?).ok()
}
