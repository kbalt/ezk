use crate::{call::Call, MediaBackend, CONTENT_TYPE_SDP};
use bytesstr::BytesStr;
use rtc::sdp::SessionDescription;
use sip_auth::ClientAuthenticator;
use sip_core::{transaction::TsxResponse, Endpoint, Request};
use sip_types::{
    header::typed::{Contact, ContentType},
    msg::StatusLine,
    uri::{NameAddr, SipUri},
    StatusCode,
};
use sip_ua::invite::{
    create_ack,
    initiator::{Early, EarlyResponse, InviteInitiator, Response},
    session::InviteSession,
};
use std::{future::poll_fn, mem::take, task::Poll};

/// Any errors that might be encountered while making the initial call's INVITE request
#[derive(Debug, thiserror::Error)]
pub enum MakeCallError<M, A> {
    #[error(transparent)]
    Core(#[from] sip_core::Error),
    #[error(transparent)]
    Auth(A),
    #[error(transparent)]
    Media(M),
    #[error("Got response with unexpected status {0:?}")]
    Failed(StatusLine),
}

/// Any errors that might be encountered while processing the call's INVITE responses
#[derive(Debug, thiserror::Error)]
pub enum MakeCallCompletionError<M> {
    #[error(transparent)]
    Core(#[from] sip_core::Error),
    #[error("Got response with unexpected status {0:?}")]
    Failed(StatusLine),
    #[error(transparent)]
    Media(M),
    #[error("Missing SDP in response")]
    MissingSdpInResponse,
}

/// In-progress outbound call which can still be canceled.
///
/// Forked calls will be canceled or terminated. First established session wins.
///
/// This type exists as an intermediate state so that calls can be canceled gracefully.
pub struct OutboundCall<M> {
    state: Option<OutboundCallState<M>>,
    unacknowledged: Option<UnacknowledgedCall<M>>,
}

struct OutboundCallState<M> {
    sent_sdp_offer: bool,
    media: M,

    initiator: InviteInitiator,
    earlies: Vec<(Early, Option<SessionDescription>)>,
}

impl<M: MediaBackend> OutboundCall<M> {
    /// Create an [`OutboundCall`], sending an INVITE request to the target uri
    ///
    /// Waits for any (non 100 Trying) response before returning
    pub async fn make<A: ClientAuthenticator>(
        endpoint: Endpoint,
        mut authenticator: A,
        id: NameAddr,
        contact: Contact,
        target: SipUri,
        mut media: M,
    ) -> Result<Self, MakeCallError<M::Error, A::Error>> {
        let mut initiator = InviteInitiator::new(endpoint.clone(), id, contact, target);

        // Only create a SDP offer if the sdp-session has media set by the user
        let sdp_offer = if media.has_media() {
            Some(
                media
                    .create_sdp_offer()
                    .await
                    .map_err(MakeCallError::Media)?,
            )
        } else {
            None
        };

        'authorize: loop {
            let mut invite = initiator.create_invite();

            if let Some(offer_sdp) = &sdp_offer {
                attach_sdp(&mut invite, offer_sdp);
            }

            authenticator.authorize_request(&mut invite.headers);

            initiator.send_invite(invite).await?;

            loop {
                match initiator.receive().await? {
                    Response::Provisional(..) => {
                        // TODO: return OutboundCall here already so the call can be cancelled?
                    }
                    Response::Failure(tsx_response) => {
                        // Authorize requests if possible
                        if tsx_response.line.code != StatusCode::UNAUTHORIZED {
                            return Err(MakeCallError::Failed(tsx_response.line));
                        }

                        let transaction = initiator
                            .transaction()
                            .expect("initiator isn't finished yet");
                        let invite = transaction.request();

                        authenticator
                            .handle_rejection(
                                sip_auth::RequestParts {
                                    line: &invite.msg.line,
                                    headers: &invite.msg.headers,
                                    body: &invite.msg.body,
                                },
                                sip_auth::ResponseParts {
                                    line: &tsx_response.line,
                                    headers: &tsx_response.headers,
                                    body: &tsx_response.body,
                                },
                            )
                            .map_err(MakeCallError::Auth)?;

                        continue 'authorize;
                    }
                    Response::Early(early, tsx_response, ..) => {
                        // Got an early dialog - probably ringing, return Outbound call
                        return Ok(OutboundCall {
                            state: Some(OutboundCallState {
                                sent_sdp_offer: sdp_offer.is_some(),
                                media,
                                initiator,
                                earlies: vec![(early, extract_sdp(&tsx_response))],
                            }),
                            unacknowledged: None,
                        });
                    }
                    Response::Session(session, tsx_response) => {
                        // First response created a session - great, return it
                        return Ok(OutboundCall {
                            state: None,
                            unacknowledged: Some(UnacknowledgedCall {
                                sent_sdp_offer: sdp_offer.is_some(),
                                media,
                                initiator,
                                earlies: vec![],
                                session,
                                final_response: tsx_response,
                                early_sdp: None,
                            }),
                        });
                    }
                    Response::EarlyEvent => {
                        // technically unreachable, so just ignoring it
                    }
                    Response::Finished => {
                        // this isn't technically a timeout but we treat it as one, since this should be unreachable
                        return Err(MakeCallError::Core(sip_core::Error::RequestTimedOut));
                    }
                }
            }
        }
    }

    /// Cancel the call gracefully.
    ///
    /// If the call is already set up, but has not received a provisional response,
    /// the existing session will be terminated with a BYE request.
    pub async fn cancel(mut self) -> Result<(), sip_core::Error> {
        if let Some(mut completed) = self.unacknowledged.take() {
            completed.session.terminate().await?;
            return Ok(());
        }

        if let Some(inner) = self.state.take() {
            inner.initiator.cancel().await?;
        };

        Ok(())
    }

    /// Wait for the final response from the peer
    ///
    /// The returned future is cancel-safe, and the call can be canceled as long as this function has not returned.
    pub async fn wait_for_completion(
        &mut self,
    ) -> Result<UnacknowledgedCall<M>, MakeCallCompletionError<M::Error>> {
        if let Some(completed) = self.unacknowledged.take() {
            return Ok(completed);
        }

        let this = self
            .state
            .as_mut()
            .expect("OutboundCall::wait_for_completion must not be called again after returning");

        loop {
            match this.initiator.receive().await? {
                Response::Provisional(..) => {
                    // ignore provisional responses outside the dialog
                }
                Response::Failure(tsx_response) => {
                    return Err(MakeCallCompletionError::Failed(tsx_response.line));
                }
                Response::Early(early, tsx_response, ..) => {
                    // got an early dialog, store it and poll it concurrently with the invite transaction
                    this.earlies.push((early, extract_sdp(&tsx_response)))
                }
                Response::Session(session, tsx_response) => {
                    let early_sdp = extract_sdp(&tsx_response);

                    let this = take(&mut self.state).unwrap();

                    return Ok(UnacknowledgedCall {
                        sent_sdp_offer: this.sent_sdp_offer,
                        media: this.media,
                        initiator: this.initiator,
                        earlies: this.earlies,
                        session,
                        final_response: tsx_response,
                        early_sdp,
                    });
                }
                Response::EarlyEvent => {
                    // We received an internal message that was forwarded to an early handle
                }
                Response::Finished => {
                    unreachable!("function returns on all call termination events")
                }
            }

            // Poll all early calls,
            let early_event = poll_fn(|cx| -> Poll<Result<_, MakeCallCompletionError<M::Error>>> {
                for (i, (early, _)) in this.earlies.iter_mut().enumerate() {
                    let response = match early.poll_receive(cx) {
                        Poll::Ready(response) => response?,
                        Poll::Pending => continue,
                    };

                    return Poll::Ready(Ok(Some((i, response))));
                }

                Poll::Ready(Ok(None))
            })
            .await?;

            // We got an early event
            let Some((i, response)) = early_event else {
                continue;
            };

            match response {
                EarlyResponse::Provisional(..) => {
                    // ignore additional provisional responses for early dialogs
                }
                EarlyResponse::Success(session, tsx_response) => {
                    // got a success response for an early dialog, establish the call with it and cancel everything else
                    let mut this = take(&mut self.state).unwrap();

                    let (_, early_sdp) = this.earlies.remove(i);

                    return Ok(UnacknowledgedCall {
                        sent_sdp_offer: this.sent_sdp_offer,
                        media: this.media,
                        initiator: this.initiator,
                        earlies: this.earlies,
                        session,
                        final_response: tsx_response,
                        early_sdp,
                    });
                }
                EarlyResponse::Terminated => {
                    unreachable!("function returns on all call termination events");
                }
            }
        }
    }
}

/// A call that has received its final response and must still be acknowledged using an ACK request.
///
/// This type is an API oddity existing between [`OutboundCall`] and [`Call`] so that
/// [`OutboundCall::wait_for_completion`] can be cancel-safe (which returns this).
///
/// All functions by this are **not** cancel-safe.
pub struct UnacknowledgedCall<M> {
    sent_sdp_offer: bool,
    media: M,
    initiator: InviteInitiator,
    earlies: Vec<(Early, Option<SessionDescription>)>,
    session: InviteSession,
    final_response: TsxResponse,
    early_sdp: Option<SessionDescription>,
}

impl<M: MediaBackend> UnacknowledgedCall<M> {
    /// Terminate the completed call
    pub async fn terminate(mut self) -> Result<(), sip_core::Error> {
        self.session.terminate().await?;
        Ok(())
    }

    /// Complete the call setup & SDP handshake
    ///
    /// Cancels all pending early dialogs
    pub async fn finish(mut self) -> Result<Call<M>, MakeCallCompletionError<M::Error>> {
        for (early, _) in self.earlies {
            tokio::spawn(early.cancel());
        }

        let remote_sdp = self.early_sdp.or_else(|| extract_sdp(&self.final_response));

        let remote_sdp = if let Some(remote_sdp) = remote_sdp {
            remote_sdp
        } else {
            self.session.terminate().await?;
            return Err(MakeCallCompletionError::MissingSdpInResponse);
        };

        let mut pending_ack = create_ack(
            &self.session.dialog,
            self.final_response.base_headers.cseq.cseq,
        )
        .await?;

        if self.sent_sdp_offer {
            self.media
                .receive_sdp_answer(remote_sdp)
                .await
                .map_err(MakeCallCompletionError::Media)?;
        } else {
            let sdp_answer = self
                .media
                .receive_sdp_offer(remote_sdp)
                .await
                .map_err(MakeCallCompletionError::Media)?;

            attach_sdp(&mut pending_ack.msg, &sdp_answer);
        }

        self.session
            .endpoint
            .send_outgoing_request(&mut pending_ack)
            .await
            .map_err(sip_core::Error::Io)?;

        self.initiator.set_acknowledge(&self.session, pending_ack);

        tokio::spawn(async move {
            while let Ok(event) = self.initiator.receive().await {
                match event {
                    Response::Provisional(..) => {}
                    Response::Failure(..) => break,
                    Response::Early(early, ..) => {
                        tokio::spawn(early.cancel());
                    }
                    Response::Session(mut session, ..) => {
                        let _ = session.terminate().await;
                    }
                    Response::EarlyEvent => {}
                    Response::Finished => break,
                }
            }
        });

        Ok(Call {
            invite_session: self.session,
            media: self.media,
        })
    }
}

fn attach_sdp(request: &mut Request, sdp: &SessionDescription) {
    request
        .headers
        .insert_named(&ContentType(BytesStr::from_static("application/sdp")));

    request.body = sdp.to_string().into();
}

fn extract_sdp(tsx_response: &TsxResponse) -> Option<SessionDescription> {
    if tsx_response
        .headers
        .get_named::<ContentType>()
        .is_ok_and(|content_type| content_type == CONTENT_TYPE_SDP)
    {
        let sdp = BytesStr::from_utf8_bytes(tsx_response.body.clone()).ok()?;
        return SessionDescription::parse(&sdp).ok();
    }

    None
}
