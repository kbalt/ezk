use super::Inner;
use super::timer::SessionTimer;
use crate::dialog::{Dialog, UsageGuard};
use crate::invite::AwaitedAck;
use sip_core::transaction::{ServerInvTsx, ServerTsx, TsxResponse};
use sip_core::transport::OutgoingResponse;
use sip_core::{Endpoint, IncomingRequest, Result};
use sip_types::header::typed::Refresher;
use sip_types::{CodeKind, Method, StatusCode};
use std::sync::Arc;
use tokio::select;
use tokio::sync::mpsc::{self, Receiver};
use tokio::sync::oneshot;

#[derive(Debug, Clone, Copy)]
pub enum Role {
    Uac,
    Uas,
}

#[derive(Debug)]
pub struct InviteSession {
    pub endpoint: Endpoint,
    inner: Arc<Inner>,

    pub role: Role,

    /// Receiver side of dialog-usage events
    usage_events: Receiver<UsageEvent>,

    pub session_timer: SessionTimer,

    // drop usage before dialog
    _usage_guard: UsageGuard,
    pub dialog: Arc<Dialog>,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionRefreshError {
    #[error(transparent)]
    Core(#[from] sip_core::Error),
    #[error("Unexpected status code {0:?}")]
    UnexpectedStatus(StatusCode),
}

#[allow(clippy::large_enum_variant)] // TODO address this
pub enum InviteSessionEvent {
    RefreshNeeded,
    Notify(IncomingRequest),
    ReInviteReceived(ReInviteReceived),
    Bye(ByeEvent),
    Terminated,
}

pub struct ReInviteReceived {
    pub invite: IncomingRequest,
    pub transaction: ServerInvTsx,
}

pub struct ByeEvent {
    bye: IncomingRequest,
    transaction: ServerTsx,
}

impl InviteSession {
    pub(super) fn new(
        endpoint: Endpoint,
        inner: Arc<Inner>,
        role: Role,
        usage_events: mpsc::Receiver<UsageEvent>,
        session_timer: SessionTimer,
        usage_guard: UsageGuard,
        dialog: Dialog,
    ) -> Self {
        Self {
            endpoint,
            inner,
            role,
            usage_events,
            session_timer,
            _usage_guard: usage_guard,
            dialog: Arc::new(dialog),
        }
    }

    pub async fn run(&mut self) -> Result<InviteSessionEvent> {
        select! {
            _ = self.session_timer.wait() => {
               self.handle_session_timer().await
            }
            event = self.usage_events.recv() => {
                self.handle_usage_event(event).await
            }
        }
    }

    pub async fn terminate(&mut self) -> Result<TsxResponse, sip_core::Error> {
        let mut state = self.inner.state.lock().await;
        state.set_terminated();

        let request = self.dialog.create_request(Method::BYE);

        let mut target_tp_info = self.dialog.target_tp_info.lock().await;

        let mut transaction = self
            .endpoint
            .send_request(request, &mut target_tp_info)
            .await?;

        drop(target_tp_info);

        transaction.receive_final().await
    }

    async fn handle_usage_event(&mut self, evt: Option<UsageEvent>) -> Result<InviteSessionEvent> {
        let evt = if let Some(evt) = evt {
            evt
        } else {
            // Usage events channel has been dropped,
            // because the state was set to Terminated.
            return Ok(InviteSessionEvent::Terminated);
        };

        match evt {
            UsageEvent::Notify(mut incoming_request) => {
                // Always respond with 200 OK
                let transaction = self.endpoint.create_server_tsx(&mut incoming_request);
                let response =
                    self.dialog
                        .create_response(&incoming_request, StatusCode::OK, None)?;
                transaction.respond(response).await?;

                Ok(InviteSessionEvent::Notify(incoming_request))
            }
            UsageEvent::Bye(mut request) => {
                let transaction = self.endpoint.create_server_tsx(&mut request);

                Ok(InviteSessionEvent::Bye(ByeEvent {
                    bye: request,
                    transaction,
                }))
            }
            UsageEvent::ReInvite(mut invite) => {
                self.session_timer.reset();

                let transaction = self.endpoint.create_server_inv_tsx(&mut invite);

                Ok(InviteSessionEvent::ReInviteReceived(ReInviteReceived {
                    invite,
                    transaction,
                }))
            }
        }
    }

    async fn handle_session_timer(&mut self) -> Result<InviteSessionEvent> {
        match (self.role, self.session_timer.refresher) {
            (_, Refresher::Unspecified) => unreachable!(),
            (Role::Uac, Refresher::Uac) | (Role::Uas, Refresher::Uas) => {
                // We are responsible for the refresh
                // Timer expired meaning we are responsible for refresh now
                self.session_timer.reset();

                Ok(InviteSessionEvent::RefreshNeeded)
            }
            (Role::Uac, Refresher::Uas) | (Role::Uas, Refresher::Uac) => {
                // Peer is responsible for refresh
                // Timer expired meaning we didn't get a RE-INVITE
                self.terminate().await?;
                Ok(InviteSessionEvent::Terminated)
            }
        }
    }

    pub async fn refresh(&mut self) -> Result<(), SessionRefreshError> {
        self.session_timer.reset();

        let mut invite = self.dialog.create_request(Method::INVITE);
        self.session_timer.populate_refresh(&mut invite);

        let mut target_tp_info = self.dialog.target_tp_info.lock().await;

        let mut transaction = self
            .endpoint
            .send_invite(invite, &mut target_tp_info)
            .await?;

        drop(target_tp_info);

        let mut ack = None;

        while let Some(response) = transaction.receive().await? {
            match response.line.code.kind() {
                CodeKind::Provisional => { /* ignore */ }
                CodeKind::Success => {
                    let ack = if let Some(ack) = &mut ack {
                        ack
                    } else {
                        let ack_req =
                            super::create_ack(&self.dialog, response.base_headers.cseq.cseq)
                                .await?;

                        ack.insert(ack_req)
                    };

                    self.endpoint
                        .send_outgoing_request(ack)
                        .await
                        .map_err(sip_core::Error::from)?;
                }
                _ => return Err(SessionRefreshError::UnexpectedStatus(response.line.code)),
            }
        }

        Ok(())
    }

    pub async fn handle_bye(&mut self, event: ByeEvent) -> Result<()> {
        let response = self
            .dialog
            .create_response(&event.bye, StatusCode::OK, None)?;

        event.transaction.respond(response).await?;

        Ok(())
    }

    pub async fn handle_reinvite_success(
        &mut self,
        event: ReInviteReceived,
        response: OutgoingResponse,
    ) -> Result<IncomingRequest> {
        let (ack_sender, ack_recv) = oneshot::channel();

        *self.inner.awaited_ack.lock() = Some(AwaitedAck {
            cseq: event.invite.base_headers.cseq.cseq,
            ack_sender,
        });

        let accepted = event.transaction.respond_success(response).await?;

        super::receive_ack(accepted, ack_recv).await
    }
}

pub(super) enum UsageEvent {
    Notify(IncomingRequest),
    ReInvite(IncomingRequest),
    Bye(IncomingRequest),
}
