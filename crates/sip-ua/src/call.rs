use crate::account::{AccountId, AccountSharedState};
use crate::auth::SharedAuthentication;
use crate::internal::dialog::DialogLayer;
use crate::internal::invite::initiator::{Initiator, Response};
use crate::internal::invite::session::Session;
use crate::internal::invite::InviteLayer;
use crate::UserAgent;
use sdp_types::msg::Message as SdpMessage;
use sip_auth::{CredentialStore, RequestParts, UacAuthSession};
use sip_core::{Endpoint, LayerKey};
use sip_types::header::typed::Contact;
use sip_types::uri::Uri;
use sip_types::{Code, Name};
use std::sync::Arc;
use tokio::sync::Mutex;

slotmap::new_key_type! {
    pub struct CallId;
}

#[derive(Default)]
pub struct SdpSession {
    pub local_sdp: Option<SdpMessage>,
    pub remote_sdp: Option<SdpMessage>,
}

#[async_trait::async_trait]
pub trait CallCallbacks: Send + Sync + 'static {
    async fn call_state_changed(&mut self, _previous: &CallState, _new: &CallState) {}

    async fn create_offer(&mut self) -> Option<SdpMessage> {
        None
    }
    async fn create_answer(&mut self, offer: SdpMessage) -> Option<SdpMessage> {
        None
    }

    async fn receive_answer(&mut self, answer: SdpMessage) {}
}

struct DefaultCallCallbacks;
impl CallCallbacks for DefaultCallCallbacks {}

enum Command {}

pub(crate) struct UaLayerCallData {
    task_cmd_sender: flume::Sender<Command>,
}

pub enum CallState {
    Null,
    Ringing,
    Established,
    Disconnected,
}

pub struct Call {
    state: CallState,

    session: Session,
}

enum CallCommand {}

struct OutgoingCallTask<CB> {
    callbacks: CB,
    acc_shared: Arc<Mutex<AccountSharedState>>,
    auth: Arc<SharedAuthentication>,

    state: CallState,
    options: MakeCallOptions,

    command_recv: flume::Receiver<Command>,

    initiator: Initiator,
    auth_session: UacAuthSession,
    sdp_session: SdpSession,
}

impl<CB> OutgoingCallTask<CB>
where
    CB: CallCallbacks,
{
    #[allow(clippy::too_many_arguments)]
    async fn create(
        endpoint: Endpoint,
        dialog_layer: LayerKey<DialogLayer>,
        invite_layer: LayerKey<InviteLayer>,
        acc_shared: Arc<Mutex<AccountSharedState>>,
        auth: Arc<SharedAuthentication>,
        callbacks: CB,
        command_recv: flume::Receiver<Command>,
        target: Box<dyn Uri>,
        options: MakeCallOptions,
        result_send: flume::Sender<Result<(), MakeCallError>>,
    ) {
        let acc_shared_ = acc_shared.lock().await;

        let id = acc_shared_.public_id();

        let initiator = Initiator::new(
            endpoint,
            dialog_layer,
            invite_layer,
            id.clone(),
            Contact::new(id),
            target,
        );

        drop(acc_shared_);

        let mut auth_session: UacAuthSession = Default::default();
        auth_session.get_authenticator().enforce_qop = auth.enforce_qop;
        auth_session.get_authenticator().reject_md5 = auth.reject_md5;

        Self {
            callbacks,
            acc_shared,
            auth,
            state: CallState::Null,
            options,
            command_recv,
            initiator,
            auth_session,
            sdp_session: SdpSession::default(),
        }
        .run(result_send)
        .await
    }

    async fn run(mut self, result_send: flume::Sender<Result<(), MakeCallError>>) {
        if let Err(e) = self.send_initial_invite().await {
            result_send.try_send(Err(e)).expect("dropped result_recv");
            return;
        }

        loop {
            let response = match self.initiator.receive().await {
                Ok(response) => response,
                Err(e) => {
                    result_send
                        .try_send(Err(MakeCallError::Core(e)))
                        .expect("dropped result_recv");
                    return;
                }
            };

            match response {
                Response::Provisional(response) => {}
                Response::Failure(response) => {
                    if matches!(response.line.code.into_u16(), 401 | 407) {
                        let request = self.initiator.transaction().unwrap().request();

                        let result = self.auth_session.handle_authenticate(
                            &response.headers,
                            &self.auth.credentials.read(),
                            RequestParts {
                                line: &request.msg.line,
                                headers: &request.msg.headers,
                                body: &request.msg.body,
                            },
                        );

                        if let Err(e) = self.auth.try_query_credentials(result).await {
                            result_send
                                .try_send(Err(MakeCallError::Auth(e)))
                                .expect("dropped result_recv");
                        } else if let Err(e) = self.send_initial_invite().await {
                            result_send.try_send(Err(e)).expect("dropped result_recv");
                            return;
                        }
                    } else {
                        result_send
                            .try_send(Err(MakeCallError::Failed(response.line.code)))
                            .expect("dropped result_recv");
                    }
                }
                Response::Early(_, _, _) => todo!(),
                Response::Session(_, _) => todo!(),
                Response::Finished => return,
            }
        }
    }

    async fn send_initial_invite(&mut self) -> Result<(), MakeCallError> {
        let mut request = self.initiator.create_invite();
        self.auth_session.authorize_request(&mut request.headers);

        if let Some(local_sdp) = self.callbacks.create_offer().await {
            request.body = local_sdp.to_string().into();
            request
                .headers
                .insert(Name::CONTENT_TYPE, "application/sdp");

            self.sdp_session.local_sdp = Some(local_sdp);
        }

        self.initiator.send_invite(request).await?;

        Ok(())
    }
}

#[derive(Default)]
pub struct MakeCallOptions {
    _priv: (),
}

#[derive(Debug, thiserror::Error)]
pub enum MakeCallError {
    #[error("invalid account id")]
    InvalidAccountId,
    #[error("INVITE failed with response code {0:?}")]
    Failed(Code),
    #[error(transparent)]
    Core(#[from] sip_core::Error),
    #[error(transparent)]
    Auth(#[from] sip_auth::Error),
}

impl UserAgent {
    pub async fn make_call<U>(
        &self,
        account_id: AccountId,
        target: U,
        options: MakeCallOptions,
    ) -> Result<CallId, MakeCallError>
    where
        U: Into<Box<dyn Uri>>,
    {
        let (call_id, result_recv) =
            self.do_make_call(account_id, target.into(), options, DefaultCallCallbacks)?;
        result_recv.recv_async().await.unwrap().map(|_| call_id)
    }

    fn do_make_call<CB>(
        &self,
        account_id: AccountId,
        target: Box<dyn Uri>,
        options: MakeCallOptions,
        callbacks: CB,
    ) -> Result<(CallId, flume::Receiver<Result<(), MakeCallError>>), MakeCallError>
    where
        CB: CallCallbacks,
    {
        let ua_layer = &self.endpoint[self.ua_layer];
        let accounts = ua_layer.accounts.lock();
        let acc_data = accounts
            .get(account_id)
            .ok_or(MakeCallError::InvalidAccountId)?;
        let acc_shared = acc_data.shared.clone();

        let (task_cmd_sender, command_recv) = flume::bounded(4);
        let call_id = ua_layer
            .calls
            .lock()
            .insert(UaLayerCallData { task_cmd_sender });

        let (result_send, result_recv) = flume::bounded(1);

        self.runtime.spawn(OutgoingCallTask::create(
            self.endpoint.clone(),
            self.dialog_layer,
            self.invite_layer,
            acc_shared,
            acc_data.auth.clone(),
            callbacks,
            command_recv,
            target,
            options,
            result_send,
        ));

        Ok((call_id, result_recv))
    }
}
