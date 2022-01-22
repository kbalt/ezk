//! All account and registration related types

use crate::internal::register::Registration;
use crate::UserAgent;
use flume::bounded;
use sip_auth::digest::DigestCredentials;
use sip_auth::{CredentialStore, RequestParts, UacAuthSession};
use sip_core::transaction::TsxResponse;
use sip_core::transport::TargetTransportInfo;
use sip_core::Endpoint;
use sip_types::header::typed::Contact;
use sip_types::uri::sip::SipUri;
use sip_types::uri::{NameAddr, Uri};
use sip_types::{Code, CodeKind};
use std::mem::replace;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

slotmap::new_key_type! {
    pub struct AccountId;
}

/// Configuration for a SIP account which can be registered on some registrar
pub struct AccountConfig {
    username: String,
    registrar: Box<dyn Uri>,

    /// Credentials related to this account
    ///
    /// Used to authenticate all requests related to this account.
    ///
    /// If empty or containing invalid credentials when trying to register this account
    /// the callback API will be probed ([`AccountRegistrationCallbacks`]).
    pub credentials: CredentialStore,

    /// Optional display name for this account
    pub display_name: Option<String>,

    /// Time between REGISTER requests
    ///
    /// Default: 300s
    pub registration_delta: Duration,

    /// Set a custom public socket address to use for this account
    ///
    /// If not set the address of the transport used to send the
    /// REGISTER request will be used in the SIP message.
    /// Since transports usually are bound to `0.0.0.0:5060` that address
    /// will not be useful as well but at least not wrong.
    /// SIP responses will contain hints what the correct address is, which will then be used.
    ///
    /// Note, that if this `pub_addr` is set that that address is locked in and
    /// will not be overwritten by the application.
    pub pub_addr: Option<SocketAddr>,

    /// Enforce quality of protection for authentications related to this account
    ///
    /// Enabling the option all Digest challenges will be treated as if they sent qop="auth"
    ///
    /// Disabled by default for backwards compatibility but recommended if compatible
    pub enforce_qop: bool,
}

impl AccountConfig {
    /// Create a new account config with its minimum of required configuration
    pub fn new(username: String, registrar: impl Into<Box<dyn Uri>>) -> Self {
        Self {
            username,
            registrar: registrar.into(),
            credentials: CredentialStore::new(),
            registration_delta: Duration::from_secs(300),
            display_name: None,
            pub_addr: None,
            enforce_qop: false,
        }
    }
}

/// State of a registration
pub enum RegistrationState {
    /// Initial state, nothing happened so far
    Null,
    /// Registration was successful
    Registered,
    /// A fatal error occurred resulting in the registration task to be stopped
    Error(RegistrationError),
}

#[derive(Debug, thiserror::Error)]
pub enum RegistrationError {
    #[error(transparent)]
    Core(#[from] sip_core::Error),
    #[error(transparent)]
    Auth(#[from] sip_auth::Error),
    #[error("failed with status code {0:?}")]
    Failed(Code),
}

/// Trait containing callbacks called by a running registration of an account
#[async_trait::async_trait]
pub trait AccountRegistrationCallbacks: Send + Sync + 'static {
    /// Notifies of any state changes of the registration
    async fn registration_state_changed(
        &mut self,
        _previous: &RegistrationState,
        _new: &RegistrationState,
    ) {
    }

    /// Prompts for credentials when registration failed because of missing or invalid credentials
    ///
    /// Can be used for prompting a user.
    ///
    /// Should avoid returning the same values for a realm as that will only result in this function being called again.
    /// Use the [`CredentialStore`] in the [`AccountConfig`] instead, to store/prepare credentials.
    async fn query_credentials(&mut self, _realm: &str) -> Option<DigestCredentials> {
        None
    }
}

struct DefaultAccountRegistrationCallbacks;
impl AccountRegistrationCallbacks for DefaultAccountRegistrationCallbacks {}

enum Command {
    Stop(flume::Sender<Result<(), RegistrationError>>),
}

pub(crate) struct AccountState {
    shared_state: Arc<Mutex<AccountSharedState>>,
    reg_task_cmd_sender: Option<flume::Sender<Command>>,
}

impl AccountState {
    pub(crate) fn new(config: AccountConfig) -> Self {
        Self {
            shared_state: Arc::new(Mutex::new(AccountSharedState {
                pub_addr: config.pub_addr,
                pub_addr_locked: config.pub_addr.is_some(),
                config,
            })),
            reg_task_cmd_sender: None,
        }
    }
}

struct AccountSharedState {
    config: AccountConfig,
    pub_addr: Option<SocketAddr>,
    pub_addr_locked: bool,
}

impl AccountSharedState {
    pub(crate) fn public_id(&self) -> NameAddr {
        let uri = SipUri::new(self.pub_addr.expect("pub_addr must be set").into())
            .user(self.config.username.clone().into());

        if let Some(display_name) = &self.config.display_name {
            NameAddr::new(display_name.as_str(), uri)
        } else {
            NameAddr::uri(uri)
        }
    }
}

struct AccountRegistrationTask<CB> {
    endpoint: Endpoint,
    callbacks: CB,
    shared_state: Arc<Mutex<AccountSharedState>>,

    state: RegistrationState,
    task_state: RegistrationTaskState,

    command_recv: flume::Receiver<Command>,

    credentials: CredentialStore,
    auth_session: UacAuthSession,
    registration: Registration,

    target_transport_info: TargetTransportInfo,
}

#[derive(Debug)]
enum RegistrationTaskState {
    Waiting,
    ReBindNeeded,
    ReBindWithNewIdNeeded { new_id: NameAddr },
    Stopping(Option<flume::Sender<Result<(), RegistrationError>>>),
}

impl<CB> AccountRegistrationTask<CB>
where
    CB: AccountRegistrationCallbacks,
{
    async fn create(
        endpoint: Endpoint,
        shared_state: Arc<Mutex<AccountSharedState>>,
        callbacks: CB,
        command_recv: flume::Receiver<Command>,
        result_send: flume::Sender<Result<(), RegistrationError>>,
    ) {
        let mut state = shared_state.lock().await;

        let mut target_transport_info = TargetTransportInfo::default();

        if state.pub_addr.is_none() {
            match endpoint.select_transport(&*state.config.registrar).await {
                Ok((transport, destination)) => {
                    state.pub_addr = Some(transport.bound());

                    target_transport_info.destination = destination;
                    target_transport_info.transport = Some(transport);
                }
                Err(e) => {
                    log::error!("failed to select transport for registration task, {}", e);
                    result_send
                        .try_send(Err(RegistrationError::Core(e)))
                        .unwrap();
                    return;
                }
            };
        };

        let credentials = state.config.credentials.clone();
        let registration = Registration::new(
            state.public_id(),
            state.config.registrar.clone(),
            state.config.registration_delta,
        );

        let mut auth_session: UacAuthSession = Default::default();
        auth_session.get_authenticator().enforce_qop = state.config.enforce_qop;

        drop(state);

        Self {
            endpoint,
            callbacks,
            shared_state,
            state: RegistrationState::Null,
            task_state: RegistrationTaskState::Waiting,
            command_recv,
            credentials,
            auth_session,
            registration,
            target_transport_info,
        }
        .run(result_send)
        .await
    }

    async fn run(mut self, result_send: flume::Sender<Result<(), RegistrationError>>) {
        let response = match self.send_register(false).await {
            Ok(response) => response,
            Err(e) => {
                result_send
                    .try_send(Err(e))
                    .expect("result receiver dropped");
                return;
            }
        };

        match response.line.code.into_u16() {
            200..=299 => {
                self.registration.receive_success_response(response);
                self.callbacks
                    .registration_state_changed(
                        &RegistrationState::Null,
                        &RegistrationState::Registered,
                    )
                    .await;

                self.state = RegistrationState::Registered;

                if result_send.try_send(Ok(())).is_err() {
                    self.task_state = RegistrationTaskState::Stopping(None);
                }
            }
            _ => {
                result_send
                    .try_send(Err(RegistrationError::Failed(response.line.code)))
                    .expect("result receiver dropped");
            }
        }

        loop {
            match replace(&mut self.task_state, RegistrationTaskState::Waiting) {
                RegistrationTaskState::Waiting => {
                    tokio::select! {
                        _ = self.registration.wait_for_expiry() => {
                            self.task_state = RegistrationTaskState::ReBindNeeded;
                        },
                        cmd = self.command_recv.recv_async() => {
                            self.handle_cmd(cmd).await;
                        }
                    };
                }
                RegistrationTaskState::ReBindNeeded => {
                    let response = match self.send_register(false).await {
                        Ok(response) => response,
                        Err(e) => {
                            self.on_error(e).await;
                            return;
                        }
                    };

                    match response.line.code.into_u16() {
                        200..=299 => {
                            self.registration.receive_success_response(response);
                        }
                        _ => {
                            self.on_error(RegistrationError::Failed(response.line.code))
                                .await;
                            return;
                        }
                    }
                }
                RegistrationTaskState::ReBindWithNewIdNeeded { new_id } => {
                    // Remove old binding
                    let response = match self.send_register(true).await {
                        Ok(response) => response,
                        Err(e) => {
                            self.on_error(e).await;
                            return;
                        }
                    };

                    if !matches!(response.line.code.kind(), CodeKind::Success) {
                        self.on_error(RegistrationError::Failed(response.line.code))
                            .await;
                        return;
                    }

                    // Set new contact
                    self.registration.set_contact(Contact {
                        uri: new_id,
                        params: Default::default(),
                    });

                    // Create new binding with new contact
                    self.task_state = RegistrationTaskState::ReBindNeeded;
                }
                RegistrationTaskState::Stopping(Some(tx)) => {
                    tx.try_send(self.send_register(true).await.map(|_| ()))
                        .expect("result receiver dropped");

                    return;
                }
                RegistrationTaskState::Stopping(None) => {
                    if let Err(e) = self.send_register(true).await {
                        log::error!("failed to silently unregister {:?}", e)
                    }

                    return;
                }
            }
        }
    }

    async fn send_register(
        &mut self,
        remove_binding: bool,
    ) -> Result<TsxResponse, RegistrationError> {
        // try up to 12 times then give up on authorizing
        // something funky has to be happening at this point
        for _ in 0..12 {
            let mut request = self.registration.create_register(remove_binding);
            self.auth_session.authorize_request(&mut request.headers);

            let mut transaction = self
                .endpoint
                .send_request(request, &mut self.target_transport_info)
                .await?;

            let response = transaction.receive_final().await?;

            if !remove_binding {
                self.update_received_rport(&response).await;
            }

            if matches!(
                response.line.code,
                Code::UNAUTHORIZED | Code::PROXY_AUTHENTICATION_REQUIRED
            ) {
                let request = transaction.request();

                let res = self.auth_session.handle_authenticate(
                    &response.headers,
                    &self.credentials,
                    RequestParts {
                        line: &request.msg.line,
                        headers: &request.msg.headers,
                        body: &[],
                    },
                );

                match res {
                    Ok(..) => { /* ok */ }
                    Err(sip_auth::Error::FailedToAuthenticate(realms)) => {
                        for realm in &realms {
                            if let Some(credentials) = self.callbacks.query_credentials(realm).await
                            {
                                self.credentials.add_for_realm(realm.as_str(), credentials)
                            } else {
                                return Err(RegistrationError::Auth(
                                    sip_auth::Error::FailedToAuthenticate(realms),
                                ));
                            }
                        }
                    }
                    Err(e) => return Err(RegistrationError::Auth(e)),
                }

                match replace(&mut self.task_state, RegistrationTaskState::Waiting) {
                    RegistrationTaskState::ReBindWithNewIdNeeded { new_id }
                        if !remove_binding && matches!(&self.state, RegistrationState::Null) =>
                    {
                        // No need to remove binding, none created yet

                        // Set new contact
                        self.registration.set_contact(Contact {
                            uri: new_id,
                            params: Default::default(),
                        });
                    }
                    RegistrationTaskState::Stopping(_) => unreachable!(),
                    _ => {}
                }
            } else {
                return Ok(response);
            }
        }

        Err(RegistrationError::Failed(Code::UNAUTHORIZED))
    }

    async fn update_received_rport(&mut self, response: &TsxResponse) {
        let received: Option<IpAddr> = response.base_headers.via[0]
            .params
            .get_val("received")
            .and_then(|v| v.parse().ok());
        let rport: Option<u16> = response.base_headers.via[0]
            .params
            .get_val("rport")
            .and_then(|v| v.parse().ok());

        if received.is_some() || rport.is_some() {
            let mut state = self.shared_state.lock().await;

            if !state.pub_addr_locked {
                let mut addr = state.pub_addr.unwrap_or_else(|| {
                    self.target_transport_info
                        .transport
                        .as_ref()
                        .expect("transport field is set, message was already sent")
                        .bound()
                });

                if let Some(received) = received {
                    addr.set_ip(received);
                }
                if let Some(rport) = rport {
                    addr.set_port(rport);
                }

                if state.pub_addr.map(|x| x != addr).unwrap_or(true) {
                    state.pub_addr = Some(addr);

                    self.target_transport_info.via_host_port = Some(addr.into());

                    let new_id = state.public_id();
                    self.registration.set_id(new_id.clone());

                    // Address has changed. Do not set new contact in registration yet.
                    // Instead put it in state so old binding can be removed first and then set the contact.
                    self.task_state = RegistrationTaskState::ReBindWithNewIdNeeded { new_id };
                }
            }
        }
    }

    async fn on_error(mut self, e: RegistrationError) {
        log::error!("Registration state changed to error {}", e);

        let error_state = RegistrationState::Error(e);
        self.callbacks
            .registration_state_changed(&self.state, &error_state)
            .await;
        self.state = error_state;
        self.task_state = RegistrationTaskState::Stopping(None);
    }

    async fn handle_cmd(&mut self, cmd: Result<Command, flume::RecvError>) {
        match cmd {
            Ok(Command::Stop(tx)) => {
                self.task_state = RegistrationTaskState::Stopping(Some(tx));
            }
            Err(..) => {
                self.task_state = RegistrationTaskState::Stopping(None);
            }
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RegisterError {
    #[error("invalid account id")]
    InvalidAccountId,
    #[error("account is already registering")]
    AlreadyRegistering,
    #[error(transparent)]
    Registration(RegistrationError),
}

#[derive(Debug, thiserror::Error)]
pub enum UnregisterError {
    #[error("invalid account id")]
    InvalidAccountId,
    #[error("account is not registered")]
    NotRegistering,
    #[error(transparent)]
    Registration(RegistrationError),
}

impl UserAgent {
    /// Create an account using the given [`AccountConfig`].  
    /// Infallible as it doesn't do anything else but creating the account.
    ///
    /// Returns a new id to identify the account, which can be used to interact with the created account.  
    /// e.g. register the account using [`register`](UserAgent::register)
    pub fn create_account(&self, config: AccountConfig) -> AccountId {
        self.endpoint[self.ua_layer]
            .accounts
            .lock()
            .insert(AccountState::new(config))
    }

    /// Delete the account of the given `account_id`  
    /// Any active registrations/bindings for this account will be automatically removed.
    ///
    /// Returns `true` if the account for the id existed and was deleted.
    pub fn delete_account(&self, account_id: AccountId) -> bool {
        self.endpoint[self.ua_layer]
            .accounts
            .lock()
            .remove(account_id)
            .is_some()
    }

    /// Try to register the account of the given `account_id` at the configured registrar
    ///
    /// Spawns a new task which keeps the registration active until the account is deleted
    /// or [`unregister`](UserAgent::unregister) is called.
    ///
    /// Returns the result of the initial REGISTER request
    pub async fn register(&self, account_id: AccountId) -> Result<(), RegisterError> {
        self.register_with_callbacks(account_id, DefaultAccountRegistrationCallbacks)
            .await
    }

    /// Same as [`register`](UserAgent::register), but with custom callbacks.
    /// See [`AccountRegistrationCallbacks`].
    pub async fn register_with_callbacks<CB>(
        &self,
        account_id: AccountId,
        callbacks: CB,
    ) -> Result<(), RegisterError>
    where
        CB: AccountRegistrationCallbacks,
    {
        let receiver = self.do_register_with_callbacks(account_id, callbacks)?;

        receiver
            .recv_async()
            .await
            .unwrap()
            .map_err(RegisterError::Registration)
    }

    fn do_register_with_callbacks<CB>(
        &self,
        account_id: AccountId,
        callbacks: CB,
    ) -> Result<flume::Receiver<Result<(), RegistrationError>>, RegisterError>
    where
        CB: AccountRegistrationCallbacks,
    {
        let ua_layer = &self.endpoint[self.ua_layer];
        let mut accounts = ua_layer.accounts.lock();
        let state = accounts
            .get_mut(account_id)
            .ok_or(RegisterError::InvalidAccountId)?;

        if state.reg_task_cmd_sender.is_some() {
            return Err(RegisterError::AlreadyRegistering);
        }

        let (reg_task_cmd_sender, command_recv) = bounded(4);
        state.reg_task_cmd_sender = Some(reg_task_cmd_sender);

        let (result_send, result_recv) = bounded(1);
        let task = AccountRegistrationTask::create(
            self.endpoint.clone(),
            state.shared_state.clone(),
            callbacks,
            command_recv,
            result_send,
        );

        self.runtime.spawn(task);

        Ok(result_recv)
    }

    /// Stops any registration for the account of the given `account_id`
    ///
    /// Returns the result of the REGISTER request
    pub async fn unregister(&self, account_id: AccountId) -> Result<(), UnregisterError> {
        let ua_layer = &self.endpoint[self.ua_layer];
        let mut accounts = ua_layer.accounts.lock();
        let state = accounts
            .get_mut(account_id)
            .ok_or(UnregisterError::InvalidAccountId)?;

        if let Some(sender) = state.reg_task_cmd_sender.take() {
            drop(accounts);

            let (tx, rx) = flume::bounded(1);
            sender
                .send_async(Command::Stop(tx))
                .await
                .map_err(|_| UnregisterError::NotRegistering)?;

            let result = rx
                .recv_async()
                .await
                .map_err(|_| UnregisterError::NotRegistering)?;

            result.map_err(UnregisterError::Registration)
        } else {
            Err(UnregisterError::NotRegistering)
        }
    }
}
