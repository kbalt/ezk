use crate::register::Registration as RegistrationProto;
use crate::{
    MediaBackend,
    outbound_call::{MakeCallError, OutboundCall},
};
use sip_auth::{ClientAuthenticator, RequestParts, ResponseParts};
use sip_core::{
    Endpoint,
    transport::{TargetTransportInfo, TransportState},
};
use sip_types::{
    StatusCode,
    header::typed::Contact,
    uri::{NameAddr, SipUri},
};
use std::{sync::Arc, time::Duration};
use tokio::{select, sync::watch};

/// Any errors that might be encountered while registering with a SIP registrar.
#[derive(Debug, thiserror::Error)]
pub enum RegisterError<A> {
    #[error(transparent)]
    Core(#[from] sip_core::Error),
    #[error("Authentication of REGISTER request failed")]
    Auth(#[source] A),
    #[error("Got response to REGISTER with unexpected status code {0:?}")]
    Failed(StatusCode),
}

/// Configuration used to bind an account to a SIP registrar
pub struct RegistrarConfig {
    pub registrar: SipUri,

    /// Username used for building the ID
    pub username: String,

    /// Display name of the user for the binding, may be displayed to other users
    pub display_name: Option<String>,

    /// Override the generated ID used in the From header
    pub override_id: Option<NameAddr>,

    /// Override the generated Contact header
    pub override_contact: Option<Contact>,

    /// Override the default expiry duration
    pub expiry: Option<Duration>,
}

impl RegistrarConfig {
    pub fn new(username: String, registrar: SipUri) -> Self {
        RegistrarConfig {
            registrar,
            username,
            display_name: None,
            override_id: None,
            override_contact: None,
            expiry: None,
        }
    }

    /// Set a display name to use, see [`RegistrarConfig::display_name`]
    pub fn with_display_name(self, display_name: String) -> Self {
        Self {
            display_name: Some(display_name),
            ..self
        }
    }

    /// Override the default expiry duration
    pub fn with_custom_expiry(self, expiry: Duration) -> Self {
        Self {
            expiry: Some(expiry),
            ..self
        }
    }

    /// Override the generated ID used in the From header
    pub fn with_override_id(self, id: NameAddr) -> Self {
        Self {
            override_id: Some(id),
            ..self
        }
    }

    /// Override the generated Contact header
    pub fn with_override_contact(self, contact: Contact) -> Self {
        Self {
            override_contact: Some(contact),
            ..self
        }
    }
}

/// An active registration with a SIP registrar.
///
/// Dropping this type will remove the registration from the SIP registrar.
pub struct Registration {
    endpoint: Endpoint,
    is_registered: watch::Receiver<bool>,
    inner: Arc<RegistrationInner>,
}

pub(crate) struct RegistrationInner {
    id: NameAddr,
    contact: Contact,
    registrar: SipUri,
    // the expiry we request, not the one that actually was returned by the server
    request_expiry: Duration,

    is_registered: watch::Sender<bool>,
}

impl Registration {
    /// Send a REGISTER request using the provided config.
    /// If the registration was a success a background task will keep the binding active until [`Registration`] is dropped.
    pub async fn register<A: ClientAuthenticator + Send + 'static>(
        endpoint: Endpoint,
        config: RegistrarConfig,
        mut authenticator: A,
    ) -> Result<Self, RegisterError<A::Error>> {
        let id = config.override_id.clone().unwrap_or_else(|| {
            let uri = SipUri::new(config.registrar.host_port.clone())
                .user(config.username.clone().into());

            if let Some(display_name) = config.display_name {
                NameAddr::new(display_name, uri)
            } else {
                NameAddr::uri(uri)
            }
        });

        let (transport, remote_addr) = endpoint.select_transport(&config.registrar).await?;
        let contact = config.override_contact.clone().unwrap_or_else(|| {
            Contact::new(NameAddr::uri(
                SipUri::new(transport.bound().into()).user(config.username.clone().into()),
            ))
        });

        let mut registration = RegistrationProto::new(
            id.clone(),
            contact.clone(),
            config.registrar.clone(),
            Duration::from_secs(300),
        );

        let mut target_transport_info = TargetTransportInfo {
            via_host_port: Some(transport.bound().into()),
            transport: Some((transport, remote_addr)),
        };

        register(
            &endpoint,
            &mut target_transport_info,
            &mut registration,
            &mut authenticator,
            false,
        )
        .await?;

        // keep alive
        let (tx, rx) = watch::channel(true);
        let inner = Arc::new(RegistrationInner {
            id,
            contact,
            registrar: config.registrar,
            request_expiry: config.expiry.unwrap_or(Duration::from_secs(300)),
            is_registered: tx,
        });

        tokio::spawn(keep_alive_task(
            endpoint.clone(),
            registration,
            target_transport_info,
            authenticator,
            inner.clone(),
        ));

        Ok(Self {
            endpoint,
            is_registered: rx,
            inner,
        })
    }

    /// Make a call to the user on the registrar this `Registration` is bound to
    pub async fn make_call<A: ClientAuthenticator, M: MediaBackend>(
        &self,
        target: String,
        authenticator: A,
        media: M,
    ) -> Result<OutboundCall<M>, MakeCallError<M::Error, A::Error>> {
        let target = if let Ok(target) = target.parse() {
            target
        } else {
            self.inner.registrar.clone().user(target.into())
        };

        self.make_call_to_uri(target, authenticator, media).await
    }

    /// Make a call to the specified target uri using this registrations local user identity
    pub async fn make_call_to_uri<A: ClientAuthenticator, M: MediaBackend>(
        &self,
        target: SipUri,
        authenticator: A,
        media: M,
    ) -> Result<OutboundCall<M>, MakeCallError<M::Error, A::Error>> {
        OutboundCall::make(
            self.endpoint.clone(),
            authenticator,
            self.inner.id.clone(),
            self.inner.contact.clone(),
            target,
            media,
        )
        .await
    }

    /// Returns if the binding is still active
    pub fn is_registered(&mut self) -> bool {
        *self.is_registered.borrow_and_update()
    }

    /// Returns once the registration has failed.
    ///
    /// The failure state is permanent and the registration can be retried using [`Registration::retry_register`]
    pub async fn wait_for_registration_failure(&mut self) {
        let _ = self
            .is_registered
            .wait_for(|is_registered| !(*is_registered))
            .await;
    }

    /// Retry registering with the registrar.
    ///
    /// Should only be called after [`Registration::is_registered`] returned false or
    /// [`Registration::wait_for_registration_failure`] returned.
    pub async fn retry_register<A: ClientAuthenticator + Send + 'static>(
        &mut self,
        mut authenticator: A,
    ) -> Result<(), RegisterError<A::Error>> {
        if self.is_registered() {
            return Ok(());
        }

        let mut registration = RegistrationProto::new(
            self.inner.id.clone(),
            self.inner.contact.clone(),
            self.inner.registrar.clone(),
            self.inner.request_expiry,
        );

        let mut target_transport_info = TargetTransportInfo::default();

        register(
            &self.endpoint,
            &mut target_transport_info,
            &mut registration,
            &mut authenticator,
            false,
        )
        .await?;

        self.inner.is_registered.send_replace(true);

        // keep alive
        tokio::spawn(keep_alive_task(
            self.endpoint.clone(),
            registration,
            target_transport_info,
            authenticator,
            self.inner.clone(),
        ));

        Ok(())
    }
}

async fn keep_alive_task<A: ClientAuthenticator>(
    endpoint: Endpoint,
    mut registration: RegistrationProto,
    mut target_transport_info: TargetTransportInfo,
    mut authenticator: A,
    inner: Arc<RegistrationInner>,
) {
    let (transport, _) = target_transport_info
        .transport
        .as_ref()
        .expect("successful REGISTER must have selected a transport");
    let mut transport_state = transport.watch_state();
    let watch_transport = !transport.is_udp();

    loop {
        select! {
            biased;
            // Do not refresh or unregister when closure is already known.
            state = transport_state.wait_for(|state| matches!(state, TransportState::Closed(_))), if watch_transport => {
                inner.is_registered.send_replace(false);
                log::warn!("REGISTER transport failed: {state:?}");
                return;
            }
            _ = inner.is_registered.closed() => {
                // Registration dropped, exit loop
                break;
            }
            _ = registration.wait_for_expiry() => {}
        }

        // Refresh binding
        if let Err(e) = register(
            &endpoint,
            &mut target_transport_info,
            &mut registration,
            &mut authenticator,
            false,
        )
        .await
        {
            inner.is_registered.send_replace(false);
            log::warn!("REGISTER request to refresh binding failed: {e}");
            return;
        }

        inner.is_registered.send_replace(true);
    }

    // Remove binding
    if let Err(e) = register(
        &endpoint,
        &mut target_transport_info,
        &mut registration,
        &mut authenticator,
        true,
    )
    .await
    {
        log::warn!("REGISTER request to remove binding failed: {e}");
    }

    inner.is_registered.send_replace(false);
}

/// Send a register request and handle authentication using the given session and credentials
async fn register<A: ClientAuthenticator>(
    endpoint: &Endpoint,
    target_transport_info: &mut TargetTransportInfo,
    registration: &mut RegistrationProto,
    authenticator: &mut A,
    remove_binding: bool,
) -> Result<(), RegisterError<A::Error>> {
    loop {
        let mut request = registration.create_register(remove_binding);
        request.headers.insert_named(endpoint.allowed());
        authenticator.authorize_request(&mut request.headers);

        let mut transaction = endpoint
            .send_request(request, target_transport_info)
            .await?;

        let response = transaction.receive_final().await?;

        let response_code = response.line.code;

        match response_code.into_u16() {
            200..=299 => {
                if !remove_binding {
                    registration.receive_success_response(response);
                }

                return Ok(());
            }
            401 | 407 => {
                // wrap
                authenticator
                    .handle_rejection(
                        RequestParts {
                            line: &transaction.request().msg.line,
                            headers: &transaction.request().msg.headers,
                            body: &transaction.request().msg.body,
                        },
                        ResponseParts {
                            line: &response.line,
                            headers: &response.headers,
                            body: &response.body,
                        },
                    )
                    .map_err(RegisterError::Auth)?;
            }
            400..=499 if !remove_binding => {
                if !registration.receive_error_response(response) {
                    return Err(RegisterError::Failed(response_code));
                }
            }
            _ => return Err(RegisterError::Failed(response_code)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sip_auth::DigestAuthenticator;
    use sip_core::{IncomingRequest, Layer, MayTake};
    use sip_types::header::typed::Expires;
    use std::error::Error;
    use tokio::{sync::mpsc, time::timeout};

    struct Registrar(mpsc::UnboundedSender<u32>);

    #[async_trait::async_trait]
    impl Layer for Registrar {
        fn name(&self) -> &'static str {
            "test-registrar"
        }

        async fn receive(&self, endpoint: &Endpoint, request: MayTake<'_, IncomingRequest>) {
            let mut request = request.take();
            let expires = request.headers.get_named::<Expires>().unwrap();
            let response = endpoint.create_response(&request, StatusCode::OK, None);
            endpoint
                .create_server_tsx(&mut request)
                .respond(response)
                .await
                .unwrap();
            self.0.send(expires.0).unwrap();
        }
    }

    #[tokio::test]
    async fn retry_restores_registered_state() -> Result<(), Box<dyn Error>> {
        timeout(Duration::from_secs(5), async {
            let (responses, mut received) = mpsc::unbounded_channel();
            let mut registrar_builder = Endpoint::builder();
            let transport = registrar_builder.bind_udp("127.0.0.1:0".parse()?).await?;
            registrar_builder.add_layer(Registrar(responses));
            let _registrar = registrar_builder.build();

            let mut endpoint_builder = Endpoint::builder();
            endpoint_builder.add_allow(sip_types::Method::REGISTER);
            endpoint_builder.bind_udp("127.0.0.1:0".parse()?).await?;
            let endpoint = endpoint_builder.build();

            let registrar_uri = SipUri::new(transport.bound().into());
            let id = NameAddr::uri("sip:alice@example.com".parse()?);
            let contact = Contact::new(NameAddr::uri("sip:alice@127.0.0.1".parse()?));
            let (is_registered, receiver) = watch::channel(false);
            let inner = Arc::new(RegistrationInner {
                id,
                contact,
                registrar: registrar_uri,
                request_expiry: Duration::from_secs(300),
                is_registered,
            });
            let mut registration = Registration {
                endpoint,
                is_registered: receiver,
                inner,
            };

            registration
                .retry_register(DigestAuthenticator::new(Default::default()))
                .await?;
            assert!(registration.is_registered());
            assert_eq!(received.recv().await, Some(300));

            drop(registration);
            assert_eq!(received.recv().await, Some(0));

            Ok::<_, Box<dyn Error>>(())
        })
        .await??;

        Ok(())
    }
}
