use crate::{
    outbound_call::{MakeCallError, OutboundCall},
    MediaBackend,
};
use sip_auth::{ClientAuthenticator, RequestParts, ResponseParts};
use sip_core::{transport::TargetTransportInfo, Endpoint};
use sip_types::{
    header::typed::{Contact, FromTo},
    uri::{NameAddr, SipUri},
    Name, StatusCode,
};
use sip_ua::register::Registration as RegistrationProto;
use std::{sync::Arc, time::Duration};
use tokio::{select, sync::watch};

/// Any errors that might be encountered while registering with a SIP registrar.
#[derive(Debug, thiserror::Error)]
pub enum RegisterError<A> {
    #[error(transparent)]
    Core(#[from] sip_core::Error),
    #[error(transparent)]
    Auth(A),
    #[error("Got response with unexpected status code={0:?}")]
    Failed(StatusCode),
}

/// Configuration used to bind an account to a SIP registrar
pub struct RegistrarConfig {
    pub registrar: SipUri,
    pub username: String,

    /// Override the generated ID use in the From header
    pub override_id: Option<NameAddr>,
    /// Override the generated Contact header
    pub override_contact: Option<Contact>,
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
            NameAddr::uri(
                SipUri::new(config.registrar.host_port.clone())
                    .user(config.username.clone().into()),
            )
        });

        let (transport, remote_addr) = endpoint.select_transport(&config.registrar).await?;
        let contact = config.override_contact.clone().unwrap_or_else(|| {
            Contact::new(NameAddr::uri(
                SipUri::new(transport.sent_by().into()).user(config.username.clone().into()),
            ))
        });

        let mut registration = RegistrationProto::new(
            id.clone(),
            contact.clone(),
            config.registrar.clone(),
            Duration::from_secs(300),
        );

        let mut target_transport_info = TargetTransportInfo {
            via_host_port: Some(transport.sent_by().into()),
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

    pub async fn make_call<A: ClientAuthenticator, M: MediaBackend>(
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

    pub fn is_registered(&mut self) -> bool {
        *self.is_registered.borrow_and_update()
    }

    pub async fn wait_for_registration_failure(&mut self) {
        let _ = self
            .is_registered
            .wait_for(|is_registered| !(*is_registered))
            .await;
    }
}

async fn keep_alive_task<A: ClientAuthenticator>(
    endpoint: Endpoint,
    mut registration: RegistrationProto,
    mut target_transport_info: TargetTransportInfo,
    mut authenticator: A,
    inner: Arc<RegistrationInner>,
) {
    loop {
        select! {
            _ = inner.is_registered.closed() => {
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
        } else {
            inner.is_registered.send_replace(true);
        }
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
        request
            .headers
            .edit(Name::TO, |to: &mut FromTo| to.tag = None)
            .map_err(sip_core::Error::Header)?;

        authenticator.authorize_request(&mut request.headers);

        let mut transaction = endpoint
            .send_request(request, target_transport_info)
            .await?;

        let response = transaction.receive_final().await.unwrap();

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
