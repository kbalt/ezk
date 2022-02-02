use parking_lot as pl;
use sip_auth::digest::DigestCredentials;
use sip_auth::CredentialStore;
use tokio::sync::Mutex;

#[derive(Default)]
pub struct AuthenticationConfig {
    /// Storage for credentials with a realm->credential mapping
    pub credentials: CredentialStore,

    /// Enforce quality of protection for all challenges
    ///
    /// Treats all authentication challenges as if they at least sent qop="auth"
    ///
    /// Disabled by default for backwards compatibility but recommended if compatible
    pub enforce_qop: bool,

    /// Reject MD5 for authentication
    pub reject_md5: bool,

    /// Callbacks which can be used to dynamically prompt for credentials
    pub callbacks: Box<dyn CredentialCallbacks>,
}

pub(crate) struct SharedAuthentication {
    pub(crate) callbacks: Mutex<Box<dyn CredentialCallbacks>>,
    pub(crate) credentials: pl::RwLock<CredentialStore>,
    pub(crate) enforce_qop: bool,
    pub(crate) reject_md5: bool,
}

impl From<AuthenticationConfig> for SharedAuthentication {
    fn from(config: AuthenticationConfig) -> Self {
        Self {
            callbacks: Mutex::new(config.callbacks),
            credentials: pl::RwLock::new(config.credentials),
            enforce_qop: config.enforce_qop,
            reject_md5: config.reject_md5,
        }
    }
}

impl SharedAuthentication {
    // TODO: function name
    pub(crate) async fn query_credentials_if_possible(
        &self,
        result: Result<(), sip_auth::Error>,
    ) -> Result<(), sip_auth::Error> {
        match result {
            Ok(()) => Ok(()),
            Err(sip_auth::Error::FailedToAuthenticate(realms)) => {
                let callbacks = self.callbacks.lock().await;

                for realm in &realms {
                    if let Some(credentials) = callbacks.query_credentials(realm).await {
                        self.credentials
                            .write()
                            .add_for_realm(realm.as_str(), credentials);
                    } else {
                        return Err(sip_auth::Error::FailedToAuthenticate(realms));
                    }
                }

                Ok(())
            }
            Err(e) => Err(e),
        }
    }
}

#[async_trait::async_trait]
pub trait CredentialCallbacks: Send + Sync + 'static {
    /// Prompts for credentials whenever authentication for a given realm fails
    ///
    /// Can be used for prompting a user.
    ///
    /// Should avoid returning the same values for a realm as that will only result in this function being called again.
    /// Use the [`CredentialStore`] in the [`AuthenticationConfig`] instead, to store/prepare credentials.
    async fn query_credentials(&self, _realm: &str) -> Option<DigestCredentials> {
        None
    }
}

impl Default for Box<dyn CredentialCallbacks> {
    fn default() -> Self {
        struct DefaultCredentialCallbacks;
        impl CredentialCallbacks for DefaultCredentialCallbacks {}
        Box::new(DefaultCredentialCallbacks)
    }
}
