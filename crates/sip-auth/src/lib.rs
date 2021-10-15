use bytesstr::BytesStr;
use digest::{DigestAuthenticator, DigestCredentials};
use sip_types::header::typed::{AuthChallenge, AuthResponse};
use sip_types::msg::RequestLine;
use sip_types::{Headers, Name};
use std::collections::HashMap;

pub mod digest;
mod error;

pub use error::Error;

/// Information about the request that has to be authenticated
#[derive(Debug, Clone, Copy)]
pub struct RequestParts<'s> {
    pub line: &'s RequestLine,
    pub headers: &'s Headers,
    pub body: &'s [u8],
}

/// A HashMap wrapper that holds credentials mapped to their respective realm
///
/// Default credentials can be set to attempt authentication for unknown realms
#[derive(Default)]
pub struct CredentialStore<C = DigestCredentials>
where
    C: Send + Sync,
{
    default: Option<C>,
    map: HashMap<String, C>,
}

impl<C> CredentialStore<C>
where
    C: Send + Sync,
{
    pub fn new() -> Self {
        Self {
            default: None,
            map: HashMap::new(),
        }
    }

    /// Set default `credentials` to authenticate on unknown realms
    pub fn set_default(&mut self, credentials: C) {
        self.default = Some(credentials)
    }

    /// Add `credentials` that will be used when authenticating for `realm`
    pub fn add_for_realm<R>(&mut self, realm: R, credentials: C)
    where
        R: Into<String>,
    {
        self.map.insert(realm.into(), credentials);
    }

    /// Get credentials for the specified `realm`
    ///
    /// Returns the default credentials when no credentials where set for the
    /// requested `realm`
    pub fn get_for_realm(&self, realm: &str) -> Option<&C> {
        self.map.get(realm).or_else(|| self.default.as_ref())
    }

    /// Remove credentials for the specified `realm`
    pub fn remove_for_realm(&mut self, realm: &str) {
        self.map.remove(realm);
    }
}

/// The UAC (User Agent Client) authenticator trait
///
/// May be implemented for each authentication scheme that shall be supported.
/// See [`DigestAuthenticator`] for an example implementation.
pub trait UacAuthenticator: Default + Send + Sync {
    type Credentials: Send + Sync;

    /// Return the realm that the scheme wants the client to authenticate for.
    ///
    /// Each scheme is required to provide a realm of some sort.
    fn get_realm<'s>(&mut self, auth: &'s AuthChallenge) -> Result<&'s BytesStr, Error>;

    /// Handle the [`AuthChallenge`] and provide the [`AuthResponse`]
    fn handle_challenge(
        &mut self,
        responses: &[ResponseEntry],
        request_parts: RequestParts<'_>,
        challenge: AuthChallenge,
        credentials: &Self::Credentials,
    ) -> Result<AuthResponse, Error>;

    /// Gets called when a header gets used/reused for a request.
    fn on_authorize_request(&mut self, response: &mut ResponseEntry);
}

/// Contains a list of authentication challenges that want to authenticate the same realm.
///
/// As each realm may only be authenticated once per request, only the topmost supported challenge will
/// be used for authentication. (See RFC8760 Section 2.4)
struct ChallengedRealm {
    realm: BytesStr,
    challenges: Vec<(bool, AuthChallenge)>,
}

/// A cached authorization response that will be used/reused to authorize a request
pub struct ResponseEntry {
    pub realm: BytesStr,
    pub response: AuthResponse,

    /// Number of times the response has been used in a request.
    ///
    /// Will be initialized at 0 and incremented each time after calling
    /// `UacAuthenticator::on_authorize_request`.
    pub use_count: u32,

    is_proxy: bool,
}

/// A stateful UAC (User Agent Client) authentication session
#[derive(Default)]
pub struct UacAuthSession<A: UacAuthenticator = DigestAuthenticator> {
    authenticator: A,
    responses: Vec<ResponseEntry>,
}

impl<A: UacAuthenticator> UacAuthSession<A> {
    pub fn new(authenticator: A) -> Self {
        Self {
            authenticator,
            responses: vec![],
        }
    }

    /// Get the inner authenticator to access exposed functionality
    pub fn get_authenticator(&mut self) -> &mut A {
        &mut self.authenticator
    }

    /// Generates the appropriate authorization headers for a 401 or 407 response.
    pub fn handle_authenticate(
        &mut self,
        headers: &Headers,
        credential_store: &CredentialStore<A::Credentials>,
        request_parts: RequestParts<'_>,
    ) -> Result<(), Error> {
        let mut challenged_realms = vec![];

        self.read_challenges(false, headers, &mut challenged_realms)?;
        self.read_challenges(true, headers, &mut challenged_realms)?;

        let mut failed_realms = vec![];

        'outer: for challenged_realm in challenged_realms {
            let credentials = if let Some(credentials) =
                credential_store.get_for_realm(&challenged_realm.realm)
            {
                credentials
            } else {
                failed_realms.push(challenged_realm.realm);
                continue;
            };

            for (is_proxy, challenge) in challenged_realm.challenges {
                let result = self.authenticator.handle_challenge(
                    &self.responses,
                    request_parts,
                    challenge,
                    credentials,
                );

                let response = match result {
                    Ok(response) => response,
                    Err(e) => {
                        log::warn!("failed to handle challenge {}", e);
                        continue;
                    }
                };

                let realm = challenged_realm.realm;

                // Remove old response for the realm
                if let Some(i) = self
                    .responses
                    .iter()
                    .position(|response| response.realm == realm)
                {
                    self.responses.remove(i);
                }

                let entry = ResponseEntry {
                    realm,
                    response,
                    use_count: 0,
                    is_proxy,
                };

                self.responses.push(entry);

                continue 'outer;
            }

            failed_realms.push(challenged_realm.realm);
        }

        if !failed_realms.is_empty() {
            let mut dst = String::new();
            let mut iter = failed_realms.into_iter();
            let first = iter.next().unwrap();
            dst.push_str(&first);
            for realm in iter {
                dst.push_str(", ");
                dst.push_str(&realm);
            }

            return Err(Error::FailedToAuthenticate(dst.into()));
        }

        Ok(())
    }

    /// Apply the generated authentication headers to the provided `headers`
    pub fn authorize_request(&mut self, headers: &mut Headers) {
        for entry in &mut self.responses {
            let name = if entry.is_proxy {
                Name::PROXY_AUTHORIZATION
            } else {
                Name::AUTHORIZATION
            };

            self.authenticator.on_authorize_request(entry);

            entry.use_count += 1;

            headers.insert_type(name, &entry.response);
        }
    }

    /// Read all authentication headers and group them by realm
    fn read_challenges(
        &mut self,
        is_proxy: bool,
        headers: &Headers,
        dst: &mut Vec<ChallengedRealm>,
    ) -> Result<(), Error> {
        let challenge_name = if is_proxy {
            Name::PROXY_AUTHENTICATE
        } else {
            Name::WWW_AUTHENTICATE
        };

        let challenges = headers
            .try_get::<Vec<AuthChallenge>>(challenge_name)
            .map(|val| val.map_err(Error::Header))
            .transpose()?
            .unwrap_or_default();

        for challenge in challenges {
            let realm = match self.authenticator.get_realm(&challenge) {
                Ok(realm) => realm,
                Err(Error::UnknownScheme(scheme)) => {
                    // TODO: unsupported schemes may trigger weird behavior:
                    // the session will not respond to challenges it does not
                    // understand and may send a invalid auth-response headers
                    log::warn!("Skipped unknown authentication scheme: {}", scheme);
                    continue;
                }
                Err(e) => return Err(e),
            };

            if let Some(challenged_realm) = dst
                .iter_mut()
                .find(|challenged_realm| &challenged_realm.realm == realm)
            {
                challenged_realm.challenges.push((is_proxy, challenge));
            } else {
                dst.push(ChallengedRealm {
                    realm: realm.clone(),
                    challenges: vec![(is_proxy, challenge)],
                });
            }
        }

        Ok(())
    }
}
