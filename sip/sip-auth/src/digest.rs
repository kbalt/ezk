use crate::{ClientAuthenticator, RequestParts, ResponseParts};
use bytesstr::BytesStr;
use sha2::Digest;
use sip_types::header::HeaderError;
use sip_types::header::typed::{
    Algorithm, AlgorithmValue, AuthChallenge, DigestChallenge, DigestResponse, QopOption,
    QopResponse, Username,
};
use sip_types::print::{AppendCtx, PrintCtx, UriContext};
use sip_types::{Headers, Name};
use std::collections::HashMap;

#[derive(Debug, thiserror::Error)]
pub enum DigestError {
    #[error("failed to authenticate realms: {0:?}")]
    FailedToAuthenticate(Vec<BytesStr>),
    #[error("encountered unsupported algorithm {0}")]
    UnsupportedAlgorithm(BytesStr),
    #[error("missing credentials for realm {0}")]
    MissingCredentials(BytesStr),
    #[error("unsupported qop")]
    UnsupportedQop,
    #[error(transparent)]
    Header(HeaderError),
}

/// A HashMap wrapper that holds credentials mapped to their respective realm
///
/// Default credentials can be set to attempt authentication for unknown realms
#[derive(Default, Clone)]
pub struct DigestCredentials {
    default: Option<DigestUser>,
    map: HashMap<String, DigestUser>,
}

impl DigestCredentials {
    pub fn new() -> Self {
        Self {
            default: None,
            map: HashMap::new(),
        }
    }

    /// Set default `credentials` to authenticate on unknown realms
    pub fn set_default(&mut self, credentials: DigestUser) {
        self.default = Some(credentials)
    }

    /// Add `credentials` that will be used when authenticating for `realm`
    pub fn add_for_realm<R>(&mut self, realm: R, credentials: DigestUser)
    where
        R: Into<String>,
    {
        self.map.insert(realm.into(), credentials);
    }

    /// Get credentials for the specified `realm`
    ///
    /// Returns the default credentials when no credentials where set for the
    /// requested `realm`
    pub fn get_for_realm(&self, realm: &str) -> Option<&DigestUser> {
        self.map.get(realm).or(self.default.as_ref())
    }

    /// Remove credentials for the specified `realm`
    pub fn remove_for_realm(&mut self, realm: &str) {
        self.map.remove(realm);
    }
}

#[derive(Clone)]
pub struct DigestUser {
    user: String,
    password: Vec<u8>,
}

impl DigestUser {
    pub fn new<U, P>(user: U, password: P) -> Self
    where
        U: Into<String>,
        P: Into<Vec<u8>>,
    {
        Self {
            user: user.into(),
            password: password.into(),
        }
    }
}

/// Used to solve Digest authenticate challenges in 401 / 407 SIP responses
pub struct DigestAuthenticator {
    pub credentials: DigestCredentials,
    qop_responses: Vec<(BytesStr, QopEntry)>,
    responses: Vec<ResponseEntry>,

    /// Respond with qop `Auth` when a challenge does not contain qop field (RFC8760 Section 2.6). Is false by default
    pub enforce_qop: bool,
    /// Reject challenges with MD5 algorithm. Is false by default
    pub reject_md5: bool,
}

struct QopEntry {
    ha1: String,
    ha2: String,
    hash: HashFn,
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
pub(crate) struct ResponseEntry {
    pub realm: BytesStr,
    pub header: DigestResponse,

    /// Number of times the response has been used in a request.
    ///
    /// Will be initialized at 0 and incremented each time after calling
    /// `UacAuthenticator::on_authorize_request`.
    pub use_count: u32,

    is_proxy: bool,
}

impl ClientAuthenticator for DigestAuthenticator {
    type Error = DigestError;

    fn authorize_request(&mut self, request_headers: &mut Headers) {
        for response in &mut self.responses {
            let name = if response.is_proxy {
                Name::PROXY_AUTHORIZATION
            } else {
                Name::AUTHORIZATION
            };

            // nc is already correct
            if response.use_count > 0 {
                let digest_realm = &response.header.realm;

                // qop response needs its nonce-count incremented and response re-calculated
                if let Some(qop_response) = &mut response.header.qop_response {
                    qop_response.nc += 1;

                    let (_, qop_entry) = self
                        .qop_responses
                        .iter_mut()
                        .find(|(realm, _)| realm == digest_realm)
                        .expect("qop_entry must be some");

                    match qop_response.qop {
                        QopOption::Auth | QopOption::AuthInt => {
                            let hash = (qop_entry.hash)(
                                format!(
                                    "{}:{}:{:08X}:{}:auth:{}",
                                    qop_entry.ha1,
                                    response.header.nonce,
                                    qop_response.nc,
                                    qop_response.cnonce,
                                    qop_entry.ha2
                                )
                                .as_bytes(),
                            );

                            response.header.response = hash.into();
                        }
                        QopOption::Other(_) => unreachable!(),
                    };
                }
            }

            response.use_count += 1;

            request_headers.insert_type(name, &response.header);
        }
    }

    fn handle_rejection(
        &mut self,
        rejected_request: RequestParts<'_>,
        reject_response: ResponseParts<'_>,
    ) -> Result<(), DigestError> {
        let mut challenged_realms = vec![];

        self.read_challenges(false, reject_response.headers, &mut challenged_realms)?;
        self.read_challenges(true, reject_response.headers, &mut challenged_realms)?;

        let mut failed_realms = vec![];

        'outer: for challenged_realm in challenged_realms {
            for (is_proxy, challenge) in challenged_realm.challenges {
                let AuthChallenge::Digest(challenge) = challenge else {
                    continue;
                };

                let result = self.handle_challenge(rejected_request, challenge);

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
                    header: response,
                    use_count: 0,
                    is_proxy,
                };

                self.responses.push(entry);

                continue 'outer;
            }

            failed_realms.push(challenged_realm.realm);
        }

        if !failed_realms.is_empty() {
            return Err(DigestError::FailedToAuthenticate(failed_realms));
        }

        Ok(())
    }
}

impl DigestAuthenticator {
    pub fn new(credentials: DigestCredentials) -> Self {
        Self {
            credentials,
            qop_responses: vec![],
            responses: vec![],
            enforce_qop: false,
            reject_md5: false,
        }
    }

    /// Read all authentication headers and group them by realm
    fn read_challenges(
        &mut self,
        is_proxy: bool,
        headers: &Headers,
        dst: &mut Vec<ChallengedRealm>,
    ) -> Result<(), DigestError> {
        let challenge_name = if is_proxy {
            Name::PROXY_AUTHENTICATE
        } else {
            Name::WWW_AUTHENTICATE
        };

        let challenges = headers
            .try_get::<Vec<AuthChallenge>>(challenge_name)
            .map(|val| val.map_err(DigestError::Header))
            .transpose()?
            .unwrap_or_default();

        for challenge in challenges {
            let realm = match &challenge {
                AuthChallenge::Digest(digest_challenge) => &digest_challenge.realm,
                AuthChallenge::Other(..) => {
                    continue;
                }
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

    fn handle_challenge(
        &mut self,
        request_parts: RequestParts<'_>,
        challenge: DigestChallenge,
    ) -> Result<DigestResponse, DigestError> {
        // Following things can happen:
        // - We didn't respond to this challenge yet -> authenticate
        // - We did respond, but
        //     - The previous response has an outdated nonce, sets stale to `true` -> authenticate with new nonce
        //     - The new challenge has set a new nonce but hasn't set stale=true,
        //       this is a observed behavior from other implementations and happens
        //       when using any qop. To solve this issue, stale is ignored and the
        //       the nonce is compared directly.
        let previous_response = self
            .responses
            .iter()
            .find(|response| response.realm == challenge.realm);

        let authenticate = if let Some(previous_response) = previous_response {
            previous_response.header.nonce != challenge.nonce
        } else {
            true
        };

        if authenticate {
            self.handle_digest_challenge(challenge, request_parts)
        } else {
            Err(DigestError::FailedToAuthenticate(vec![challenge.realm]))
        }
    }

    fn handle_digest_challenge(
        &mut self,
        digest_challenge: DigestChallenge,
        request_parts: RequestParts<'_>,
    ) -> Result<DigestResponse, DigestError> {
        let algorithm_value = match digest_challenge.algorithm.clone() {
            Algorithm::AkaNamespace((_, av)) => av,
            Algorithm::AlgorithmValue(av) => av,
        };

        let (hash, is_session): (HashFn, bool) = match algorithm_value {
            AlgorithmValue::MD5 => {
                if self.reject_md5 {
                    return Err(DigestError::UnsupportedAlgorithm(BytesStr::from_static(
                        "MD5",
                    )));
                } else {
                    (hash_md5, false)
                }
            }
            AlgorithmValue::MD5Sess => {
                if self.reject_md5 {
                    return Err(DigestError::UnsupportedAlgorithm(BytesStr::from_static(
                        "MD5",
                    )));
                } else {
                    (hash_md5, true)
                }
            }
            AlgorithmValue::SHA256 => (hash_sha256, false),
            AlgorithmValue::SHA256Sess => (hash_sha256, true),
            AlgorithmValue::SHA512256 => (hash_sha512_trunc256, false),
            AlgorithmValue::SHA512256Sess => (hash_sha512_trunc256, true),
            AlgorithmValue::Other(other) => return Err(DigestError::UnsupportedAlgorithm(other)),
        };

        let response = self.digest_respond(digest_challenge, request_parts, is_session, hash)?;

        Ok(response)
    }

    fn digest_respond(
        &mut self,
        mut challenge: DigestChallenge,
        request_parts: RequestParts<'_>,
        is_session: bool,
        hash: HashFn,
    ) -> Result<DigestResponse, DigestError> {
        let digest_user = self
            .credentials
            .get_for_realm(&challenge.realm)
            .ok_or_else(|| DigestError::MissingCredentials(challenge.realm.clone()))?
            .clone();

        let cnonce = BytesStr::from(uuid::Uuid::new_v4().simple().to_string());

        let mut ha1 = hash(
            [
                format!("{}:{}:", digest_user.user, challenge.realm).as_bytes(),
                &digest_user.password,
            ]
            .concat()
            .as_slice(),
        );

        if is_session {
            ha1 = format!("{}:{}:{}", ha1, challenge.nonce, cnonce);
        }

        let ctx = PrintCtx {
            method: Some(&request_parts.line.method),
            uri: Some(UriContext::ReqUri),
        };

        let uri = request_parts.line.uri.print_ctx(ctx).to_string();

        // enforce qop when enabled (See RFC8760 Section 2.6)
        if challenge.qop.is_empty() && self.enforce_qop {
            challenge.qop.push(QopOption::Auth)
        }

        let (response, qop_response) = if !challenge.qop.is_empty() {
            if challenge.qop.contains(&QopOption::AuthInt) {
                let ha2 = hash(
                    format!(
                        "{}:{}:{}",
                        &request_parts.line.method,
                        uri,
                        hash(request_parts.body)
                    )
                    .as_bytes(),
                );

                let nc = 1;

                let response = hash(
                    format!(
                        "{}:{}:{:08X}:{}:auth-int:{}",
                        ha1, challenge.nonce, nc, cnonce, ha2
                    )
                    .as_bytes(),
                );

                self.save_qop_response(challenge.realm.clone(), ha1, ha2, hash);

                let qop_response = QopResponse {
                    qop: QopOption::AuthInt,
                    cnonce,
                    nc,
                };

                (response, Some(qop_response))
            } else if challenge.qop.contains(&QopOption::Auth) {
                let a2 = format!("{}:{}", &request_parts.line.method, uri);
                let ha2 = hash(a2.as_bytes());

                let nc = 1;

                let response = hash(
                    format!(
                        "{}:{}:{:08X}:{}:auth:{}",
                        ha1, challenge.nonce, nc, cnonce, ha2
                    )
                    .as_bytes(),
                );

                self.save_qop_response(challenge.realm.clone(), ha1, ha2, hash);

                let qop_response = QopResponse {
                    qop: QopOption::Auth,
                    cnonce,
                    nc,
                };

                (response, Some(qop_response))
            } else {
                return Err(DigestError::UnsupportedQop);
            }
        } else {
            let a2 = format!("{}:{}", &request_parts.line.method, uri);

            (
                hash(format!("{}:{}:{}", ha1, challenge.nonce, hash(a2.as_bytes())).as_bytes()),
                None,
            )
        };

        let username = if challenge.userhash {
            // Hash the username when the challenge sets `userhash` (RFC7616 Section 3.4.4)
            let username_hash =
                hash(format!("{}:{}", digest_user.user, challenge.realm).as_bytes())
                    .as_str()
                    .into();

            Username::Username(username_hash)
        } else {
            Username::new(digest_user.user.as_str().into())
        };

        Ok(DigestResponse {
            username,
            realm: challenge.realm,
            nonce: challenge.nonce,
            uri: uri.into(),
            response: response.into(),
            algorithm: challenge.algorithm,
            opaque: challenge.opaque,
            qop_response,
            userhash: challenge.userhash,
            other: vec![],
        })
    }

    fn save_qop_response(
        &mut self,
        challenge_realm: BytesStr,
        ha1: String,
        ha2: String,
        hash: HashFn,
    ) {
        let qop_entry = QopEntry { ha1, ha2, hash };

        if let Some((_, old_qop_entry)) = self
            .qop_responses
            .iter_mut()
            .find(|(realm, _)| *realm == challenge_realm)
        {
            *old_qop_entry = qop_entry;
        } else {
            self.qop_responses
                .push((challenge_realm.clone(), qop_entry))
        }
    }
}

fn hash_md5(i: &[u8]) -> String {
    format!("{:x}", md5::compute(i))
}

fn hash_sha256(i: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(i);
    format!("{:x}", hasher.finalize())
}

fn hash_sha512_trunc256(i: &[u8]) -> String {
    let mut hasher = sha2::Sha512_256::new();
    hasher.update(i);
    format!("{:x}", hasher.finalize())
}

type HashFn = fn(&[u8]) -> String;

#[cfg(test)]
mod test {
    use super::*;
    use sip_types::{
        Headers, Method, Name, StatusCode,
        header::typed::AuthResponse,
        msg::{RequestLine, StatusLine},
        uri::SipUri,
    };

    fn test_authenticator() -> DigestAuthenticator {
        let mut credentials = DigestCredentials::new();

        credentials.add_for_realm("example.org", DigestUser::new("user123", "password123"));

        DigestAuthenticator::new(credentials)
    }

    #[test]
    fn digest_challenge() {
        let mut authenticator = test_authenticator();

        let mut headers = Headers::new();

        headers.insert_type(
            Name::WWW_AUTHENTICATE,
            &AuthChallenge::Digest(DigestChallenge {
                realm: "example.org".into(),
                domain: None,
                nonce: "YWmh5GFpoLjiTDCA1hTSSygkgdj99aHE".into(),
                opaque: None,
                stale: false,
                algorithm: Algorithm::AlgorithmValue(AlgorithmValue::MD5),
                qop: vec![],
                userhash: false,
                other: vec![],
            }),
        );

        let line = RequestLine {
            method: Method::REGISTER,
            uri: "sip:example.org".parse::<SipUri>().unwrap(),
        };

        authenticator
            .handle_rejection(
                RequestParts {
                    line: &line,
                    headers: &Headers::new(),
                    body: &[],
                },
                ResponseParts {
                    line: &StatusLine {
                        code: StatusCode::UNAUTHORIZED,
                        reason: None,
                    },
                    headers: &headers,
                    body: &[],
                },
            )
            .unwrap();

        let mut response_headers = Headers::new();
        authenticator.authorize_request(&mut response_headers);

        let authorization = response_headers
            .get::<AuthResponse>(Name::AUTHORIZATION)
            .unwrap();

        match authorization {
            AuthResponse::Digest(DigestResponse {
                username,
                realm,
                nonce,
                uri,
                response,
                algorithm,
                opaque,
                qop_response,
                userhash,
                other,
            }) => {
                assert_eq!(username, Username::Username("user123".into()));
                assert_eq!(realm, "example.org");
                assert_eq!(nonce, "YWmh5GFpoLjiTDCA1hTSSygkgdj99aHE");
                assert_eq!(uri, "sip:example.org");
                assert_eq!(response, "bc185e4893f17f12dc53153d2a62e6a6");
                assert_eq!(algorithm, Algorithm::AlgorithmValue(AlgorithmValue::MD5));
                assert_eq!(opaque, None);
                assert_eq!(qop_response, None);
                assert!(!userhash);
                assert_eq!(other, vec![]);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn digest_challenge_and_response() {
        let mut authenticator = test_authenticator();

        let mut headers = Headers::new();

        headers.insert_type(
            Name::WWW_AUTHENTICATE,
            &AuthChallenge::Digest(DigestChallenge {
                realm: "example.org".into(),
                domain: None,
                nonce: "YWmh5GFpoLjiTDCA1hTSSygkgdj99aHE".into(),
                opaque: None,
                stale: false,
                algorithm: Algorithm::AlgorithmValue(AlgorithmValue::MD5),
                qop: vec![QopOption::AuthInt],
                userhash: false,
                other: vec![],
            }),
        );

        let uri: SipUri = "sip:example.org".parse().unwrap();

        let line = RequestLine {
            method: Method::REGISTER,
            uri,
        };

        authenticator
            .handle_rejection(
                RequestParts {
                    line: &line,
                    headers: &Headers::new(),
                    body: &[],
                },
                ResponseParts {
                    line: &StatusLine {
                        code: StatusCode::UNAUTHORIZED,
                        reason: None,
                    },
                    headers: &headers,
                    body: &[],
                },
            )
            .unwrap();

        let mut response_headers = Headers::new();
        authenticator.authorize_request(&mut response_headers);

        let response = response_headers
            .get::<AuthResponse>(Name::AUTHORIZATION)
            .unwrap();

        let resp_value = match response {
            AuthResponse::Digest(DigestResponse {
                username,
                realm,
                nonce,
                uri,
                response, // cannot check, cnonce is random
                algorithm,
                opaque,
                qop_response,
                userhash,
                other,
            }) => {
                assert_eq!(username, Username::Username("user123".into()));
                assert_eq!(realm, "example.org");
                assert_eq!(nonce, "YWmh5GFpoLjiTDCA1hTSSygkgdj99aHE");
                assert_eq!(uri, "sip:example.org");
                assert_eq!(algorithm, Algorithm::AlgorithmValue(AlgorithmValue::MD5));
                assert_eq!(opaque, None);
                let qop_response = qop_response.unwrap();
                assert_eq!(qop_response.qop, QopOption::AuthInt);
                assert_eq!(qop_response.nc, 1);
                assert!(!userhash);
                assert_eq!(other, vec![]);
                response
            }
            _ => panic!("Expected digest"),
        };

        let mut response_headers = Headers::new();
        authenticator.authorize_request(&mut response_headers);

        let response = response_headers
            .get::<AuthResponse>(Name::AUTHORIZATION)
            .unwrap();

        match response {
            AuthResponse::Digest(DigestResponse {
                username,
                realm,
                nonce,
                uri,
                response, // cannot check, cnonce is random
                algorithm,
                opaque,
                qop_response,
                userhash,
                other,
            }) => {
                assert_eq!(username, Username::Username("user123".into()));
                assert_eq!(realm, "example.org");
                assert_eq!(nonce, "YWmh5GFpoLjiTDCA1hTSSygkgdj99aHE");
                assert_eq!(uri, "sip:example.org");

                assert_eq!(algorithm, Algorithm::AlgorithmValue(AlgorithmValue::MD5));
                assert_eq!(opaque, None);
                let qop_response = qop_response.unwrap();
                assert_eq!(qop_response.qop, QopOption::AuthInt);
                assert_eq!(qop_response.nc, 2);
                assert!(!userhash);
                assert_eq!(other, vec![]);
                assert_ne!(resp_value, response)
            }
            _ => panic!("Expected digest"),
        }
    }
}
