use crate::{Error, RequestParts, ResponseEntry, UacAuthenticator};
use bytesstr::BytesStr;
use sha2::Digest;
use sip_types::header::typed::{
    Algorithm, AuthChallenge, AuthResponse, DigestChallenge, DigestResponse, QopOption,
    QopResponse, Username,
};
use sip_types::print::{AppendCtx, PrintCtx, UriContext};

pub struct DigestCredentials {
    user: String,
    password: String,
}

impl DigestCredentials {
    pub fn new<U, P>(user: U, password: P) -> Self
    where
        U: Into<String>,
        P: Into<String>,
    {
        Self {
            user: user.into(),
            password: password.into(),
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

struct QopEntry {
    ha1: String,
    ha2: String,
    hash: HashFn,
}

/// Used to authorize 401 & 407 Digest responses
#[derive(Default)]
pub struct DigestAuthenticator {
    qop_responses: Vec<(BytesStr, QopEntry)>,
    /// Respond with qop `Auth` when a challenge does not contain qop field (RFC8760 Section 2.6). Is false by default
    pub enforce_qop: bool,
    /// Reject challenges with MD5 algorithm. Is false by default
    pub reject_md5: bool,
}

impl UacAuthenticator for DigestAuthenticator {
    type Credentials = DigestCredentials;

    fn get_realm<'s>(&mut self, auth: &'s AuthChallenge) -> Result<&'s BytesStr, Error> {
        match auth {
            AuthChallenge::Digest(digest) => Ok(&digest.realm),
            AuthChallenge::Other(other) => Err(Error::UnknownScheme(other.scheme.clone())),
        }
    }

    fn handle_challenge(
        &mut self,
        responses: &[ResponseEntry],
        request_parts: RequestParts<'_>,
        challenge: AuthChallenge,
        credentials: &DigestCredentials,
    ) -> Result<AuthResponse, Error> {
        let challenge = match challenge {
            AuthChallenge::Digest(challenge) => challenge,
            AuthChallenge::Other(other) => return Err(Error::UnknownScheme(other.scheme)),
        };

        // Following things can happen:
        // - We didn't respond to this challenge yet -> authenticate
        // - We did respond, but
        //     - The previous response has an outdated nonce, sets stale to `true` -> authenticate with new nonce
        //     - The new challenge has set a new nonce but hasn't set stale=true,
        //       this is a observed behavior from other implementations and happens
        //       when using any qop. To solve this issue, stale is ignored and the
        //       the nonce is compared directly.
        let previous_response = responses
            .iter()
            .find(|response| response.realm == challenge.realm);

        let authenticate = if let Some(previous_response) = previous_response {
            match &previous_response.response {
                AuthResponse::Digest(digest_response) => digest_response.nonce != challenge.nonce,
                AuthResponse::Other(_) => true,
            }
        } else {
            true
        };

        if authenticate {
            self.handle_digest_challenge(credentials, challenge, request_parts)
        } else {
            Err(Error::FailedToAuthenticate(challenge.realm))
        }
    }

    fn on_authorize_request(&mut self, response: &mut ResponseEntry) {
        let digest = match &mut response.response {
            AuthResponse::Digest(response) => response,
            AuthResponse::Other(_) => return,
        };

        // nc is already correct
        if response.use_count == 0 {
            return;
        }

        let digest_realm = &digest.realm;

        // qop response needs its nonce-count incremented and response re-calculated
        let qop_response = if let Some(qop_response) = &mut digest.qop_response {
            qop_response.nc += 1;
            qop_response
        } else {
            return;
        };

        let (_, qop_entry) = self
            .qop_responses
            .iter_mut()
            .find(|(realm, _)| realm == digest_realm)
            .expect("qop_entry must be some");

        let response = match qop_response.qop {
            QopOption::Auth | QopOption::AuthInt => (qop_entry.hash)(
                format!(
                    "{}:{}:{:08X}:{}:auth:{}",
                    qop_entry.ha1,
                    digest.nonce,
                    qop_response.nc,
                    qop_response.cnonce,
                    qop_entry.ha2
                )
                .as_bytes(),
            ),
            QopOption::Other(_) => unreachable!(),
        };

        digest.response = response.into();
    }
}

impl DigestAuthenticator {
    fn handle_digest_challenge(
        &mut self,
        credentials: &DigestCredentials,
        digest: DigestChallenge,
        request_parts: RequestParts<'_>,
    ) -> Result<AuthResponse, Error> {
        let (hash, is_session): (HashFn, bool) = match digest.algorithm {
            Algorithm::MD5 => {
                if self.reject_md5 {
                    return Err(Error::UnsupportedAlgorithm(BytesStr::from_static("MD5")));
                } else {
                    (hash_md5, false)
                }
            }
            Algorithm::MD5Sess => {
                if self.reject_md5 {
                    return Err(Error::UnsupportedAlgorithm(BytesStr::from_static("MD5")));
                } else {
                    (hash_md5, true)
                }
            }
            Algorithm::SHA256 => (hash_sha256, false),
            Algorithm::SHA256Sess => (hash_sha256, true),
            Algorithm::SHA512256 => (hash_sha512_trunc256, false),
            Algorithm::SHA512256Sess => (hash_sha512_trunc256, true),
            Algorithm::Other(other) => return Err(Error::UnsupportedAlgorithm(other)),
        };

        let response = self.digest_respond(digest, request_parts, credentials, is_session, hash)?;

        Ok(AuthResponse::Digest(response))
    }

    fn digest_respond(
        &mut self,
        mut challenge: DigestChallenge,
        request_parts: RequestParts<'_>,
        credentials: &DigestCredentials,
        is_session: bool,
        hash: HashFn,
    ) -> Result<DigestResponse, Error> {
        let cnonce = BytesStr::from(uuid::Uuid::new_v4().simple().to_string());

        let mut ha1 = hash(
            format!(
                "{}:{}:{}",
                credentials.user, challenge.realm, credentials.password
            )
            .as_bytes(),
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

                self.save_qop_response(&challenge.realm, ha1, ha2, hash);

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

                self.save_qop_response(&challenge.realm, ha1, ha2, hash);

                let qop_response = QopResponse {
                    qop: QopOption::Auth,
                    cnonce,
                    nc,
                };

                (response, Some(qop_response))
            } else {
                return Err(Error::UnsupportedQop);
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
                hash(format!("{}:{}", credentials.user, challenge.realm).as_bytes())
                    .as_str()
                    .into();

            Username::Username(username_hash)
        } else {
            Username::new(credentials.user.as_str().into())
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
        challenge_realm: &BytesStr,
        ha1: String,
        ha2: String,
        hash: HashFn,
    ) {
        let qop_entry = QopEntry { ha1, ha2, hash };

        if let Some((_, old_qop_entry)) = self
            .qop_responses
            .iter_mut()
            .find(|(realm, _)| realm == challenge_realm)
        {
            *old_qop_entry = qop_entry;
        } else {
            self.qop_responses
                .push((challenge_realm.clone(), qop_entry))
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::CredentialStore;
    use crate::UacAuthSession;
    use sip_types::msg::RequestLine;
    use sip_types::uri::sip::SipUri;
    use sip_types::Headers;
    use sip_types::Method;
    use sip_types::Name;

    fn test_credentials() -> CredentialStore {
        let mut store = CredentialStore::new();

        store.add_for_realm(
            "example.org",
            DigestCredentials::new("user123", "password123"),
        );

        store
    }

    #[test]
    fn digest_challenge() {
        let credentials = test_credentials();

        let mut headers = Headers::new();

        headers.insert_type(
            Name::WWW_AUTHENTICATE,
            &AuthChallenge::Digest(DigestChallenge {
                realm: "example.org".into(),
                domain: None,
                nonce: "YWmh5GFpoLjiTDCA1hTSSygkgdj99aHE".into(),
                opaque: None,
                stale: false,
                algorithm: Algorithm::MD5,
                qop: vec![],
                userhash: false,
                other: vec![],
            }),
        );

        let uri: SipUri = "sip:example.org".parse().unwrap();

        let line = RequestLine {
            method: Method::REGISTER,
            uri: Box::new(uri),
        };

        let mut session = UacAuthSession::<DigestAuthenticator>::default();

        session
            .handle_authenticate(
                &headers,
                &credentials,
                RequestParts {
                    line: &line,
                    headers: &Headers::new(),
                    body: &[],
                },
            )
            .unwrap();

        let mut response_headers = Headers::new();
        session.authorize_request(&mut response_headers);

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
                assert_eq!(algorithm, Algorithm::MD5);
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
        let credentials = test_credentials();

        let mut headers = Headers::new();

        headers.insert_type(
            Name::WWW_AUTHENTICATE,
            &AuthChallenge::Digest(DigestChallenge {
                realm: "example.org".into(),
                domain: None,
                nonce: "YWmh5GFpoLjiTDCA1hTSSygkgdj99aHE".into(),
                opaque: None,
                stale: false,
                algorithm: Algorithm::MD5,
                qop: vec![QopOption::AuthInt],
                userhash: false,
                other: vec![],
            }),
        );

        let uri: SipUri = "sip:example.org".parse().unwrap();

        let line = RequestLine {
            method: Method::REGISTER,
            uri: Box::new(uri),
        };

        let mut session = UacAuthSession::<DigestAuthenticator>::default();

        session
            .handle_authenticate(
                &headers,
                &credentials,
                RequestParts {
                    line: &line,
                    headers: &Headers::new(),
                    body: &[],
                },
            )
            .unwrap();

        let mut response_headers = Headers::new();
        session.authorize_request(&mut response_headers);

        let response = response_headers
            .get::<AuthResponse>(Name::AUTHORIZATION)
            .unwrap();

        let resp_value;

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
                assert_eq!(algorithm, Algorithm::MD5);
                assert_eq!(opaque, None);
                let qop_response = qop_response.unwrap();
                assert_eq!(qop_response.qop, QopOption::AuthInt);
                assert_eq!(qop_response.nc, 1);
                assert!(!userhash);
                assert_eq!(other, vec![]);
                resp_value = response;
            }
            _ => panic!("Expected digest"),
        }

        let mut response_headers = Headers::new();
        session.authorize_request(&mut response_headers);

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

                assert_eq!(algorithm, Algorithm::MD5);
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
