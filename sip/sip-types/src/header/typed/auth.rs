use crate::header::headers::OneOrMore;
use crate::header::{ExtendValues, HeaderParse};
use crate::parse::{parse_quoted, token, whitespace};
use crate::print::{AppendCtx, Print, PrintCtx};
use anyhow::{Context, bail};
use bytes::Bytes;
use bytesstr::BytesStr;
use internal::IResult;
use internal::ws;
use nom::branch::alt;
use nom::bytes::complete::{tag, take_while, take_while1};
use nom::combinator::{map, map_res};
use nom::multi::many0;
use nom::sequence::{preceded, tuple};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use std::borrow::Cow;
use std::fmt;
use std::fmt::{Display, Write};

// TODO: auth info header (https://datatracker.ietf.org/doc/html/rfc2617#section-3.2.3)

/// Param contained inside [Auth].
///
/// Has some special printing rules. Might not be hardcoded in the future.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthParam {
    pub name: BytesStr,
    pub value: BytesStr,
}

impl fmt::Display for AuthParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, r#"{}="{}""#, self.name, self.value)
    }
}

impl AuthParam {
    fn parse(src: &bytes::Bytes) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            map(
                ws((
                    take_while(token),
                    tag("="),
                    alt((parse_quoted, take_while(token))),
                )),
                move |(name, _, value)| AuthParam {
                    name: BytesStr::from_parse(src, name),
                    value: BytesStr::from_parse(src, value),
                },
            )(i)
        }
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum AuthChallenge {
    Digest(DigestChallenge),
    Other(Auth),
}

impl HeaderParse for AuthChallenge {
    fn parse<'i>(src: &'i Bytes, i: &'i str) -> IResult<&'i str, Self> {
        map_res(
            parse_auth_params(src),
            |(scheme, params)| -> anyhow::Result<Self> {
                match scheme.as_ref() {
                    "Digest" => Ok(Self::Digest(DigestChallenge::from_auth_params(params)?)),
                    _ => Ok(Self::Other(Auth { scheme, params })),
                }
            },
        )(i)
    }
}

impl ExtendValues for AuthChallenge {
    fn extend_values(&self, ctx: PrintCtx<'_>, values: &mut OneOrMore) {
        values.push(self.print_ctx(ctx).to_string().into());
    }

    fn create_values(&self, ctx: PrintCtx<'_>) -> OneOrMore {
        OneOrMore::One(self.print_ctx(ctx).to_string().into())
    }
}

impl Print for AuthChallenge {
    fn print(&self, f: &mut fmt::Formatter<'_>, ctx: PrintCtx<'_>) -> fmt::Result {
        match self {
            AuthChallenge::Digest(digest) => digest.print(f, ctx),
            AuthChallenge::Other(other) => other.print(f, ctx),
        }
    }
}

#[derive(Debug, Clone)]
pub struct DigestChallenge {
    pub realm: BytesStr,
    pub domain: Option<BytesStr>, // TODO: this may be a vec. See (https://datatracker.ietf.org/doc/html/rfc2617#section-3.2.1, https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/WWW-Authenticate)
    pub nonce: BytesStr,
    pub opaque: Option<BytesStr>,
    pub stale: bool,
    pub algorithm: Algorithm,
    pub qop: Vec<QopOption>,
    pub userhash: bool,
    // TODO: add charset? https://datatracker.ietf.org/doc/html/rfc7616#section-4
    /// Remaining fields
    pub other: Vec<AuthParam>,
}

impl DigestChallenge {
    pub(crate) fn from_auth_params(params: Vec<AuthParam>) -> anyhow::Result<Self> {
        let mut realm = None;
        let mut domain = None;
        let mut nonce = None;
        let mut opaque = None;
        let mut stale = false;
        let mut algorithm = Algorithm::AlgorithmValue(AlgorithmValue::MD5);
        let mut qop = vec![];
        let mut userhash = false;
        let mut other = vec![];

        for param in params {
            match param.name.as_ref() {
                "realm" => realm = Some(param.value),
                "domain" => domain = Some(param.value),
                "nonce" => nonce = Some(param.value),
                "opaque" => opaque = Some(param.value),
                "stale" => stale = param.value.eq_ignore_ascii_case("true"),
                "algorithm" => algorithm = Algorithm::from(param.value),
                "qop" => qop.extend(
                    param
                        .value
                        .split(',')
                        .map(|v| QopOption::from(param.value.slice_ref(v.trim()))),
                ),
                "userhash" => userhash = param.value.eq_ignore_ascii_case("true"),
                _ => other.push(param),
            }
        }

        Ok(Self {
            realm: realm.context("Missing realm in authenticate header")?,
            domain,
            nonce: nonce.context("Missing nonce in authenticate header")?,
            opaque,
            stale,
            algorithm,
            qop,
            userhash,
            other,
        })
    }
}

impl ExtendValues for DigestChallenge {
    fn extend_values(&self, ctx: PrintCtx<'_>, values: &mut OneOrMore) {
        values.push(self.print_ctx(ctx).to_string().into());
    }

    fn create_values(&self, ctx: PrintCtx<'_>) -> OneOrMore {
        OneOrMore::One(self.print_ctx(ctx).to_string().into())
    }
}

impl Print for DigestChallenge {
    fn print(&self, f: &mut fmt::Formatter<'_>, _ctx: PrintCtx<'_>) -> fmt::Result {
        write!(
            f,
            r#"Digest realm="{}", nonce="{}""#,
            self.realm, self.nonce,
        )?;

        if let Some(domain) = &self.domain {
            write!(f, r#", domain="{}""#, domain)?;
        }

        if let Some(opaque) = &self.opaque {
            write!(f, r#", opaque="{}""#, opaque)?;
        }

        if self.stale {
            f.write_str(", stale=true")?;
        }

        if !matches!(
            self.algorithm,
            Algorithm::AlgorithmValue(AlgorithmValue::MD5)
        ) {
            write!(f, ", algorithm={}", self.algorithm)?;
        }

        let mut qop_iter = self.qop.iter();

        if let Some(first) = qop_iter.next() {
            write!(f, r#", qop="{}"#, first)?;

            for qop_option in qop_iter {
                write!(f, ",{}", qop_option)?;
            }

            f.write_char('"')?;
        }

        if self.userhash {
            f.write_str(", userhash=true")?;
        }

        for param in &self.other {
            write!(f, ", {}", param)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
#[allow(clippy::large_enum_variant)]
pub enum AuthResponse {
    Digest(DigestResponse),
    Other(Auth),
}

impl HeaderParse for AuthResponse {
    fn parse<'i>(src: &'i Bytes, i: &'i str) -> IResult<&'i str, Self> {
        map_res(
            parse_auth_params(src),
            |(scheme, params)| -> anyhow::Result<Self> {
                match scheme.as_ref() {
                    "Digest" => Ok(Self::Digest(DigestResponse::from_auth_params(params)?)),
                    _ => Ok(Self::Other(Auth { scheme, params })),
                }
            },
        )(i)
    }
}

impl ExtendValues for AuthResponse {
    fn extend_values(&self, ctx: PrintCtx<'_>, values: &mut OneOrMore) {
        values.push(self.print_ctx(ctx).to_string().into());
    }

    fn create_values(&self, ctx: PrintCtx<'_>) -> OneOrMore {
        OneOrMore::One(self.print_ctx(ctx).to_string().into())
    }
}

impl Print for AuthResponse {
    fn print(&self, f: &mut fmt::Formatter<'_>, ctx: PrintCtx<'_>) -> fmt::Result {
        match self {
            AuthResponse::Digest(digest) => digest.print(f, ctx),
            AuthResponse::Other(other) => other.print(f, ctx),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Username {
    Username(BytesStr),
    UsernameNonASCII(BytesStr),
}

const CHARSET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'!')
    .remove(b'#')
    .remove(b'$')
    .remove(b'&')
    .remove(b'+')
    .remove(b'-')
    .remove(b'.')
    .remove(b'^')
    .remove(b'_')
    .remove(b'`')
    .remove(b'|')
    .remove(b'~');

impl Username {
    /// Create a new [`Username`]
    ///
    /// Determines the variant and encodes non ascii usernames with utf8 percentage encoding.
    pub fn new(username: BytesStr) -> Self {
        let maybe_encoded = utf8_percent_encode(&username, CHARSET).into();

        match maybe_encoded {
            Cow::Borrowed(_) => Username::Username(username),
            Cow::Owned(encoded) => {
                let username_encoded = format!("UTF-8''{}", encoded).into();

                Username::UsernameNonASCII(username_encoded)
            }
        }
    }
}

impl Display for Username {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Username::Username(username) => {
                write!(f, r#"username="{}""#, username)
            }
            Username::UsernameNonASCII(username_non_ascii) => {
                write!(f, r#"username*={}"#, username_non_ascii)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct DigestResponse {
    pub username: Username,
    pub realm: BytesStr,
    pub nonce: BytesStr,
    pub uri: BytesStr,
    pub response: BytesStr,
    pub algorithm: Algorithm,
    pub opaque: Option<BytesStr>,
    pub qop_response: Option<QopResponse>,
    pub userhash: bool,
    /// Remaining fields
    pub other: Vec<AuthParam>,
}

impl DigestResponse {
    pub(crate) fn from_auth_params(params: Vec<AuthParam>) -> anyhow::Result<Self> {
        let mut username = None;
        let mut username_non_ascii = None;
        let mut realm = None;
        let mut nonce = None;
        let mut uri = None;
        let mut response = None;
        let mut algorithm = Algorithm::AlgorithmValue(AlgorithmValue::MD5);
        let mut opaque = None;

        // qop related params
        let mut qop = None;
        let mut cnonce = None;
        let mut nc = None;

        let mut userhash = false;

        let mut other = vec![];

        for param in params {
            match param.name.as_ref() {
                "username" => username = Some(param.value),
                "username*" => username_non_ascii = Some(param.value),
                "realm" => realm = Some(param.value),
                "nonce" => nonce = Some(param.value),
                "uri" => uri = Some(param.value),
                "response" => response = Some(param.value),
                "algorithm" => algorithm = Algorithm::from(param.value),
                "opaque" => opaque = Some(param.value),
                "qop" => qop = Some(QopOption::from(param.value)),
                "cnonce" => cnonce = Some(param.value),
                "nc" => nc = Some(u32::from_str_radix(param.value.as_ref(), 16)),
                "userhash" => userhash = param.value.eq_ignore_ascii_case("true"),
                _ => other.push(param),
            }
        }

        let qop_response = if let Some(qop) = qop {
            Some(QopResponse {
                qop,
                cnonce: cnonce.context("Missing cnonce in authorization header")?,
                nc: nc
                    .context("Missing nc in authorization header")?
                    .context("Failed to parse nc value")?,
            })
        } else {
            None
        };

        if username.is_some() && username_non_ascii.is_some() {
            bail!("Received both, 'username' and 'username*' in authorization header");
        }

        let username = if let Some(username) = username {
            Username::Username(username)
        } else if let Some(username_non_ascii) = username_non_ascii {
            if userhash {
                bail!("Received 'userhash=true' and 'username*' in authorization header");
            }

            Username::UsernameNonASCII(username_non_ascii)
        } else {
            bail!("Missing username in authorization header");
        };

        Ok(Self {
            username,
            realm: realm.context("Missing realm in authorization header")?,
            nonce: nonce.context("Missing nonce in authorization header")?,
            uri: uri.context("Missing uri in authorization header")?,
            response: response.context("Missing response in authorization header")?,
            algorithm,
            opaque,
            qop_response,
            userhash,
            other,
        })
    }
}

impl ExtendValues for DigestResponse {
    fn extend_values(&self, ctx: PrintCtx<'_>, values: &mut OneOrMore) {
        values.push(self.print_ctx(ctx).to_string().into());
    }

    fn create_values(&self, ctx: PrintCtx<'_>) -> OneOrMore {
        OneOrMore::One(self.print_ctx(ctx).to_string().into())
    }
}

impl Print for DigestResponse {
    fn print(&self, f: &mut fmt::Formatter<'_>, _ctx: PrintCtx<'_>) -> fmt::Result {
        write!(
            f,
            r#"Digest {}, realm="{}", nonce="{}", uri="{}", response="{}""#,
            self.username, self.realm, self.nonce, self.uri, self.response
        )?;

        if !matches!(
            self.algorithm,
            Algorithm::AlgorithmValue(AlgorithmValue::MD5)
        ) {
            write!(f, ", algorithm={}", self.algorithm)?;
        }

        if let Some(opaque) = &self.opaque {
            write!(f, r#", opaque="{}""#, opaque)?;
        }

        if let Some(qop_response) = &self.qop_response {
            write!(
                f,
                r#", qop="{}", cnonce="{}", nc={:08X}"#,
                qop_response.qop, qop_response.cnonce, qop_response.nc
            )?;
        }

        if self.userhash {
            f.write_str(", userhash=true")?;
        }

        for param in &self.other {
            write!(f, ", {}", param)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QopResponse {
    pub qop: QopOption,
    pub cnonce: BytesStr,
    pub nc: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QopOption {
    Auth,
    AuthInt,
    Other(BytesStr),
}

impl From<BytesStr> for QopOption {
    fn from(value: BytesStr) -> Self {
        match value.as_ref() {
            "auth" => Self::Auth,
            "auth-int" => Self::AuthInt,
            token => Self::Other(value.slice_ref(token)),
        }
    }
}

impl Display for QopOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QopOption::Auth => f.write_str("auth"),
            QopOption::AuthInt => f.write_str("auth-int"),
            QopOption::Other(token) => f.write_str(token),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Algorithm {
    AkaNamespace((AkaVersion, AlgorithmValue)),
    AlgorithmValue(AlgorithmValue),
}

impl From<BytesStr> for Algorithm {
    fn from(value: BytesStr) -> Self {
        // Check if it is an aka-namespace
        if let Some((version, algorithm)) = value.split_once('-') {
            // 5 characters, starting with case-insensitive "AKAv", followed by single-digit number
            if version.len() == 5
                && version[0..4].eq_ignore_ascii_case("AKAv")
                && version.as_bytes()[4].is_ascii_digit()
            {
                return Algorithm::AkaNamespace((
                    AkaVersion::from(BytesStr::from(version)),
                    AlgorithmValue::from(BytesStr::from(algorithm)),
                ));
            }
        }
        // Otherwise, is only an algorithm-value
        Algorithm::AlgorithmValue(AlgorithmValue::from(value))
    }
}

impl Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Algorithm::AlgorithmValue(algorithm) => write!(f, "{}", algorithm),
            Algorithm::AkaNamespace((version, algorithm)) => write!(f, "{}-{}", version, algorithm),
        }
    }
}

/// AKA versions
/// <https://www.iana.org/assignments/aka-version-namespace/aka-version-namespace.xhtml>
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AkaVersion {
    /// <https://datatracker.ietf.org/doc/html/rfc3310>
    AKAv1,
    /// <https://datatracker.ietf.org/doc/html/rfc4169>
    AKAv2,
    Other(BytesStr),
}

impl From<BytesStr> for AkaVersion {
    fn from(value: BytesStr) -> Self {
        if value.eq_ignore_ascii_case("AKAv1") {
            AkaVersion::AKAv1
        } else if value.eq_ignore_ascii_case("AKAv2") {
            AkaVersion::AKAv2
        } else {
            AkaVersion::Other(value)
        }
    }
}

impl fmt::Display for AkaVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AkaVersion::AKAv1 => f.write_str("AKAv1"),
            AkaVersion::AKAv2 => f.write_str("AKAv2"),
            AkaVersion::Other(other) => f.write_str(other),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlgorithmValue {
    MD5,
    MD5Sess,
    SHA256,
    SHA256Sess,
    SHA512256,
    SHA512256Sess,
    Other(BytesStr),
}

impl From<BytesStr> for AlgorithmValue {
    fn from(value: BytesStr) -> Self {
        if value.eq_ignore_ascii_case("MD5") {
            AlgorithmValue::MD5
        } else if value.eq_ignore_ascii_case("MD5-sess") {
            AlgorithmValue::MD5Sess
        } else if value.eq_ignore_ascii_case("SHA-256") {
            AlgorithmValue::SHA256
        } else if value.eq_ignore_ascii_case("SHA-256-sess") {
            AlgorithmValue::SHA256Sess
        } else if value.eq_ignore_ascii_case("SHA-512-256") {
            AlgorithmValue::SHA512256
        } else if value.eq_ignore_ascii_case("SHA-512-256-sess") {
            AlgorithmValue::SHA512256Sess
        } else {
            AlgorithmValue::Other(value)
        }
    }
}

impl fmt::Display for AlgorithmValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AlgorithmValue::MD5 => f.write_str("MD5"),
            AlgorithmValue::MD5Sess => f.write_str("MD5-sess"),
            AlgorithmValue::SHA256 => f.write_str("SHA-256"),
            AlgorithmValue::SHA256Sess => f.write_str("SHA-256-sess"),
            AlgorithmValue::SHA512256 => f.write_str("SHA-512-256"),
            AlgorithmValue::SHA512256Sess => f.write_str("SHA-512-256-sess"),
            AlgorithmValue::Other(other) => f.write_str(other),
        }
    }
}

fn parse_auth_params(
    src: &Bytes,
) -> impl Fn(&str) -> IResult<&str, (BytesStr, Vec<AuthParam>)> + '_ {
    move |i| {
        tuple((
            map(take_while1(|c| !whitespace(c)), |scheme| {
                BytesStr::from_parse(src, scheme)
            }),
            preceded(
                take_while(whitespace),
                map(
                    tuple((
                        AuthParam::parse(src),
                        many0(map(ws((tag(","), AuthParam::parse(src))), |(_, scheme)| {
                            scheme
                        })),
                    )),
                    |(first_param, mut v)| {
                        v.insert(0, first_param);
                        v
                    },
                ),
            ),
        ))(i)
    }
}

/// Implementation for all Auth kind headers.
#[derive(Debug, Clone)]
pub struct Auth {
    pub scheme: BytesStr,
    pub params: Vec<AuthParam>,
}

impl Print for Auth {
    fn print(&self, f: &mut fmt::Formatter<'_>, _: PrintCtx<'_>) -> fmt::Result {
        write!(f, "{} ", self.scheme)?;

        let mut params = self.params.iter();

        if let Some(param) = params.next() {
            write!(f, "{}", param)?;

            for param in params {
                write!(f, ", {}", param)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::print::AppendCtx;
    use crate::{Headers, Name};

    #[test]
    fn parse_simple_digest_challenge() {
        let input = BytesStr::from_static(r#"Digest realm="example.com", nonce="abc123""#);

        let (rem, auth) = AuthChallenge::parse(input.as_ref(), &input).unwrap();

        match auth {
            AuthChallenge::Digest(DigestChallenge {
                realm,
                domain,
                nonce,
                opaque,
                stale,
                algorithm,
                qop,
                userhash,
                other,
            }) => {
                assert_eq!(realm, "example.com");
                assert_eq!(domain, None);
                assert_eq!(nonce, "abc123");
                assert_eq!(opaque, None);
                assert!(!stale);
                assert_eq!(algorithm, Algorithm::AlgorithmValue(AlgorithmValue::MD5));
                assert_eq!(qop, vec![]);
                assert!(!userhash);
                assert!(other.is_empty())
            }
            _ => panic!(),
        }

        assert_eq!(rem, "");
    }

    #[test]
    fn print_simple_digest_challenge() {
        let challenge = AuthChallenge::Digest(DigestChallenge {
            realm: BytesStr::from_static("example.com"),
            domain: None,
            nonce: BytesStr::from_static("abc123"),
            opaque: None,
            stale: false,
            algorithm: Algorithm::AlgorithmValue(AlgorithmValue::MD5),
            qop: vec![],
            userhash: false,
            other: vec![],
        });

        let expected = r#"Digest realm="example.com", nonce="abc123""#;

        assert_eq!(expected, challenge.default_print_ctx().to_string());
    }

    #[test]
    fn parse_digest_aka_challenge() {
        let input = BytesStr::from_static(
            r#"Digest realm="example.com", nonce="abc123", algorithm="AKAv1-MD5""#,
        );

        let (rem, auth) = AuthChallenge::parse(input.as_ref(), &input).unwrap();

        match auth {
            AuthChallenge::Digest(DigestChallenge {
                realm,
                domain,
                nonce,
                opaque,
                stale,
                algorithm,
                qop,
                userhash,
                other,
            }) => {
                assert_eq!(realm, "example.com");
                assert_eq!(domain, None);
                assert_eq!(nonce, "abc123");
                assert_eq!(opaque, None);
                assert!(!stale);
                assert_eq!(
                    algorithm,
                    Algorithm::AkaNamespace((AkaVersion::AKAv1, AlgorithmValue::MD5))
                );
                assert_eq!(qop, vec![]);
                assert!(!userhash);
                assert!(other.is_empty())
            }
            _ => panic!(),
        }

        assert_eq!(rem, "");

        let input = BytesStr::from_static(
            r#"Digest realm="example.com", nonce="abc123", algorithm="AKAv2-SHA-256""#,
        );

        let (rem, auth) = AuthChallenge::parse(input.as_ref(), &input).unwrap();

        match auth {
            AuthChallenge::Digest(DigestChallenge {
                realm,
                domain,
                nonce,
                opaque,
                stale,
                algorithm,
                qop,
                userhash,
                other,
            }) => {
                assert_eq!(realm, "example.com");
                assert_eq!(domain, None);
                assert_eq!(nonce, "abc123");
                assert_eq!(opaque, None);
                assert!(!stale);
                assert_eq!(
                    algorithm,
                    Algorithm::AkaNamespace((AkaVersion::AKAv2, AlgorithmValue::SHA256))
                );
                assert_eq!(qop, vec![]);
                assert!(!userhash);
                assert!(other.is_empty())
            }
            _ => panic!(),
        }

        assert_eq!(rem, "");

        let input = BytesStr::from_static(
            r#"Digest realm="example.com", nonce="abc123", algorithm="AKAv3-SHA-512-256-sess""#,
        );

        let (rem, auth) = AuthChallenge::parse(input.as_ref(), &input).unwrap();

        match auth {
            AuthChallenge::Digest(DigestChallenge {
                realm,
                domain,
                nonce,
                opaque,
                stale,
                algorithm,
                qop,
                userhash,
                other,
            }) => {
                assert_eq!(realm, "example.com");
                assert_eq!(domain, None);
                assert_eq!(nonce, "abc123");
                assert_eq!(opaque, None);
                assert!(!stale);
                assert_eq!(
                    algorithm,
                    Algorithm::AkaNamespace((
                        AkaVersion::Other(BytesStr::from_static("AKAv3")),
                        AlgorithmValue::SHA512256Sess
                    ))
                );
                assert_eq!(qop, vec![]);
                assert!(!userhash);
                assert!(other.is_empty())
            }
            _ => panic!(),
        }

        assert_eq!(rem, "");

        let input = BytesStr::from_static(
            r#"Digest realm="example.com", nonce="abc123", algorithm="AKA-ABC123""#,
        );

        let (rem, auth) = AuthChallenge::parse(input.as_ref(), &input).unwrap();

        match auth {
            AuthChallenge::Digest(DigestChallenge {
                realm,
                domain,
                nonce,
                opaque,
                stale,
                algorithm,
                qop,
                userhash,
                other,
            }) => {
                assert_eq!(realm, "example.com");
                assert_eq!(domain, None);
                assert_eq!(nonce, "abc123");
                assert_eq!(opaque, None);
                assert!(!stale);
                assert_eq!(
                    algorithm,
                    Algorithm::AlgorithmValue(AlgorithmValue::Other(BytesStr::from_static(
                        "AKA-ABC123"
                    )))
                );
                assert_eq!(qop, vec![]);
                assert!(!userhash);
                assert!(other.is_empty())
            }
            _ => panic!(),
        }

        assert_eq!(rem, "");

        let input = BytesStr::from_static(
            r#"Digest realm="example.com", nonce="abc123", algorithm="AKAvX-ABC123""#,
        );

        let (rem, auth) = AuthChallenge::parse(input.as_ref(), &input).unwrap();

        match auth {
            AuthChallenge::Digest(DigestChallenge {
                realm,
                domain,
                nonce,
                opaque,
                stale,
                algorithm,
                qop,
                userhash,
                other,
            }) => {
                assert_eq!(realm, "example.com");
                assert_eq!(domain, None);
                assert_eq!(nonce, "abc123");
                assert_eq!(opaque, None);
                assert!(!stale);
                assert_eq!(
                    algorithm,
                    Algorithm::AlgorithmValue(AlgorithmValue::Other(BytesStr::from_static(
                        "AKAvX-ABC123"
                    )))
                );
                assert_eq!(qop, vec![]);
                assert!(!userhash);
                assert!(other.is_empty())
            }
            _ => panic!(),
        }

        assert_eq!(rem, "");
    }

    #[test]
    fn all_fields_digest_challenge() {
        let input = BytesStr::from_static(
            r#"Digest realm="example.com", domain="TODO", nonce="abc123", opaque="opaque_value", stale=true, algorithm=SHA-256, qop="auth,auth-int,a_token", another-field="some_extension""#,
        );

        let (rem, auth) = AuthChallenge::parse(input.as_ref(), &input).unwrap();

        match auth {
            AuthChallenge::Digest(DigestChallenge {
                realm,
                domain,
                nonce,
                opaque,
                stale,
                algorithm,
                qop,
                userhash,
                other,
            }) => {
                assert_eq!(realm, "example.com");
                assert_eq!(domain, Some(BytesStr::from_static("TODO")));
                assert_eq!(nonce, "abc123");
                assert_eq!(opaque, Some(BytesStr::from_static("opaque_value")));
                assert!(stale);
                assert_eq!(algorithm, Algorithm::AlgorithmValue(AlgorithmValue::SHA256));
                assert_eq!(
                    qop,
                    vec![
                        QopOption::Auth,
                        QopOption::AuthInt,
                        QopOption::Other(BytesStr::from_static("a_token"))
                    ]
                );
                assert!(!userhash);
                assert_eq!(other.len(), 1);
                assert_eq!(
                    other[0],
                    AuthParam {
                        name: BytesStr::from_static("another-field"),
                        value: BytesStr::from_static("some_extension")
                    }
                );
            }
            _ => panic!(),
        }

        assert_eq!(rem, "");
    }

    #[test]
    fn print_all_fields_digest_challenge() {
        let challenge = AuthChallenge::Digest(DigestChallenge {
            realm: BytesStr::from_static("example.com"),
            domain: Some(BytesStr::from_static("TODO")),
            nonce: BytesStr::from_static("abc123"),
            opaque: Some(BytesStr::from_static("opaque_value")),
            stale: true,
            algorithm: Algorithm::AlgorithmValue(AlgorithmValue::SHA256),
            qop: vec![
                QopOption::Auth,
                QopOption::AuthInt,
                QopOption::Other(BytesStr::from_static("a_token")),
            ],
            userhash: false,
            other: vec![AuthParam {
                name: BytesStr::from_static("another-field"),
                value: BytesStr::from_static("some_extension"),
            }],
        });

        let expected = r#"Digest realm="example.com", nonce="abc123", domain="TODO", opaque="opaque_value", stale=true, algorithm=SHA-256, qop="auth,auth-int,a_token", another-field="some_extension""#;

        assert_eq!(expected, challenge.default_print_ctx().to_string());
    }

    #[test]
    fn parse_multiple_digest_challenge() {
        let mut headers = Headers::new();
        headers.insert(Name::WWW_AUTHENTICATE, "Digest realm=\"example.com\", nonce=\"abc123\", Digest realm=\"example.org\", nonce=\"123abc\", OAuth some-field=\"oauth_field\"");
        headers.insert(
            Name::WWW_AUTHENTICATE,
            "Digest realm=\"example.net\", nonce=\"xyz987\", algorithm=\"SHA-256\"",
        );

        let www_vec = headers
            .get::<Vec<AuthChallenge>>(Name::WWW_AUTHENTICATE)
            .unwrap();

        match &www_vec[0] {
            AuthChallenge::Digest(DigestChallenge {
                realm,
                domain,
                nonce,
                opaque,
                stale,
                algorithm,
                qop,
                userhash,
                other,
            }) => {
                assert_eq!(realm, "example.com");
                assert_eq!(domain, &None);
                assert_eq!(algorithm, &Algorithm::AlgorithmValue(AlgorithmValue::MD5));
                assert_eq!(nonce, "abc123");
                assert_eq!(opaque, &None);
                assert_eq!(stale, &false);
                assert_eq!(qop, &vec![]);
                assert_eq!(userhash, &false);
                assert!(other.is_empty());
            }
            _ => panic!(),
        }

        match &www_vec[1] {
            AuthChallenge::Digest(DigestChallenge {
                realm,
                domain,
                nonce,
                opaque,
                stale,
                algorithm,
                qop,
                userhash,
                other,
            }) => {
                assert_eq!(realm, "example.org");
                assert_eq!(domain, &None);
                assert_eq!(algorithm, &Algorithm::AlgorithmValue(AlgorithmValue::MD5));
                assert_eq!(nonce, "123abc");
                assert_eq!(opaque, &None);
                assert_eq!(stale, &false);
                assert_eq!(qop, &vec![]);
                assert_eq!(userhash, &false);
                assert!(other.is_empty());
            }
            _ => panic!(),
        }

        match &www_vec[2] {
            AuthChallenge::Other(Auth { scheme, params }) => {
                assert_eq!(scheme, "OAuth");
                assert_eq!(params[0].name, "some-field");
                assert_eq!(params[0].value, "oauth_field");
            }
            _ => panic!(),
        }

        match &www_vec[3] {
            AuthChallenge::Digest(DigestChallenge {
                realm,
                domain,
                nonce,
                opaque,
                stale,
                algorithm,
                qop,
                userhash,
                other,
            }) => {
                assert_eq!(realm, "example.net");
                assert_eq!(domain, &None);
                assert_eq!(nonce, "xyz987");
                assert_eq!(opaque, &None);
                assert_eq!(stale, &false);
                assert_eq!(
                    algorithm,
                    &Algorithm::AlgorithmValue(AlgorithmValue::SHA256)
                );
                assert_eq!(qop, &vec![]);
                assert_eq!(userhash, &false);
                assert!(other.is_empty());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn parse_qop_digest_challenge_with_whitespace() {
        let input = BytesStr::from_static(
            "Digest realm=\"example.com\", nonce=\"abc123\", qop=\"auth, auth-int  , AuTh-Int\"",
        );

        let (rem, auth) = AuthChallenge::parse(input.as_ref(), &input).unwrap();

        match auth {
            AuthChallenge::Digest(DigestChallenge {
                realm,
                domain,
                nonce,
                opaque,
                stale,
                algorithm,
                qop,
                userhash,
                other,
            }) => {
                assert_eq!(realm, "example.com");
                assert_eq!(domain, None);
                assert_eq!(nonce, "abc123");
                assert_eq!(algorithm, Algorithm::AlgorithmValue(AlgorithmValue::MD5));
                assert_eq!(opaque, None);
                assert!(!stale);
                assert_eq!(
                    qop,
                    vec![
                        QopOption::Auth,
                        QopOption::AuthInt,
                        QopOption::Other(BytesStr::from_static("AuTh-Int")),
                    ]
                );
                assert!(!userhash);
                assert!(other.is_empty());
            }
            _ => panic!(),
        }

        assert_eq!(rem, "");
    }

    #[test]
    fn parse_simple_digest_response() {
        let input = BytesStr::from_static(
            r#"Digest username="alice", realm="example.com", nonce="abc123", uri="sip:bob@example.com", response="00000000000000000000000000000000""#,
        );

        let (rem, auth) = AuthResponse::parse(input.as_ref(), &input).unwrap();

        assert!(rem.is_empty());

        match auth {
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
                assert_eq!(username, Username::Username("alice".into()));
                assert_eq!(realm, "example.com");
                assert_eq!(nonce, "abc123");
                assert_eq!(uri, "sip:bob@example.com");
                assert_eq!(response, "00000000000000000000000000000000");
                assert_eq!(algorithm, Algorithm::AlgorithmValue(AlgorithmValue::MD5));
                assert_eq!(opaque, None);
                assert_eq!(qop_response, None);
                assert!(!userhash);
                assert!(other.is_empty());
            }
            AuthResponse::Other(_) => panic!(),
        }
    }

    #[test]
    fn print_simple_digest_response() {
        let digest = AuthResponse::Digest(DigestResponse {
            username: Username::new("alice".into()),
            realm: BytesStr::from_static("example.com"),
            nonce: BytesStr::from_static("abc123"),
            uri: BytesStr::from_static("sip:bob@example.com"),
            response: BytesStr::from_static("00000000000000000000000000000000"),
            algorithm: Algorithm::AlgorithmValue(AlgorithmValue::MD5),
            opaque: None,
            qop_response: None,
            userhash: false,
            other: vec![],
        });

        let expected = r#"Digest username="alice", realm="example.com", nonce="abc123", uri="sip:bob@example.com", response="00000000000000000000000000000000""#;

        assert_eq!(expected, digest.default_print_ctx().to_string());
    }

    #[test]
    fn parse_all_fields_digest_response() {
        let input = BytesStr::from_static(
            r#"Digest username="alice", realm="example.com", nonce="abc123", uri="sip:bob@example.com", response="00000000000000000000000000000000", algorithm=SHA-256, opaque="opaque_value", qop="auth", cnonce="def456", nc=00000001, another-field="some_extension""#,
        );

        let (rem, auth) = AuthResponse::parse(input.as_ref(), &input).unwrap();

        match auth {
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
                assert_eq!(username, Username::Username("alice".into()));
                assert_eq!(realm, "example.com");
                assert_eq!(nonce, "abc123");
                assert_eq!(uri, "sip:bob@example.com");
                assert_eq!(response, "00000000000000000000000000000000");
                assert_eq!(algorithm, Algorithm::AlgorithmValue(AlgorithmValue::SHA256));
                assert_eq!(opaque, Some(BytesStr::from_static("opaque_value")));
                assert_eq!(
                    qop_response,
                    Some(QopResponse {
                        qop: QopOption::Auth,
                        cnonce: BytesStr::from_static("def456"),
                        nc: 1
                    })
                );
                assert!(!userhash);
                assert_eq!(
                    other[0],
                    AuthParam {
                        name: BytesStr::from_static("another-field"),
                        value: BytesStr::from_static("some_extension"),
                    }
                );
            }
            AuthResponse::Other(_) => panic!(),
        }

        assert_eq!(rem, "");
    }

    #[test]
    fn print_all_fields_digest_response() {
        let digest = AuthResponse::Digest(DigestResponse {
            username: Username::new("alice".into()),
            realm: BytesStr::from_static("example.com"),
            nonce: BytesStr::from_static("abc123"),
            uri: BytesStr::from_static("sip:bob@example.com"),
            response: BytesStr::from_static("00000000000000000000000000000000"),
            algorithm: Algorithm::AlgorithmValue(AlgorithmValue::SHA256),
            opaque: Some(BytesStr::from_static("opaque_value")),
            qop_response: Some(QopResponse {
                qop: QopOption::Auth,
                cnonce: BytesStr::from_static("def456"),
                nc: 1,
            }),
            userhash: false,
            other: vec![AuthParam {
                name: BytesStr::from_static("another-field"),
                value: BytesStr::from_static("some_extension"),
            }],
        });

        let expected = r#"Digest username="alice", realm="example.com", nonce="abc123", uri="sip:bob@example.com", response="00000000000000000000000000000000", algorithm=SHA-256, opaque="opaque_value", qop="auth", cnonce="def456", nc=00000001, another-field="some_extension""#;

        assert_eq!(expected, digest.default_print_ctx().to_string());
    }

    #[test]
    fn parse_qop_auth_int_digest_response() {
        let input = BytesStr::from_static(
            r#"Digest username="alice", realm="example.com", nonce="abc123", uri="sip:bob@example.com", response="00000000000000000000000000000000", qop="auth-int", cnonce="def456", nc=00000001"#,
        );

        let (rem, auth) = AuthResponse::parse(input.as_ref(), &input).unwrap();

        match auth {
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
                assert_eq!(username, Username::Username("alice".into()));
                assert_eq!(realm, "example.com");
                assert_eq!(nonce, "abc123");
                assert_eq!(uri, "sip:bob@example.com");
                assert_eq!(response, "00000000000000000000000000000000");
                assert_eq!(algorithm, Algorithm::AlgorithmValue(AlgorithmValue::MD5));
                assert_eq!(opaque, None);
                assert_eq!(
                    qop_response,
                    Some(QopResponse {
                        qop: QopOption::AuthInt,
                        cnonce: BytesStr::from_static("def456"),
                        nc: 1,
                    })
                );
                assert!(!userhash);
                assert!(other.is_empty());
            }
            AuthResponse::Other(_) => panic!(),
        }

        assert_eq!(rem, "");
    }

    #[test]
    fn parse_qop_auth_token_digest_response() {
        let input = BytesStr::from_static(
            r#"Digest username="alice", realm="example.com", nonce="abc123", uri="sip:bob@example.com", response="00000000000000000000000000000000", qop="a_token", cnonce="def456", nc=00000001"#,
        );

        let (rem, auth) = AuthResponse::parse(input.as_ref(), &input).unwrap();

        match auth {
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
                assert_eq!(username, Username::Username("alice".into()));
                assert_eq!(realm, "example.com");
                assert_eq!(nonce, "abc123");
                assert_eq!(uri, "sip:bob@example.com");
                assert_eq!(response, "00000000000000000000000000000000");
                assert_eq!(algorithm, Algorithm::AlgorithmValue(AlgorithmValue::MD5));
                assert_eq!(opaque, None);
                assert_eq!(
                    qop_response,
                    Some(QopResponse {
                        qop: QopOption::Other(BytesStr::from_static("a_token")),
                        cnonce: BytesStr::from_static("def456"),
                        nc: 1,
                    })
                );
                assert!(!userhash);
                assert!(other.is_empty());
            }
            AuthResponse::Other(_) => panic!(),
        }

        assert_eq!(rem, "");
    }

    #[test]
    fn test_username_encoding_spaces() {
        let name_str = "Oh Long Johnson";

        let username = Username::new(name_str.into()).to_string();

        assert_eq!(username, "username*=UTF-8''Oh%20Long%20Johnson")
    }

    #[test]
    fn test_username_encoding_alphanumeric() {
        let name_str = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

        let username = Username::new(name_str.into()).to_string();

        assert_eq!(
            username,
            r#"username="1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ""#
        )
    }

    #[test]
    fn test_username_encoding_allowed_special_chars() {
        let name_str = "!#$&+-.^_`|~";

        let username = Username::new(name_str.into()).to_string();

        assert_eq!(username, r#"username="!#$&+-.^_`|~""#)
    }
}
