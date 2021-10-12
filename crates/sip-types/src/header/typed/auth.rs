use crate::header::headers::OneOrMore;
use crate::header::{ExtendValues, HeaderParse};
use crate::parse::{parse_quoted, token, whitespace, ParseCtx};
use crate::print::{AppendCtx, Print, PrintCtx};
use anyhow::Context;
use bytesstr::BytesStr;
use internal::IResult;
use internal::{ws, ParseError};
use nom::branch::alt;
use nom::bytes::complete::{tag, take_while, take_while1};
use nom::combinator::{map, map_res};
use nom::multi::many0;
use nom::sequence::{preceded, tuple};
use nom::Finish;
use std::fmt::{self, Display, Write};

// TODO: auth info

/// Param contained inside [Auth].
///
/// Has some special printing rules. Might not be hardcoded in the future.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthParam {
    name: BytesStr,
    value: BytesStr,
}

impl fmt::Display for AuthParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, r#"{}="{}""#, self.name, self.value)
    }
}

impl AuthParam {
    pub fn parse(ctx: ParseCtx<'_>) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            map(
                ws((
                    take_while(token),
                    tag("="),
                    alt((parse_quoted, take_while(token))),
                )),
                move |(name, _, value)| AuthParam {
                    name: BytesStr::from_parse(ctx.src, name),
                    value: BytesStr::from_parse(ctx.src, value),
                },
            )(i)
        }
    }
}

#[derive(Debug, Clone)]
pub enum AuthChallenge {
    Digest(DigestChallenge),
    Other(Auth),
}

impl HeaderParse for AuthChallenge {
    fn parse<'i>(ctx: ParseCtx, i: &'i str) -> anyhow::Result<(&'i str, Self)> {
        let (rem, challenge) = map_res(
            parse_auth_params(ctx),
            |(scheme, params)| -> Result<Self, ParseError> {
                match scheme.as_ref() {
                    "Digest" => Ok(Self::Digest(DigestChallenge::from_auth_params(params)?)),
                    _ => Ok(Self::Other(Auth { scheme, params })),
                }
            },
        )(i)
        .finish()?;

        Ok((rem, challenge))
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
    realm: BytesStr,
    domain: Option<BytesStr>, // TODO: this may be a vec. See (https://datatracker.ietf.org/doc/html/rfc2617#section-3.2.1, https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/WWW-Authenticate)
    nonce: BytesStr,
    opaque: Option<BytesStr>,
    stale: bool,
    algorithm: Algorithm,
    qop: Option<Vec<QopOption>>,
    /// Remaining fields
    other: Vec<AuthParam>,
}

impl DigestChallenge {
    pub(crate) fn from_auth_params(params: Vec<AuthParam>) -> anyhow::Result<Self> {
        let mut realm = None;
        let mut domain = None;
        let mut nonce = None;
        let mut opaque = None;
        let mut stale = false;
        let mut algorithm = Algorithm::MD5;
        let mut qop = None;
        let mut other = vec![];

        for param in params {
            match param.name.as_ref() {
                "realm" => realm = Some(param.value),
                "domain" => domain = Some(param.value),
                "nonce" => nonce = Some(param.value),
                "opaque" => opaque = Some(param.value),
                "stale" => stale = param.value.eq_ignore_ascii_case("true"),
                "algorithm" => algorithm = Algorithm::from(param.value),
                "qop" => {
                    qop = Some(
                        param
                            .value
                            .split(',')
                            .into_iter()
                            .map(|v| QopOption::from(param.value.slice_ref(v.trim())))
                            .collect(),
                    )
                }
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
            other,
        })
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

        if !matches!(self.algorithm, Algorithm::MD5) {
            write!(f, ", algorithm={}", self.algorithm)?;
        }

        if let Some(qop_options) = &self.qop {
            let mut iter = qop_options.iter();

            if let Some(first) = iter.next() {
                write!(f, r#", qop="{}"#, first)?;

                for qop_option in iter {
                    write!(f, ",{}", qop_option)?;
                }

                f.write_char('"')?;
            }
        }

        for param in &self.other {
            write!(f, ", {}", param)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum AuthResponse {
    Digest(DigestResponse),
    Other(Auth),
}

impl HeaderParse for AuthResponse {
    fn parse<'i>(ctx: ParseCtx, i: &'i str) -> anyhow::Result<(&'i str, Self)> {
        let (rem, response) = map_res(
            parse_auth_params(ctx),
            |(scheme, params)| -> Result<Self, ParseError> {
                match scheme.as_ref() {
                    "Digest" => Ok(Self::Digest(DigestResponse::from_auth_params(params)?)),
                    _ => Ok(Self::Other(Auth { scheme, params })),
                }
            },
        )(i)
        .finish()?;

        Ok((rem, response))
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

#[derive(Debug, Clone)]
pub struct DigestResponse {
    username: BytesStr,
    realm: BytesStr,
    nonce: BytesStr,
    uri: BytesStr,
    response: BytesStr,
    algorithm: Algorithm,
    opaque: Option<BytesStr>,
    qop_response: Option<QopResponse>,
    /// Remaining fields
    other: Vec<AuthParam>,
}

impl DigestResponse {
    pub(crate) fn from_auth_params(params: Vec<AuthParam>) -> anyhow::Result<Self> {
        let mut username = None;
        let mut realm = None;
        let mut nonce = None;
        let mut uri = None;
        let mut response = None;
        let mut algorithm = Algorithm::MD5;
        let mut opaque = None;

        // qop related params
        let mut qop = None;
        let mut cnonce = None;
        let mut nc = None;

        let mut other = vec![];

        for param in params {
            match param.name.as_ref() {
                "username" => username = Some(param.value),
                "realm" => realm = Some(param.value),
                "nonce" => nonce = Some(param.value),
                "uri" => uri = Some(param.value),
                "response" => response = Some(param.value),
                "algorithm" => algorithm = Algorithm::from(param.value),
                "opaque" => opaque = Some(param.value),
                "qop" => qop = Some(QopOption::from(param.value)),
                "cnonce" => cnonce = Some(param.value),
                "nc" => nc = Some(u32::from_str_radix(param.value.as_ref(), 16)),
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

        Ok(Self {
            username: username.context("Missing username in authorization header")?,
            realm: realm.context("Missing realm in authorization header")?,
            nonce: nonce.context("Missing nonce in authorization header")?,
            uri: uri.context("Missing uri in authorization header")?,
            response: response.context("Missing response in authorization header")?,
            algorithm,
            opaque,
            qop_response,
            other,
        })
    }
}

impl Print for DigestResponse {
    fn print(&self, f: &mut fmt::Formatter<'_>, _ctx: PrintCtx<'_>) -> fmt::Result {
        write!(
            f,
            r#"Digest username="{}", realm="{}", nonce="{}", uri="{}", response="{}""#,
            self.username, self.realm, self.nonce, self.uri, self.response
        )?;

        if !matches!(self.algorithm, Algorithm::MD5) {
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

        for param in &self.other {
            write!(f, ", {}", param)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq)]
struct QopResponse {
    qop: QopOption,
    cnonce: BytesStr,
    nc: u32,
}

#[derive(Debug, Clone, PartialEq)]
enum QopOption {
    Auth,
    AuthInt,
    Token(BytesStr),
}

impl From<BytesStr> for QopOption {
    fn from(value: BytesStr) -> Self {
        match value.as_ref() {
            "auth" => Self::Auth,
            "auth-int" => Self::AuthInt,
            token => Self::Token(value.slice_ref(token)),
        }
    }
}

impl Display for QopOption {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            QopOption::Auth => f.write_str("auth"),
            QopOption::AuthInt => f.write_str("auth-int"),
            QopOption::Token(token) => f.write_str(token),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Algorithm {
    MD5,
    SHA1,
    Other(BytesStr),
}

impl From<BytesStr> for Algorithm {
    fn from(value: BytesStr) -> Self {
        if value.eq_ignore_ascii_case("MD5") {
            Algorithm::MD5
        } else if value.eq_ignore_ascii_case("SHA1") {
            Algorithm::SHA1
        } else {
            Algorithm::Other(value)
        }
    }
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Algorithm::MD5 => f.write_str("MD5"),
            Algorithm::SHA1 => f.write_str("SHA1"),
            Algorithm::Other(other) => f.write_str(other),
        }
    }
}

fn parse_auth_params(
    ctx: ParseCtx<'_>,
) -> impl Fn(&str) -> IResult<&str, (BytesStr, Vec<AuthParam>)> + '_ {
    move |i| {
        tuple((
            map(take_while1(|c| !whitespace(c)), |scheme| {
                BytesStr::from_parse(ctx.src, scheme)
            }),
            preceded(
                take_while(whitespace),
                map(
                    tuple((
                        AuthParam::parse(ctx),
                        many0(map(ws((tag(","), AuthParam::parse(ctx))), |(_, scheme)| {
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

        let (rem, auth) = AuthChallenge::parse(ParseCtx::default(&input), &input).unwrap();

        match auth {
            AuthChallenge::Digest(DigestChallenge {
                realm,
                domain,
                nonce,
                opaque,
                stale,
                algorithm,
                qop,
                other,
            }) => {
                assert_eq!(realm, "example.com");
                assert_eq!(domain, None);
                assert_eq!(nonce, "abc123");
                assert_eq!(opaque, None);
                assert_eq!(stale, false);
                assert_eq!(algorithm, Algorithm::MD5);
                assert_eq!(qop, None);
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
            algorithm: Algorithm::MD5,
            qop: None,
            other: vec![],
        });

        let expected = r#"Digest realm="example.com", nonce="abc123""#;

        assert_eq!(expected, challenge.default_print_ctx().to_string());
    }

    #[test]
    fn all_fields_digest_challenge() {
        let input = BytesStr::from_static(
            r#"Digest realm="example.com", domain="TODO", nonce="abc123", opaque="opaque_value", stale=true, algorithm=SHA1, qop="auth,auth-int,a_token", another-field="some_extension""#,
        );

        let (rem, auth) = AuthChallenge::parse(ParseCtx::default(&input), &input).unwrap();

        match auth {
            AuthChallenge::Digest(DigestChallenge {
                realm,
                domain,
                nonce,
                opaque,
                stale,
                algorithm,
                qop,
                other,
            }) => {
                assert_eq!(realm, "example.com");
                assert_eq!(domain, Some(BytesStr::from_static("TODO")));
                assert_eq!(nonce, "abc123");
                assert_eq!(opaque, Some(BytesStr::from_static("opaque_value")));
                assert_eq!(stale, true);
                assert_eq!(algorithm, Algorithm::SHA1);
                assert_eq!(
                    qop,
                    Some(vec![
                        QopOption::Auth,
                        QopOption::AuthInt,
                        QopOption::Token(BytesStr::from_static("a_token"))
                    ])
                );

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
            algorithm: Algorithm::SHA1,
            qop: Some(vec![
                QopOption::Auth,
                QopOption::AuthInt,
                QopOption::Token(BytesStr::from_static("a_token")),
            ]),
            other: vec![AuthParam {
                name: BytesStr::from_static("another-field"),
                value: BytesStr::from_static("some_extension"),
            }],
        });

        let expected = r#"Digest realm="example.com", nonce="abc123", domain="TODO", opaque="opaque_value", stale=true, algorithm=SHA1, qop="auth,auth-int,a_token", another-field="some_extension""#;

        assert_eq!(expected, challenge.default_print_ctx().to_string());
    }

    #[test]
    fn parse_multiple_digest_challenge() {
        let mut headers = Headers::new();
        headers.insert(Name::WWW_AUTHENTICATE, "Digest realm=\"example.com\", nonce=\"abc123\", Digest realm=\"example.org\", nonce=\"123abc\", OAuth some-field=\"oauth_field\"");
        headers.insert(
            Name::WWW_AUTHENTICATE,
            "Digest realm=\"example.net\", nonce=\"xyz987\", algorithm=\"SHA1\"",
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
                other,
            }) => {
                assert_eq!(realm, "example.com");
                assert_eq!(domain, &None);
                assert_eq!(algorithm, &Algorithm::MD5);
                assert_eq!(nonce, "abc123");
                assert_eq!(opaque, &None);
                assert_eq!(stale, &false);
                assert_eq!(qop, &None);
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
                other,
            }) => {
                assert_eq!(realm, "example.org");
                assert_eq!(domain, &None);
                assert_eq!(algorithm, &Algorithm::MD5);
                assert_eq!(nonce, "123abc");
                assert_eq!(opaque, &None);
                assert_eq!(stale, &false);
                assert_eq!(qop, &None);
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
                other,
            }) => {
                assert_eq!(realm, "example.net");
                assert_eq!(domain, &None);
                assert_eq!(nonce, "xyz987");
                assert_eq!(opaque, &None);
                assert_eq!(stale, &false);
                assert_eq!(algorithm, &Algorithm::SHA1);
                assert_eq!(qop, &None);
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

        let (rem, auth) = AuthChallenge::parse(ParseCtx::default(&input), &input).unwrap();

        match auth {
            AuthChallenge::Digest(DigestChallenge {
                realm,
                domain,
                nonce,
                opaque,
                stale,
                algorithm,
                qop,
                other,
            }) => {
                assert_eq!(realm, "example.com");
                assert_eq!(domain, None);
                assert_eq!(nonce, "abc123");
                assert_eq!(algorithm, Algorithm::MD5);
                assert_eq!(opaque, None);
                assert_eq!(stale, false);
                assert_eq!(
                    qop,
                    Some(vec![
                        QopOption::Auth,
                        QopOption::AuthInt,
                        QopOption::Token(BytesStr::from_static("AuTh-Int")),
                    ])
                );
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

        let (rem, auth) = AuthResponse::parse(ParseCtx::default(&input), &input).unwrap();

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
                other,
            }) => {
                assert_eq!(username, "alice");
                assert_eq!(realm, "example.com");
                assert_eq!(nonce, "abc123");
                assert_eq!(uri, "sip:bob@example.com");
                assert_eq!(response, "00000000000000000000000000000000");
                assert_eq!(algorithm, Algorithm::MD5);
                assert_eq!(opaque, None);
                assert_eq!(qop_response, None);
                assert!(other.is_empty());
            }
            AuthResponse::Other(_) => panic!(),
        }
    }

    #[test]
    fn print_simple_digest_response() {
        let digest = AuthResponse::Digest(DigestResponse {
            username: BytesStr::from_static("alice"),
            realm: BytesStr::from_static("example.com"),
            nonce: BytesStr::from_static("abc123"),
            uri: BytesStr::from_static("sip:bob@example.com"),
            response: BytesStr::from_static("00000000000000000000000000000000"),
            algorithm: Algorithm::MD5,
            opaque: None,
            qop_response: None,
            other: vec![],
        });

        let expected = r#"Digest username="alice", realm="example.com", nonce="abc123", uri="sip:bob@example.com", response="00000000000000000000000000000000""#;

        assert_eq!(expected, digest.default_print_ctx().to_string());
    }

    #[test]
    fn parse_all_fields_digest_response() {
        let input = BytesStr::from_static(
            r#"Digest username="alice", realm="example.com", nonce="abc123", uri="sip:bob@example.com", response="00000000000000000000000000000000", algorithm=SHA1, opaque="opaque_value", qop="auth", cnonce="def456", nc=00000001, another-field="some_extension""#,
        );

        let (rem, auth) = AuthResponse::parse(ParseCtx::default(&input), &input).unwrap();

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
                other,
            }) => {
                assert_eq!(username, "alice");
                assert_eq!(realm, "example.com");
                assert_eq!(nonce, "abc123");
                assert_eq!(uri, "sip:bob@example.com");
                assert_eq!(response, "00000000000000000000000000000000");
                assert_eq!(algorithm, Algorithm::SHA1);
                assert_eq!(opaque, Some(BytesStr::from_static("opaque_value")));
                assert_eq!(
                    qop_response,
                    Some(QopResponse {
                        qop: QopOption::Auth,
                        cnonce: BytesStr::from_static("def456"),
                        nc: 1
                    })
                );
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
            username: BytesStr::from_static("alice"),
            realm: BytesStr::from_static("example.com"),
            nonce: BytesStr::from_static("abc123"),
            uri: BytesStr::from_static("sip:bob@example.com"),
            response: BytesStr::from_static("00000000000000000000000000000000"),
            algorithm: Algorithm::SHA1,
            opaque: Some(BytesStr::from_static("opaque_value")),
            qop_response: Some(QopResponse {
                qop: QopOption::Auth,
                cnonce: BytesStr::from_static("def456"),
                nc: 1,
            }),
            other: vec![AuthParam {
                name: BytesStr::from_static("another-field"),
                value: BytesStr::from_static("some_extension"),
            }],
        });

        let expected = r#"Digest username="alice", realm="example.com", nonce="abc123", uri="sip:bob@example.com", response="00000000000000000000000000000000", algorithm=SHA1, opaque="opaque_value", qop="auth", cnonce="def456", nc=00000001, another-field="some_extension""#;

        assert_eq!(expected, digest.default_print_ctx().to_string());
    }

    #[test]
    fn parse_qop_auth_int_digest_response() {
        let input = BytesStr::from_static(
            r#"Digest username="alice", realm="example.com", nonce="abc123", uri="sip:bob@example.com", response="00000000000000000000000000000000", qop="auth-int", cnonce="def456", nc=00000001"#,
        );

        let (rem, auth) = AuthResponse::parse(ParseCtx::default(&input), &input).unwrap();

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
                other,
            }) => {
                assert_eq!(username, "alice");
                assert_eq!(realm, "example.com");
                assert_eq!(nonce, "abc123");
                assert_eq!(uri, "sip:bob@example.com");
                assert_eq!(response, "00000000000000000000000000000000");
                assert_eq!(algorithm, Algorithm::MD5);
                assert_eq!(opaque, None);
                assert_eq!(
                    qop_response,
                    Some(QopResponse {
                        qop: QopOption::AuthInt,
                        cnonce: BytesStr::from_static("def456"),
                        nc: 1,
                    })
                );
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

        let (rem, auth) = AuthResponse::parse(ParseCtx::default(&input), &input).unwrap();

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
                other,
            }) => {
                assert_eq!(username, "alice");
                assert_eq!(realm, "example.com");
                assert_eq!(nonce, "abc123");
                assert_eq!(uri, "sip:bob@example.com");
                assert_eq!(response, "00000000000000000000000000000000");
                assert_eq!(algorithm, Algorithm::MD5);
                assert_eq!(opaque, None);
                assert_eq!(
                    qop_response,
                    Some(QopResponse {
                        qop: QopOption::Token(BytesStr::from_static("a_token")),
                        cnonce: BytesStr::from_static("def456"),
                        nc: 1,
                    })
                );
                assert!(other.is_empty());
            }
            AuthResponse::Other(_) => panic!(),
        }

        assert_eq!(rem, "");
    }
}
