use crate::header::name::Name;
use crate::parse::text::{SingleTextSpec, Text};
use crate::parse::{parse_quoted, ParseCtx};
use crate::parse::{token, whitespace};
use crate::print::{Print, PrintCtx};
use bytesstr::BytesStr;
use internal::ws;
use nom::branch::alt;
use nom::bytes::complete::{tag, take_while};
use nom::combinator::map;
use nom::multi::many0;
use nom::sequence::tuple;
use nom::IResult;
use std::fmt;

/// Param contained inside [Auth].
///
/// Has some special printing rules. Might not be hardcoded in the future.
#[derive(Debug, Clone)]
pub struct AuthParam {
    name: BytesStr,
    value: BytesStr,
}

impl fmt::Display for AuthParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}=", self.name)?;

        match self.name.as_ref() {
            "realm" | "domain" | "nonce" | "opaque" | "qop" => {
                write!(f, "\"{}\"", self.value)?;
            }

            // "stale" | "algorithm" | and all other
            _ => {
                write!(f, "{}", self.value)?;
            }
        }

        Ok(())
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

/// Implementation for all Auth kind headers.
#[derive(Debug, Clone)]
pub struct Auth {
    pub token: BytesStr,
    pub params: Vec<AuthParam>,
}

impl Print for Auth {
    fn print(&self, f: &mut fmt::Formatter<'_>, _: PrintCtx<'_>) -> fmt::Result {
        write!(f, "{} ", self.token)?;

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

impl Auth {
    pub(crate) fn parse(ctx: ParseCtx<'_>) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            map(
                tuple((
                    Text::<SingleTextSpec>::parse(ctx),
                    take_while(whitespace),
                    map(
                        tuple((
                            AuthParam::parse(ctx),
                            many0(map(ws((tag(","), AuthParam::parse(ctx))), |(_, t)| t)),
                        )),
                        |(first_param, mut v)| {
                            v.insert(0, first_param);
                            v
                        },
                    ),
                )),
                |(t, _, c)| Auth {
                    token: t,
                    params: c,
                },
            )(i)
        }
    }
}

impl_wrap_header!(
    /// `Authorization` header. Wraps [Auth].
    Auth,
    Authorization,
    Single,
    Name::AUTHORIZATION
);

impl_wrap_header!(
    /// `Proxy-Authenticate` header. Wraps [Auth].
    Auth,
    ProxyAuthenticate,
    Single,
    Name::PROXY_AUTHENTICATE
);

impl_wrap_header!(
    /// `Proxy-Authorization` header. Wraps [Auth].
    Auth,
    ProxyAuthorization,
    Single,
    Name::PROXY_AUTHORIZATION
);

impl_wrap_header!(
    /// `WWW-Authenticate` header. Wraps [Auth].
    Auth,
    WWWAuthenticate,
    Single,
    Name::WWW_AUTHENTICATE
);

#[cfg(test)]
mod test {
    use super::*;
    use crate::print::AppendCtx;

    #[test]
    fn auth() {
        let input = BytesStr::from_static("Digest some=param");

        let (rem, auth) = Authorization::parse(ParseCtx::default(&input))(&input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(auth.token, "Digest");

        assert_eq!(&auth.params[0].name, "some");
        assert_eq!(&auth.params[0].value, "param");
    }

    #[test]
    fn auth_print() {
        let auth = Authorization(Auth {
            token: "Digest".into(),
            params: vec![
                AuthParam {
                    name: "some".into(),
                    value: "param".into(),
                },
                AuthParam {
                    name: "realm".into(),
                    value: "example.com".into(),
                },
            ],
        });

        assert_eq!(
            auth.default_print_ctx().to_string(),
            "Digest some=param, realm=\"example.com\""
        );
    }
}
