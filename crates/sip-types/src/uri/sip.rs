use crate::host::HostPort;
use crate::method::Method;
use crate::parse::ParseCtx;
use crate::print::{AppendCtx, Print, PrintCtx, UriContext};
use crate::uri::params::{Params, CPS, HPS};
use bytes::Bytes;
use bytesstr::BytesStr;
use internal::IResult;
use nom::branch::alt;
use nom::bytes::complete::{tag, tag_no_case, take_while};
use nom::combinator::{map, map_res, opt};
use nom::sequence::{preceded, terminated, tuple};
use percent_encoding::{percent_decode_str, percent_encode, AsciiSet};
use std::borrow::Cow;
use std::fmt;
use std::str::{FromStr, Utf8Error};
use thiserror::Error;

#[derive(Clone, PartialEq)]
pub struct UserPw {
    pub user: BytesStr,
    pub password: BytesStr,
}

#[derive(Clone, PartialEq)]
pub enum UserPart {
    Empty,
    User(BytesStr),
    // Boxed because deprecated and rarely used
    UserPw(Box<UserPw>),
}

#[derive(Clone)]
pub struct SipUri {
    pub sips: bool,

    pub user_part: UserPart,
    pub host_port: HostPort,

    pub uri_params: Params<CPS>,
    pub header_params: Params<HPS>,
}

impl SipUri {
    pub fn new(host_port: HostPort) -> Self {
        SipUri {
            sips: false,
            user_part: UserPart::Empty,
            host_port,
            uri_params: Params::new(),
            header_params: Params::new(),
        }
    }

    impl_with_params!(uri_params, uri_param_key, uri_param_value);

    pub const fn sips(mut self, sips: bool) -> Self {
        self.sips = sips;
        self
    }

    pub fn set_user(&mut self, user: BytesStr) {
        match &mut self.user_part {
            UserPart::Empty => {
                self.user_part = UserPart::User(user);
            }
            UserPart::User(old) => *old = user,
            UserPart::UserPw(old) => old.user = user,
        }
    }

    pub fn user(mut self, user: BytesStr) -> Self {
        self.set_user(user);
        self
    }

    pub fn compare(&self, other: &Self) -> bool {
        self.sips == other.sips
            && self.user_part == other.user_part
            && self.host_port == other.host_port
    }
}

impl fmt::Debug for SipUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.print_ctx(PrintCtx::default()))
    }
}

impl Print for SipUri {
    fn print(&self, f: &mut fmt::Formatter<'_>, ctx: PrintCtx<'_>) -> fmt::Result {
        use fmt::Display;

        if self.sips {
            write!(f, "sips:")?;
        } else {
            write!(f, "sip:")?;
        }

        match &self.user_part {
            UserPart::Empty => {}
            UserPart::User(user) => write!(f, "{}@", percent_encode(user.as_ref(), &USER_SET))?,
            UserPart::UserPw(user_pw) => {
                write!(
                    f,
                    "{}:{}@",
                    percent_encode(user_pw.user.as_ref(), &USER_SET),
                    user_pw.password
                )?;
            }
        }

        write!(f, "{}", self.host_port.print_ctx(ctx))?;

        match (ctx.uri, &ctx.method) {
            (Some(UriContext::ReqUri), _) => write!(f, "{}", self.uri_params),
            (Some(UriContext::FromTo), _) => self
                .uri_params
                .filtered_print(|name| !matches!(name, "maddr" | "ttl" | "transport" | "lr"))
                .fmt(f),
            (Some(UriContext::Contact), Some(&Method::REGISTER /* TODO: METHOD::REDIRECT */)) => {
                self.uri_params
                    .filtered_print(|name| !matches!(name, "lr"))
                    .fmt(f)?;

                self.header_params.fmt(f)
            }
            (Some(UriContext::Contact | UriContext::Routing), _) => self
                .uri_params
                .filtered_print(|name| !matches!(name, "ttl"))
                .fmt(f),
            _ => {
                self.uri_params.fmt(f)?;
                self.header_params.fmt(f)
            }
        }
    }
}

encode_set!(user, USER_SET);

fn user(c: char) -> bool {
    lookup_table!(c => alpha; num; '-', '_', '.', '!', '~', '*', '\'', '(', ')', '%', '&', '=', '+', '$', ',', ';', '?', '/')
}

fn password(c: char) -> bool {
    lookup_table!(c => alpha; num; '-', '_', '.', '!', '~', '*', '\'', '(', ')', '%', '&', '=', '+', '$', ',')
}

impl SipUri {
    pub fn parse(ctx: ParseCtx<'_>) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            map_res(
                tuple((
                    parse_scheme,
                    parse_user_pw,
                    HostPort::parse(ctx),
                    Params::<CPS>::parse(ctx),
                    Params::<HPS>::parse(ctx),
                )),
                |(sips, user_pw, host_port, uri_params, header_params)| -> Result<SipUri, Utf8Error> {
                    let user_part = user_part(ctx.src, user_pw)?;

                    Ok(SipUri {
                        sips,
                        user_part,
                        host_port,
                        uri_params,
                        header_params,
                    })
                },
            )(i)
        }
    }

    pub fn parse_no_params(ctx: ParseCtx<'_>) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            map_res(
                tuple((parse_scheme, parse_user_pw, HostPort::parse(ctx))),
                |(sips, user_pw, host_port)| -> Result<SipUri, Utf8Error> {
                    let user_part = user_part(ctx.src, user_pw)?;

                    Ok(SipUri {
                        sips,
                        user_part,
                        host_port,
                        uri_params: Params::new(),
                        header_params: Params::new(),
                    })
                },
            )(i)
        }
    }
}

fn user_part(src: &Bytes, user_pw: Option<(&str, Option<&str>)>) -> Result<UserPart, Utf8Error> {
    if let Some((user, password)) = user_pw {
        let user = match percent_decode_str(user).decode_utf8()? {
            Cow::Borrowed(slice) => BytesStr::from_parse(src, slice),
            Cow::Owned(owned) => BytesStr::from(owned),
        };

        if let Some(pw) = password {
            Ok(UserPart::UserPw(Box::new(UserPw {
                user,
                password: BytesStr::from_parse(src, pw),
            })))
        } else {
            Ok(UserPart::User(user))
        }
    } else {
        Ok(UserPart::Empty)
    }
}

fn parse_scheme(i: &str) -> IResult<&str, bool> {
    alt((
        map(tag_no_case("sip:"), |_| false),
        map(tag_no_case("sips:"), |_| true),
    ))(i)
}

fn parse_user_pw(i: &str) -> IResult<&str, Option<(&str, Option<&str>)>> {
    opt(terminated(
        tuple((
            take_while(user),
            opt(preceded(tag(":"), take_while(password))),
        )),
        tag("@"),
    ))(i)
}

#[derive(Debug, Error)]
#[error("invalid sip uri")]
pub struct InvalidSipUri(());

impl FromStr for SipUri {
    type Err = InvalidSipUri;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = BytesStr::from(s);

        let ctx = ParseCtx::default(&s);

        let res = Self::parse(ctx)(s.as_ref())
            .map(|(_, uri)| uri)
            .map_err(|_| InvalidSipUri(()));

        res
    }
}
