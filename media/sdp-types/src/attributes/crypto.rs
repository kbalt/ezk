use bytes::Bytes;
use bytesstr::BytesStr;
use internal::{IResult, ws};
use nom::branch::alt;
use nom::bytes::complete::{tag, take_while1};
use nom::character::complete::{char, digit1};
use nom::combinator::{map, map_res, not, opt, peek};
use nom::error::context;
use nom::multi::{separated_list0, separated_list1};
use nom::sequence::{preceded, separated_pair, terminated, tuple};
use std::fmt;

/// Crypto attribte (for SRTP only) (`a=crypto`)
///
/// [RFC4568](https://www.rfc-editor.org/rfc/rfc4568)
#[derive(Debug, Clone)]
pub struct SrtpCrypto {
    /// Unique identifier in a media description
    pub tag: u32,

    /// Crypto suite describing the encryption and authentication algorithm to use
    pub suite: SrtpSuite,

    /// One or more keys to use
    pub keys: Vec<SrtpKeyingMaterial>,

    /// Additional SRTP params
    pub params: Vec<SrtpSessionParam>,
}

impl SrtpCrypto {
    pub fn parse<'i>(src: &Bytes, i: &'i str) -> IResult<&'i str, Self> {
        context(
            "parsing srtp-crypto attribute",
            map(
                ws((
                    // tag
                    number,
                    // suite
                    SrtpSuite::parse(src),
                    // keying material
                    parse_srtp_key_params(src),
                    // session params
                    separated_list0(
                        take_while1(char::is_whitespace),
                        SrtpSessionParam::parse(src),
                    ),
                )),
                |(tag, suite, keys, params)| Self {
                    tag,
                    suite,
                    keys,
                    params,
                },
            ),
        )(i)
    }
}

impl fmt::Display for SrtpCrypto {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} {}", self.tag, self.suite)?;

        if !self.keys.is_empty() {
            write!(f, " ")?;
        }

        let mut keys = self.keys.iter().peekable();

        while let Some(key) = keys.next() {
            write!(f, "inline:{key}")?;

            if keys.peek().is_some() {
                write!(f, ";")?;
            }
        }

        for param in &self.params {
            write!(f, " {param}")?;
        }

        Ok(())
    }
}

macro_rules! suite {
    ($($suite:ident),* $(,)?) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        #[allow(non_camel_case_types)]
        pub enum SrtpSuite {
            $($suite,)*
            Ext(BytesStr),
        }

        impl SrtpSuite {
            pub fn parse(src: &Bytes) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
                move |i| {
                    context(
                        "parsing srtp suite",
                        alt((
                            $(
                            map(tag(stringify!($suite)), |_| Self::$suite),
                            )*
                            map(take_while1(is_alphanumeric_or_underscore), move |suite| {
                                Self::Ext(BytesStr::from_parse(src, suite))
                            }),
                        )),
                    )(i)
                }
            }

            pub fn as_str(&self) -> &str {
                match self {
                    $(Self::$suite => stringify!($suite),)*
                    Self::Ext(ext) => ext,
                }
            }
        }

        impl fmt::Display for SrtpSuite {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}", self.as_str())
            }
        }
    };
}

suite! {
    AES_CM_128_HMAC_SHA1_80,
    AES_CM_128_HMAC_SHA1_32,
    F8_128_HMAC_SHA1_80,
    AES_192_CM_HMAC_SHA1_80,
    AES_192_CM_HMAC_SHA1_32,
    AES_256_CM_HMAC_SHA1_80,
    AES_256_CM_HMAC_SHA1_32,
    AEAD_AES_128_GCM,
    AEAD_AES_256_GCM,
}

impl SrtpSuite {
    pub fn key_and_salt_len(&self) -> Option<(usize, usize)> {
        match self {
            SrtpSuite::AES_CM_128_HMAC_SHA1_80
            | SrtpSuite::AES_CM_128_HMAC_SHA1_32
            | SrtpSuite::F8_128_HMAC_SHA1_80 => Some((16, 14)),
            SrtpSuite::AES_192_CM_HMAC_SHA1_80 | SrtpSuite::AES_192_CM_HMAC_SHA1_32 => {
                Some((24, 14))
            }
            SrtpSuite::AES_256_CM_HMAC_SHA1_80 | SrtpSuite::AES_256_CM_HMAC_SHA1_32 => {
                Some((32, 14))
            }
            SrtpSuite::AEAD_AES_128_GCM => Some((16, 12)),
            SrtpSuite::AEAD_AES_256_GCM => Some((32, 12)),
            SrtpSuite::Ext(_) => None,
        }
    }
}

/// Parameters for an SRTP sessions
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrtpSessionParam {
    /// The SRTP Key Derivation Rate is the rate at which a pseudo-random function is applied to a master key
    Kdr(u32),
    /// SRTP messages are not encrypted
    UnencryptedSrtp,
    /// SRTCP messages are not encrypted
    UnencryptedSrtcp,
    /// SRTP messages are not authenticated
    UnauthenticatedSrtp,
    //// Use forward error correction for the RTP packets
    FecOrder(SrtpFecOrder),
    /// Use separate master key(s) for a Forward Error Correction (FEC) stream
    FecKey(Vec<SrtpKeyingMaterial>),
    /// Window Size Hint
    WindowSizeHint(u32),
    /// Unknown parameter
    Ext(BytesStr),
}

/// Order of forward error correction (FEC) relative to SRTP services
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SrtpFecOrder {
    /// FEC is applied before SRTP processing by the sender
    /// FEC is applied after SRTP processing by the receiver
    FecSrtp,

    /// FEC is applied after SRTP processing by the sender
    /// FEC is applied before SRTP processing by the receiver
    SrtpFec,
}

impl SrtpSessionParam {
    pub fn parse(src: &Bytes) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            context(
                "parsing srtp-session-param",
                alt((
                    map(preceded(tag("KDR="), number), Self::Kdr),
                    map(tag("UNENCRYPTED_SRTP"), |_| Self::UnencryptedSrtp),
                    map(tag("UNENCRYPTED_SRTCP"), |_| Self::UnencryptedSrtcp),
                    map(tag("UNAUTHENTICATED_SRTP"), |_| Self::UnauthenticatedSrtp),
                    preceded(
                        tag("FEC_ORDER="),
                        alt((
                            map(tag("FEC_SRTP"), |_| Self::FecOrder(SrtpFecOrder::FecSrtp)),
                            map(tag("SRTP_FEC"), |_| Self::FecOrder(SrtpFecOrder::SrtpFec)),
                        )),
                    ),
                    map(
                        preceded(tag("FEC_KEY="), parse_srtp_key_params(src)),
                        Self::FecKey,
                    ),
                    map(preceded(tag("WSH="), number), Self::WindowSizeHint),
                    map(
                        preceded(peek(not(char('-'))), take_while1(is_visible_char)),
                        |ext| Self::Ext(BytesStr::from_parse(src, ext)),
                    ),
                )),
            )(i)
        }
    }
}

impl fmt::Display for SrtpSessionParam {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SrtpSessionParam::Kdr(v) => write!(f, "KDR={v}"),
            SrtpSessionParam::UnencryptedSrtp => write!(f, "UNENCRYPTED_SRTP"),
            SrtpSessionParam::UnencryptedSrtcp => write!(f, "UNENCRYPTED_SRTCP"),
            SrtpSessionParam::UnauthenticatedSrtp => write!(f, "UNAUTHENTICATED_SRTP"),
            SrtpSessionParam::FecOrder(order) => {
                let order = match order {
                    SrtpFecOrder::FecSrtp => "FEC_SRTP",
                    SrtpFecOrder::SrtpFec => "SRTP_FEC",
                };

                write!(f, "FEC_ORDER={order}")
            }
            SrtpSessionParam::FecKey(keys) => {
                if keys.is_empty() {
                    return Ok(());
                }

                write!(f, "FEC_KEY=")?;

                let mut keys = keys.iter().peekable();

                while let Some(key) = keys.next() {
                    write!(f, "inline:{key}")?;

                    if keys.peek().is_some() {
                        write!(f, ";")?;
                    }
                }

                Ok(())
            }
            SrtpSessionParam::WindowSizeHint(v) => write!(f, "WSH={v}"),
            SrtpSessionParam::Ext(ext) => write!(f, "{ext}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SrtpKeyingMaterial {
    /// Concatenated master key and salt, base64 encoded
    pub key_and_salt: BytesStr,

    /// Master key lifetime (max number of SRTP/SRTCP packets using this master key)
    pub lifetime: Option<u32>,

    /// Master key index and length of the MKI field in SRTP packets
    pub mki: Option<(u32, u32)>,
}

impl SrtpKeyingMaterial {
    pub fn parse(src: &Bytes) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            context(
                "parsing keying material",
                map(
                    tuple((
                        // key and salt
                        take_while1(is_base64_char),
                        // lifetime
                        opt(map(
                            terminated(
                                preceded(char('|'), tuple((opt(tag("2^")), number))),
                                // Do not parse the mki here by mistake
                                peek(not(char(':'))),
                            ),
                            |(exp, n)| {
                                if exp.is_some() { 2u32.pow(n) } else { n }
                            },
                        )),
                        // mki
                        opt(preceded(
                            char('|'),
                            separated_pair(number, char(':'), number),
                        )),
                    )),
                    |(key_and_salt, lifetime, mki)| Self {
                        key_and_salt: BytesStr::from_parse(src, key_and_salt),
                        lifetime,
                        mki,
                    },
                ),
            )(i)
        }
    }
}

impl fmt::Display for SrtpKeyingMaterial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.key_and_salt)?;

        if let Some(lifetime) = self.lifetime {
            if lifetime.is_power_of_two() {
                write!(f, "|2^{}", lifetime.trailing_zeros())?;
            } else {
                write!(f, "|{lifetime}")?;
            }
        }

        if let Some((mki, mki_length)) = self.mki {
            write!(f, "|{mki}:{mki_length}")?;
        }

        Ok(())
    }
}

fn parse_srtp_key_params(
    src: &Bytes,
) -> impl FnMut(&str) -> IResult<&str, Vec<SrtpKeyingMaterial>> + '_ {
    move |i| {
        separated_list1(
            char(';'),
            preceded(tag("inline:"), SrtpKeyingMaterial::parse(src)),
        )(i)
    }
}

fn is_alphanumeric_or_underscore(c: char) -> bool {
    matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_')
}

fn is_visible_char(c: char) -> bool {
    matches!(c, '\u{21}'..='\u{7E}')
}

fn is_base64_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=')
}

fn number(i: &str) -> IResult<&str, u32> {
    context("parsing number", map_res(digit1, str::parse))(i)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn srtp_session_param_kdr() {
        let i = BytesStr::from_static("KDR=5");
        let (rem, param) = SrtpSessionParam::parse(i.as_ref())(&i).unwrap();

        assert!(rem.is_empty(), "rem is not empty: {rem:?}");

        let SrtpSessionParam::Kdr(5) = param else {
            panic!("expected Kdr got {param:?}")
        };

        assert_eq!(param.to_string(), "KDR=5");
    }

    #[test]
    fn srtp_session_param_unencrypted_srtp() {
        let i = BytesStr::from_static("UNENCRYPTED_SRTP");
        let (rem, param) = SrtpSessionParam::parse(i.as_ref())(&i).unwrap();

        assert!(rem.is_empty(), "rem is not empty: {rem:?}");

        let SrtpSessionParam::UnencryptedSrtp = param else {
            panic!("expected UnencryptedSrtp got {param:?}")
        };

        assert_eq!(param.to_string(), "UNENCRYPTED_SRTP");
    }

    #[test]
    fn srtp_session_param_unencrypted_srtcp() {
        let i = BytesStr::from_static("UNENCRYPTED_SRTCP");
        let (rem, param) = SrtpSessionParam::parse(i.as_ref())(&i).unwrap();

        assert!(rem.is_empty(), "rem is not empty: {rem:?}");

        let SrtpSessionParam::UnencryptedSrtcp = param else {
            panic!("expected UnencryptedSrtcp got {param:?}")
        };

        assert_eq!(param.to_string(), "UNENCRYPTED_SRTCP");
    }

    #[test]
    fn srtp_session_param_unauthenticated_srtp() {
        let i = BytesStr::from_static("UNAUTHENTICATED_SRTP");
        let (rem, param) = SrtpSessionParam::parse(i.as_ref())(&i).unwrap();

        assert!(rem.is_empty(), "rem is not empty: {rem:?}");

        let SrtpSessionParam::UnauthenticatedSrtp = param else {
            panic!("expected UnauthenticatedSrtp got {param:?}")
        };

        assert_eq!(param.to_string(), "UNAUTHENTICATED_SRTP");
    }

    #[test]
    fn srtp_session_param_fec_order1() {
        let i = BytesStr::from_static("FEC_ORDER=SRTP_FEC");
        let (rem, param) = SrtpSessionParam::parse(i.as_ref())(&i).unwrap();

        assert!(rem.is_empty(), "rem is not empty: {rem:?}");

        let SrtpSessionParam::FecOrder(SrtpFecOrder::SrtpFec) = param else {
            panic!("expected FecOrder(SrtpFecOrder::SrtpFec) got {param:?}")
        };

        assert_eq!(param.to_string(), "FEC_ORDER=SRTP_FEC");
    }

    #[test]
    fn srtp_session_param_fec_order2() {
        let i = BytesStr::from_static("FEC_ORDER=FEC_SRTP");
        let (rem, param) = SrtpSessionParam::parse(i.as_ref())(&i).unwrap();

        assert!(rem.is_empty(), "rem is not empty: {rem:?}");

        let SrtpSessionParam::FecOrder(SrtpFecOrder::FecSrtp) = param else {
            panic!("expected FecOrder(SrtpFecOrder::FecSrtp) got {param:?}")
        };

        assert_eq!(param.to_string(), "FEC_ORDER=FEC_SRTP");
    }

    #[test]
    fn srtp_session_param_fec_key1() {
        let i = BytesStr::from_static(
            "FEC_KEY=inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|2^20|1:4",
        );
        let (rem, param) = SrtpSessionParam::parse(i.as_ref())(&i).unwrap();

        assert!(rem.is_empty(), "rem is not empty: {rem:?}");

        let SrtpSessionParam::FecKey(key) = &param else {
            panic!("expected FecKey(..) got {param:?}")
        };

        assert_eq!(key.len(), 1);

        assert_eq!(
            key[0].key_and_salt,
            "d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj"
        );
        assert_eq!(key[0].lifetime, Some(1048576));
        assert_eq!(key[0].mki, Some((1, 4)));

        assert_eq!(
            param.to_string(),
            "FEC_KEY=inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|2^20|1:4"
        );
    }

    #[test]
    fn srtp_session_param_fec_key2() {
        let i = BytesStr::from_static(
            "FEC_KEY=inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|2^20|1:4;inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|2^14|1:2",
        );
        let (rem, param) = SrtpSessionParam::parse(i.as_ref())(&i).unwrap();

        assert!(rem.is_empty(), "rem is not empty: {rem:?}");

        let SrtpSessionParam::FecKey(key) = &param else {
            panic!("expected FecKey(..) got {param:?}")
        };

        assert_eq!(key.len(), 2);

        assert_eq!(
            key[0].key_and_salt,
            "d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj"
        );
        assert_eq!(key[0].lifetime, Some(1048576));
        assert_eq!(key[0].mki, Some((1, 4)));

        assert_eq!(
            key[1].key_and_salt,
            "d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj"
        );
        assert_eq!(key[1].lifetime, Some(16384));
        assert_eq!(key[1].mki, Some((1, 2)));

        assert_eq!(
            param.to_string(),
            "FEC_KEY=inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|2^20|1:4;inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|2^14|1:2"
        );
    }

    #[test]
    fn srtp_session_param_window_size_hint() {
        let i = BytesStr::from_static("WSH=5");
        let (rem, param) = SrtpSessionParam::parse(i.as_ref())(&i).unwrap();

        assert!(rem.is_empty(), "rem is not empty: {rem:?}");

        let SrtpSessionParam::WindowSizeHint(5) = param else {
            panic!("expected WindowSizeHint got {param:?}")
        };

        assert_eq!(param.to_string(), "WSH=5");
    }

    #[test]
    fn keying_material_missing_lifetime() {
        let i = BytesStr::from_static("d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|1:4");
        let (rem, key) = SrtpKeyingMaterial::parse(i.as_ref())(&i).unwrap();

        assert!(rem.is_empty(), "rem is not empty: {rem:?}");

        assert_eq!(key.key_and_salt, "d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj");
        assert_eq!(key.lifetime, None);
        assert_eq!(key.mki, Some((1, 4)));

        assert_eq!(
            key.to_string(),
            "d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|1:4"
        );
    }

    #[test]
    fn keying_material_missing_mki() {
        let i = BytesStr::from_static("d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|2^10");
        let (rem, key) = SrtpKeyingMaterial::parse(i.as_ref())(&i).unwrap();

        assert!(rem.is_empty(), "rem is not empty: {rem:?}");

        assert_eq!(key.key_and_salt, "d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj");
        assert_eq!(key.lifetime, Some(1024));
        assert_eq!(key.mki, None);

        assert_eq!(
            key.to_string(),
            "d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|2^10"
        );
    }

    #[test]
    fn keying_material_only_key_and_salt() {
        let i = BytesStr::from_static("d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj");
        let (rem, key) = SrtpKeyingMaterial::parse(i.as_ref())(&i).unwrap();

        assert!(rem.is_empty(), "rem is not empty: {rem:?}");

        assert_eq!(key.key_and_salt, "d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj");
        assert_eq!(key.lifetime, None);
        assert_eq!(key.mki, None);

        assert_eq!(key.to_string(), "d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj");
    }

    #[test]
    fn parse_everything() {
        let i = BytesStr::from_static(
            "\
1 AES_CM_128_HMAC_SHA1_80 inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|2^20|1:4;inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|2^14|1:2 \
KDR=100 \
UNENCRYPTED_SRTP \
UNENCRYPTED_SRTCP \
UNAUTHENTICATED_SRTP \
FEC_ORDER=FEC_SRTP \
FEC_ORDER=SRTP_FEC \
FEC_KEY=inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|1:4 \
WSH=123",
        );
        let (rem, c) = SrtpCrypto::parse(i.as_ref(), &i).unwrap();
        assert!(rem.is_empty(), "rem is not empty: {rem:?}");

        assert_eq!(c.tag, 1);
        assert_eq!(c.suite, SrtpSuite::AES_CM_128_HMAC_SHA1_80);

        assert_eq!(c.keys.len(), 2);

        assert_eq!(
            c.keys[0].key_and_salt,
            "d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj"
        );
        assert_eq!(c.keys[0].lifetime, Some(1048576));
        assert_eq!(c.keys[0].mki, Some((1, 4)));

        assert_eq!(
            c.keys[1].key_and_salt,
            "d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj"
        );
        assert_eq!(c.keys[1].lifetime, Some(16384));
        assert_eq!(c.keys[1].mki, Some((1, 2)));

        assert_eq!(c.params[0], SrtpSessionParam::Kdr(100));
        assert_eq!(c.params[1], SrtpSessionParam::UnencryptedSrtp);
        assert_eq!(c.params[2], SrtpSessionParam::UnencryptedSrtcp);
        assert_eq!(c.params[3], SrtpSessionParam::UnauthenticatedSrtp);
        assert_eq!(
            c.params[4],
            SrtpSessionParam::FecOrder(SrtpFecOrder::FecSrtp)
        );
        assert_eq!(
            c.params[5],
            SrtpSessionParam::FecOrder(SrtpFecOrder::SrtpFec)
        );
        assert_eq!(c.params[7], SrtpSessionParam::WindowSizeHint(123));

        assert_eq!(
            c.to_string(),
            "1 AES_CM_128_HMAC_SHA1_80 inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|2^20|1:4;inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|2^14|1:2 KDR=100 UNENCRYPTED_SRTP UNENCRYPTED_SRTCP UNAUTHENTICATED_SRTP FEC_ORDER=FEC_SRTP FEC_ORDER=SRTP_FEC FEC_KEY=inline:d0RmdmcmVCspeEc3QGZiNWpVLFJhQX1cfHAwJSoj|1:4 WSH=123"
        );
    }
}
