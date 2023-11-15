use bytes::Bytes;
use bytesstr::BytesStr;
use internal::{ws, IResult};
use nom::bytes::complete::{tag, take_while1};
use nom::character::complete::{char, digit1};
use nom::combinator::{map, map_res};
use nom::multi::{many0, separated_list0};
use nom::sequence::{preceded, separated_pair, tuple};
use std::str::FromStr;

#[derive(Debug)]
pub struct Crypto {
    tag: u32,
    suite: BytesStr,
    key_params: Vec<(BytesStr, BytesStr)>,
    session_params: Vec<BytesStr>,
}

impl Crypto {
    pub fn parse<'i>(src: &Bytes, i: &'i str) -> IResult<&'i str, Self> {
        map(
            preceded(
                tag("crypto:"),
                tuple((
                    map_res(digit1, FromStr::from_str),
                    ws((
                        // suite
                        take_while1(alphanumeric_and_underscore),
                        // key params
                        separated_list0(
                            char(';'),
                            map(
                                separated_pair(
                                    take_while1(|c| c != ':'),
                                    char(':'),
                                    take_while1(
                                        |c: char| matches!(c, '\u{21}'..='\u{3a}' | '\u{3C}'..='\u{7E}'),
                                    ),
                                ),
                                |(k, v)| {
                                    (BytesStr::from_parse(src, k), BytesStr::from_parse(src, v))
                                },
                            ),
                        ),
                        // session params
                        many0(map(ws((take_while1(vchar),)), |(s,)| {
                            BytesStr::from_parse(src, s)
                        })),
                    )),
                )),
            ),
            |(tag, (suite, key_params, session_params))| Self {
                tag,
                suite: BytesStr::from_parse(src, suite),
                key_params,
                session_params,
            },
        )(i)
    }
}

fn alphanumeric_and_underscore(c: char) -> bool {
    matches!(c, 'a'..='z' | 'A'..='Z' | '0'..='9' | '_')
}

fn vchar(c: char) -> bool {
    matches!(c, '\u{21}'..='\u{7E}')
}

fn base64(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=')
}

pub struct SrtpCrypto {
    pub tag: u32,
    pub suite: SrtpSuite,
}

#[derive(Debug)]
#[allow(non_camel_case_types)]
pub enum SrtpSuite {
    AES_CM_128_HMAC_SHA1_32,
    F8_128_HMAC_SHA1_32,
    AES_CM_128_HMAC_SHA1_80,
    Ext(BytesStr),
}

impl From<BytesStr> for SrtpSuite {
    fn from(value: BytesStr) -> Self {
        match value.as_str() {
            "AES_CM_128_HMAC_SHA1_32" => Self::AES_CM_128_HMAC_SHA1_32,
            "F8_128_HMAC_SHA1_32" => Self::F8_128_HMAC_SHA1_32,
            "AES_CM_128_HMAC_SHA1_80" => Self::AES_CM_128_HMAC_SHA1_80,
            _ => Self::Ext(value),
        }
    }
}

pub enum SrtpSessionParam {
    Kdr(u32),
    UnencryptedSrtp,
    UnencryptedSrtcp,
    FecOrder(SrtpFecType),
    FecKey(Vec<(BytesStr, BytesStr)>),
    Wsh(u32),
    Ext(BytesStr),
}

pub enum SrtpFecType {
    FecSrtp,
    SrtpFec,
}

pub struct KeyingMaterial {
    pub key_and_salt: BytesStr,
    pub lifetime: Option<u32>,
    pub mki_length: Option<(u32, u32)>,
}

impl KeyingMaterial {
    fn parse(i: &str) -> Self {
        let mut split = i.split('|');

        let key_and_salt = split.next().unwrap();

        let mut ret = Self {
            key_and_salt: key_and_salt.into(),
            lifetime: None,
            mki_length: None,
        };

        if let Some(lifetime) = split.next() {
            ret.lifetime = Some(lifetime.parse().unwrap());

            if let Some(mki_length) = split.next() {
                let (mki, length) = mki_length.split_once(':').unwrap();

                ret.mki_length = Some((mki.parse().unwrap(), length.parse().unwrap()));
            }
        }

        ret
    }
}

impl From<Crypto> for SrtpCrypto {
    fn from(value: Crypto) -> Self {
        let Crypto {
            tag,
            suite,
            key_params,
            session_params,
        } = value;

        // let key_params =

        Self {
            tag,
            suite: SrtpSuite::from(suite),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse() {
        let i = BytesStr::from_static("crypto:1 AES_CM_128_HMAC_SHA1_80 inline:PS1uQCVeeCFCanVmcjkpPywjNWhcYD0mXXtxaVBR|2^20|1:32");
        let (rem, c) = Crypto::parse(i.as_ref(), &i).unwrap();
        assert!(rem.is_empty());

        assert_eq!(c.tag, 1);
        assert_eq!(c.suite, "AES_CM_128_HMAC_SHA1_80");
        assert_eq!(c.key_params.len(), 1);
        assert_eq!(c.session_params.len(), 0);
    }
}
