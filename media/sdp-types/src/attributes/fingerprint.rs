use bytes::Bytes;
use bytesstr::BytesStr;
use internal::IResult;
use nom::{
    branch::alt,
    bytes::complete::{tag_no_case, take, take_while1},
    character::complete::char,
    combinator::{map, map_res},
    error::context,
    multi::separated_list1,
    sequence::separated_pair,
};
use std::fmt;

use crate::not_whitespace;

#[derive(Debug, Clone)]
pub struct Fingerprint {
    pub algorithm: FingerprintAlgorithm,
    pub fingerprint: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FingerprintAlgorithm {
    SHA1,
    SHA224,
    SHA256,
    SHA384,
    SHA512,
    MD5,
    MD2,
    Other(BytesStr),
}

impl Fingerprint {
    pub fn parse<'i>(src: &Bytes, i: &'i str) -> IResult<&'i str, Self> {
        context(
            "parsing fingerprint-attribute",
            map(
                separated_pair(
                    alt((
                        map(tag_no_case("SHA-1"), |_| FingerprintAlgorithm::SHA1),
                        map(tag_no_case("SHA-224"), |_| FingerprintAlgorithm::SHA224),
                        map(tag_no_case("SHA-256"), |_| FingerprintAlgorithm::SHA256),
                        map(tag_no_case("SHA-384"), |_| FingerprintAlgorithm::SHA384),
                        map(tag_no_case("SHA-512"), |_| FingerprintAlgorithm::SHA512),
                        map(tag_no_case("MD5"), |_| FingerprintAlgorithm::MD5),
                        map(tag_no_case("MD2"), |_| FingerprintAlgorithm::MD2),
                        map(take_while1(not_whitespace), |other| {
                            FingerprintAlgorithm::Other(BytesStr::from_parse(src, other))
                        }),
                    )),
                    take_while1(char::is_whitespace),
                    separated_list1(
                        char(':'),
                        map_res(take(2usize), |hex: &str| u8::from_str_radix(hex, 16)),
                    ),
                ),
                |(algorithm, fingerprint)| Self {
                    algorithm,
                    fingerprint,
                },
            ),
        )(i)
    }
}

impl fmt::Display for FingerprintAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            FingerprintAlgorithm::SHA1 => "SHA-1",
            FingerprintAlgorithm::SHA224 => "SHA-224",
            FingerprintAlgorithm::SHA256 => "SHA-256",
            FingerprintAlgorithm::SHA384 => "SHA-384",
            FingerprintAlgorithm::SHA512 => "SHA-512",
            FingerprintAlgorithm::MD5 => "MD5",
            FingerprintAlgorithm::MD2 => "MD2",
            FingerprintAlgorithm::Other(bytes_str) => bytes_str.as_str(),
        })
    }
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ", self.algorithm)?;

        let mut iter = self.fingerprint.iter();

        if let Some(b) = iter.next() {
            write!(f, "{b:2X}")?;

            for b in iter {
                write!(f, ":{b:02X}")?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn fingerprint() {
        let input = BytesStr::from_static(
            "SHA-256 D7:87:8B:B1:29:F2:19:E4:D3:06:C9:66:32:58:2C:65:4E:3E:81:3B:EC:CE:26:8C:4D:71:8A:B5:49:E0:8E:94",
        );

        let (rem, fingerprint) = Fingerprint::parse(input.as_ref(), &input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(fingerprint.algorithm, FingerprintAlgorithm::SHA256);

        assert_eq!(
            fingerprint.fingerprint,
            [
                0xD7, 0x87, 0x8B, 0xB1, 0x29, 0xF2, 0x19, 0xE4, 0xD3, 0x06, 0xC9, 0x66, 0x32, 0x58,
                0x2C, 0x65, 0x4E, 0x3E, 0x81, 0x3B, 0xEC, 0xCE, 0x26, 0x8C, 0x4D, 0x71, 0x8A, 0xB5,
                0x49, 0xE0, 0x8E, 0x94
            ]
        );

        assert_eq!(fingerprint.to_string(), input.as_str());
    }
}
