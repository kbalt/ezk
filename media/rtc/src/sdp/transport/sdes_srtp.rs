use crate::rtp_transport::RtpSdesSrtpTransport;
use base64::{Engine, prelude::BASE64_STANDARD};
use rand::Rng;
use sdp_types::{
    SrtpCrypto, SrtpKeyingMaterial,
    SrtpSuite::{self, *},
};
use srtp::{SrtpError, SrtpKeys, SrtpProfile, SrtpProtector, SrtpUnprotector};

const SUITES: [SrtpSuite; 4] = [
    AES_256_CM_HMAC_SHA1_80,
    AES_256_CM_HMAC_SHA1_32,
    AES_CM_128_HMAC_SHA1_80,
    AES_CM_128_HMAC_SHA1_32,
];

#[derive(Debug, thiserror::Error)]
pub enum SdesSrtpNegotiationError {
    #[error("Offer does not contain any compatible crypto suite")]
    NoCompatibleSrtpSuite,
    #[error("Failed to decode base64 key in crypto attribute")]
    InvalidBas64(#[from] base64::DecodeError),
    #[error("Failed to create SRTP session")]
    CreateSrtpSession(#[from] SrtpError),
}

pub(super) fn negotiate_from_offer(
    remote_crypto: &[SrtpCrypto],
) -> Result<RtpSdesSrtpTransport, SdesSrtpNegotiationError> {
    let crypto = SUITES
        .iter()
        .find_map(|suite| {
            remote_crypto
                .iter()
                .find(|c| c.suite == *suite && !c.keys.is_empty())
        })
        .ok_or(SdesSrtpNegotiationError::NoCompatibleSrtpSuite)?;

    let recv_key = BASE64_STANDARD.decode(&crypto.keys[0].key_and_salt)?;

    let profile = srtp_suite_to_profile(&crypto.suite).expect("Previously checked the suite");

    let mut send_key = vec![0u8; profile.key_and_salt_len()];
    rand::rng().fill_bytes(&mut send_key);

    let inbound = SrtpUnprotector::new(SrtpKeys::from_concatenated(profile, &recv_key)?);
    let outbound = SrtpProtector::new(SrtpKeys::from_concatenated(profile, &send_key)?);

    Ok(RtpSdesSrtpTransport::new(
        SrtpCrypto {
            tag: crypto.tag,
            suite: crypto.suite.clone(),
            keys: vec![SrtpKeyingMaterial {
                key_and_salt: BASE64_STANDARD.encode(&send_key).into(),
                lifetime: None,
                mki: None,
            }],
            params: vec![],
        },
        inbound,
        outbound,
    ))
}

pub(super) struct SdesSrtpOffer {
    keys: Vec<(SrtpSuite, Vec<u8>)>,
}

impl SdesSrtpOffer {
    pub(super) fn new() -> Self {
        let mut keys = vec![];

        for suite in SUITES {
            let profile = srtp_suite_to_profile(&suite).expect("only using known working suites");

            let mut send_key = vec![0u8; profile.key_and_salt_len()];
            rand::rng().fill_bytes(&mut send_key);

            keys.push((suite, send_key));
        }

        Self { keys }
    }

    pub(super) fn extend_crypto(&self, crypto: &mut Vec<SrtpCrypto>) {
        for (tag, (suite, key)) in self.keys.iter().enumerate() {
            let send_key = BASE64_STANDARD.encode(key);

            crypto.push(SrtpCrypto {
                tag: (tag + 1) as u32,
                suite: suite.clone(),
                keys: vec![SrtpKeyingMaterial {
                    key_and_salt: send_key.into(),
                    lifetime: None,
                    mki: None,
                }],
                params: vec![],
            });
        }
    }

    pub(super) fn receive_answer(
        self,
        remote_crypto: &[SrtpCrypto],
    ) -> Result<RtpSdesSrtpTransport, SdesSrtpNegotiationError> {
        for (index, (suite, send_key)) in self.keys.into_iter().enumerate() {
            let tag = index as u32 + 1;

            let Some(crypto) = remote_crypto
                .iter()
                .find(|c| c.tag == tag && c.suite == suite)
            else {
                continue;
            };

            let recv_key = BASE64_STANDARD.decode(&crypto.keys[0].key_and_salt)?;

            let local_sdp_crypto = SrtpCrypto {
                tag,
                suite: suite.clone(),
                keys: vec![SrtpKeyingMaterial {
                    key_and_salt: BASE64_STANDARD.encode(&send_key).into(),
                    lifetime: None,
                    mki: None,
                }],
                params: vec![],
            };

            let profile = srtp_suite_to_profile(&suite).expect("suite is one we offered");

            let inbound = SrtpUnprotector::new(SrtpKeys::from_concatenated(profile, &recv_key)?);
            let outbound = SrtpProtector::new(SrtpKeys::from_concatenated(profile, &send_key)?);

            return Ok(RtpSdesSrtpTransport::new(
                local_sdp_crypto,
                inbound,
                outbound,
            ));
        }

        Err(SdesSrtpNegotiationError::NoCompatibleSrtpSuite)
    }
}

fn srtp_suite_to_profile(suite: &SrtpSuite) -> Option<SrtpProfile> {
    match suite {
        SrtpSuite::AES_CM_128_HMAC_SHA1_80 => Some(SrtpProfile::AES_CM_128_HMAC_SHA1_80),
        SrtpSuite::AES_CM_128_HMAC_SHA1_32 => Some(SrtpProfile::AES_CM_128_HMAC_SHA1_32),
        SrtpSuite::AES_192_CM_HMAC_SHA1_80 => Some(SrtpProfile::AES_CM_192_HMAC_SHA1_80),
        SrtpSuite::AES_192_CM_HMAC_SHA1_32 => Some(SrtpProfile::AES_CM_192_HMAC_SHA1_32),
        SrtpSuite::AES_256_CM_HMAC_SHA1_80 => Some(SrtpProfile::AES_CM_256_HMAC_SHA1_80),
        SrtpSuite::AES_256_CM_HMAC_SHA1_32 => Some(SrtpProfile::AES_CM_256_HMAC_SHA1_32),
        SrtpSuite::AEAD_AES_128_GCM => Some(SrtpProfile::AEAD_AES_128_GCM),
        SrtpSuite::AEAD_AES_256_GCM => Some(SrtpProfile::AEAD_AES_256_GCM),
        _ => None,
    }
}
