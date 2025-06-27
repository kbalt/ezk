use crate::{CryptoPolicy, SrtpError, SrtpPolicy, Ssrc, ffi};
use openssl::ssl::SslRef;
use std::{borrow::Cow, mem::MaybeUninit};

/// Error returned by [`DtlsSrtpPolicies::from_ssl`]
#[derive(Debug, thiserror::Error)]
pub enum SrtpFromSslError {
    #[error("ssl is missing the srtp profile")]
    MissingSrtpProfile,
    #[error("Failed to get the crypto policy from dtls-srtp protection profile")]
    CryptoPolicyFromProfile(#[source] SrtpError),
    #[error("Failed to export keying material")]
    ExportKeyingMaterial(#[source] openssl::error::ErrorStack),
    #[error("Failed to create SrtpPolicy from DTLS key")]
    CreateSrtpPolicy(#[source] SrtpError),
    #[error("Failed to create SrtpSession policy")]
    CreateSrtpSession(#[source] SrtpError),
}

/// SRTP policies which have been extracted from an OpenSSL DTLS session
pub struct DtlsSrtpPolicies {
    pub inbound: SrtpPolicy<'static>,
    pub outbound: SrtpPolicy<'static>,
}

impl DtlsSrtpPolicies {
    // derived from https://github.com/HyeonuPark/srtp/blob/e853208c8dda77daef7d3a58c4ead01b53f062ed/src/openssl.rs#L75
    /// Create SRTP polices from a openssl DTLS session
    pub fn from_ssl(ssl: &SslRef) -> Result<DtlsSrtpPolicies, SrtpFromSslError> {
        let profile = ssl
            .selected_srtp_profile()
            .ok_or(SrtpFromSslError::MissingSrtpProfile)?;

        let profile_id = profile.id().as_raw() as ffi::srtp_profile_t;

        let (rtp_policy, rtcp_policy) = unsafe {
            let mut rtp_policy = MaybeUninit::uninit();
            let mut rtcp_policy = MaybeUninit::uninit();

            ff!(ffi::srtp_crypto_policy_set_from_profile_for_rtp(
                rtp_policy.as_mut_ptr(),
                profile_id,
            ))
            .map_err(SrtpFromSslError::CryptoPolicyFromProfile)?;

            ff!(ffi::srtp_crypto_policy_set_from_profile_for_rtcp(
                rtcp_policy.as_mut_ptr(),
                profile_id,
            ))
            .map_err(SrtpFromSslError::CryptoPolicyFromProfile)?;

            (
                CryptoPolicy {
                    policy: rtp_policy.assume_init(),
                },
                CryptoPolicy {
                    policy: rtcp_policy.assume_init(),
                },
            )
        };

        let mut material = [0u8; ffi::SRTP_MAX_KEY_LEN as usize * 2];

        ssl.export_keying_material(&mut material, "EXTRACTOR-dtls_srtp", None)
            .map_err(SrtpFromSslError::ExportKeyingMaterial)?;

        let (client_key, server_key) = unsafe {
            let master_key_len = ffi::srtp_profile_get_master_key_length(profile_id) as usize;
            let master_salt_len = ffi::srtp_profile_get_master_salt_length(profile_id) as usize;

            let master_len = master_key_len + master_salt_len;
            let rot_start = master_key_len;

            let rot_end = rot_start + master_len;

            material[rot_start..rot_end].rotate_left(master_key_len);

            (
                &material[..master_len],
                &material[master_len..(2 * master_len)],
            )
        };

        let (inbound_key, outbound_key) = if ssl.is_server() {
            (client_key, server_key)
        } else {
            (server_key, client_key)
        };

        let inbound = SrtpPolicy::new(
            rtp_policy,
            rtcp_policy,
            Cow::Owned(inbound_key.into()),
            Ssrc::AnyInbound,
        )
        .map_err(SrtpFromSslError::CreateSrtpPolicy)?;

        let outbound = SrtpPolicy::new(
            rtp_policy,
            rtcp_policy,
            Cow::Owned(outbound_key.into()),
            Ssrc::AnyOutbound,
        )
        .map_err(SrtpFromSslError::CreateSrtpPolicy)?;

        Ok(DtlsSrtpPolicies { inbound, outbound })
    }
}
