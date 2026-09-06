use crate::ffi;
use core::mem::MaybeUninit;

/// Describes a particular crypto policy that can be applied to an SRTP stream.
///
/// An [`SrtpPolicy`](crate::SrtpPolicy) consists of a list of these policies, one for each SRTP stream in the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CryptoPolicy {
    pub(crate) policy: ffi::srtp_crypto_policy_t,
}

impl CryptoPolicy {
    /// Length of the key required for this crypto policy
    pub fn key_len(&self) -> usize {
        self.policy.cipher_key_len as usize
    }
}

macro_rules! fns {
    ($($rust_fn:ident, $c_fn:ident;)*) => {
        impl CryptoPolicy {
            $(
            pub fn $rust_fn() -> Self {
                unsafe {
                    let mut policy = MaybeUninit::uninit();
                    ffi::$c_fn(policy.as_mut_ptr());
                    Self { policy: policy.assume_init() }
                }
            }
            )*
        }

        #[test]
        fn ensure_linked() {
            use std::hint::black_box;
            $(
                black_box(CryptoPolicy::$rust_fn());
            )*
        }
    };
}

fns! {
    aes_cm_128_hmac_sha1_80, srtp_crypto_policy_set_rtp_default;
    aes_cm_128_hmac_sha1_32, srtp_crypto_policy_set_aes_cm_128_hmac_sha1_32;
    aes_cm_128_null_auth, srtp_crypto_policy_set_aes_cm_128_null_auth;
    null_cipher_hmac_sha1_80, srtp_crypto_policy_set_null_cipher_hmac_sha1_80;
    null_cipher_hmac_null, srtp_crypto_policy_set_null_cipher_hmac_null;
    aes_cm_256_hmac_sha1_80, srtp_crypto_policy_set_aes_cm_256_hmac_sha1_80;
    aes_cm_256_hmac_sha1_32, srtp_crypto_policy_set_aes_cm_256_hmac_sha1_32;
    aes_cm_256_null_auth, srtp_crypto_policy_set_aes_cm_256_null_auth;
    aes_cm_192_hmac_sha1_80, srtp_crypto_policy_set_aes_cm_192_hmac_sha1_80;
    aes_cm_192_hmac_sha1_32, srtp_crypto_policy_set_aes_cm_192_hmac_sha1_32;
    aes_cm_192_null_auth, srtp_crypto_policy_set_aes_cm_192_null_auth;
    aes_gcm_128_8_auth, srtp_crypto_policy_set_aes_gcm_128_8_auth;
    aes_gcm_256_8_auth, srtp_crypto_policy_set_aes_gcm_256_8_auth;
    aes_gcm_128_8_only_auth, srtp_crypto_policy_set_aes_gcm_128_8_only_auth;
    aes_gcm_256_8_only_auth, srtp_crypto_policy_set_aes_gcm_256_8_only_auth;
    aes_gcm_128_16_auth, srtp_crypto_policy_set_aes_gcm_128_16_auth;
    aes_gcm_256_16_auth, srtp_crypto_policy_set_aes_gcm_256_16_auth;
}
