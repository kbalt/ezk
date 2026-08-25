use core::fmt;
use zeroize::Zeroizing;

use crate::kdf;
use crate::profile::SrtpProfile;
use crate::{SrtpError, kdf::*};

/// The master key and master salt protecting one direction of an SRTP session
///
/// Key material is zeroized when the value is dropped.
#[derive(Clone)]
pub struct SrtpKeys {
    profile: SrtpProfile,
    master_key: Zeroizing<Vec<u8>>,
    master_salt: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for SrtpKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print key material
        f.debug_struct("SrtpKeys")
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}

impl SrtpKeys {
    /// Create keys from a separate master key and master salt
    ///
    /// Both must have exactly the length the profile requires, see
    /// [`SrtpProfile::master_key_len`] and [`SrtpProfile::master_salt_len`].
    pub fn new(
        profile: SrtpProfile,
        master_key: &[u8],
        master_salt: &[u8],
    ) -> Result<Self, SrtpError> {
        if master_key.len() != profile.master_key_len() {
            return Err(SrtpError::BadKeyLength {
                expected: profile.master_key_len(),
                got: master_key.len(),
            });
        }

        if master_salt.len() != profile.master_salt_len() {
            return Err(SrtpError::BadKeyLength {
                expected: profile.master_salt_len(),
                got: master_salt.len(),
            });
        }

        Ok(Self {
            profile,
            master_key: Zeroizing::new(master_key.to_vec()),
            master_salt: Zeroizing::new(master_salt.to_vec()),
        })
    }

    /// Create keys from the master key and master salt concatenated
    ///
    /// This is the layout of the base64 decoded keying material of an SDES `a=crypto`
    /// attribute (RFC 4568 section 6.1).
    pub fn from_concatenated(profile: SrtpProfile, key_and_salt: &[u8]) -> Result<Self, SrtpError> {
        let key_len = profile.master_key_len();

        if key_and_salt.len() != profile.key_and_salt_len() {
            return Err(SrtpError::BadKeyLength {
                expected: profile.key_and_salt_len(),
                got: key_and_salt.len(),
            });
        }

        Self::new(profile, &key_and_salt[..key_len], &key_and_salt[key_len..])
    }

    /// Split DTLS-SRTP keying material into the keys for both directions
    ///
    /// Per RFC 5764 section 4.2 the exporter output is laid out as
    ///
    /// ```text
    /// client_write_SRTP_master_key  || server_write_SRTP_master_key ||
    /// client_write_SRTP_master_salt || server_write_SRTP_master_salt
    /// ```
    ///
    /// so each endpoint's key and salt have to be paired up. Each side reads what the
    /// other writes, which is what `is_server` selects.
    ///
    /// Returns `(inbound, outbound)`.
    pub fn from_keying_material(
        profile: SrtpProfile,
        keying_material: &[u8],
        is_server: bool,
    ) -> Result<(SrtpKeys, SrtpKeys), SrtpError> {
        let key_len = profile.master_key_len();
        let salt_len = profile.master_salt_len();
        let expected = 2 * (key_len + salt_len);

        if keying_material.len() != expected {
            return Err(SrtpError::BadKeyLength {
                expected,
                got: keying_material.len(),
            });
        }

        let (keys, salts) = keying_material.split_at(2 * key_len);
        let (client_key, server_key) = keys.split_at(key_len);
        let (client_salt, server_salt) = salts.split_at(salt_len);

        let client = SrtpKeys::new(profile, client_key, client_salt)?;
        let server = SrtpKeys::new(profile, server_key, server_salt)?;

        if is_server {
            Ok((client, server))
        } else {
            Ok((server, client))
        }
    }

    /// The profile these keys are for
    pub fn profile(&self) -> SrtpProfile {
        self.profile
    }
}

/// The session keys derived from a master key
///
/// These depend only on the master key, master salt and derivation label, not on the
/// SSRC, so they are shared by every stream using the same [`SrtpKeys`].
pub(crate) struct SessionKeys {
    pub(crate) profile: SrtpProfile,

    pub(crate) rtp_key: Zeroizing<Vec<u8>>,
    pub(crate) rtp_salt: Zeroizing<Vec<u8>>,
    pub(crate) rtp_auth: Zeroizing<Vec<u8>>,

    pub(crate) rtcp_key: Zeroizing<Vec<u8>>,
    pub(crate) rtcp_salt: Zeroizing<Vec<u8>>,
    pub(crate) rtcp_auth: Zeroizing<Vec<u8>>,
}

impl SessionKeys {
    /// Build session keys directly, bypassing the key derivation function
    #[cfg(test)]
    pub(crate) fn from_session_material(profile: SrtpProfile, key: &[u8], salt: &[u8]) -> Self {
        Self {
            profile,
            rtp_key: Zeroizing::new(key.to_vec()),
            rtp_salt: Zeroizing::new(salt.to_vec()),
            rtp_auth: Zeroizing::new(Vec::new()),
            rtcp_key: Zeroizing::new(key.to_vec()),
            rtcp_salt: Zeroizing::new(salt.to_vec()),
            rtcp_auth: Zeroizing::new(Vec::new()),
        }
    }

    pub(crate) fn derive(keys: &SrtpKeys) -> Self {
        let profile = keys.profile;

        let derive = |label: u8, len: usize| {
            let mut out = Zeroizing::new(vec![0u8; len]);
            kdf::derive(&keys.master_key, &keys.master_salt, label, &mut out);
            out
        };

        // Session salt and cipher key have the same lengths as the master salt and master
        // key (RFC 3711 section 4.3.1, RFC 7714 section 12)
        Self {
            profile,
            rtp_key: derive(LABEL_RTP_ENCRYPTION, profile.master_key_len()),
            rtp_salt: derive(LABEL_RTP_SALT, profile.master_salt_len()),
            rtp_auth: derive(LABEL_RTP_AUTHENTICATION, profile.auth_key_len()),
            rtcp_key: derive(LABEL_RTCP_ENCRYPTION, profile.master_key_len()),
            rtcp_salt: derive(LABEL_RTCP_SALT, profile.master_salt_len()),
            rtcp_auth: derive(LABEL_RTCP_AUTHENTICATION, profile.auth_key_len()),
        }
    }
}
