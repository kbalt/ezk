use crate::SrtpError;
use crate::profile::GCM_TAG_LEN;
use aes::cipher::InOutBuf;
use aes_gcm::{AeadInOut, Aes128Gcm, Aes256Gcm, KeyInit, Nonce, Tag};

/// Encrypt `buf` in place with `aad` as associated data and return the tag
///
/// # Panics
///
/// Panics if `key` is not 16 or 32 bytes long.
pub(crate) fn seal(
    key: &[u8],
    iv: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> Result<[u8; GCM_TAG_LEN], SrtpError> {
    let nonce = Nonce::cast_from_core(iv);

    let tag: Tag = match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .expect("lengths checked")
            .encrypt_inout_detached(nonce, aad, InOutBuf::from(buf)),
        32 => Aes256Gcm::new_from_slice(key)
            .expect("lengths checked")
            .encrypt_inout_detached(nonce, aad, InOutBuf::from(buf)),
        len => unreachable!("unsupported AES-GCM key length {len}"),
    }
    .map_err(|_| SrtpError::CipherFailed)?;

    let mut out = [0u8; GCM_TAG_LEN];
    out.copy_from_slice(&tag);
    Ok(out)
}

/// Decrypt `buf` in place, verifying `tag` over the ciphertext and `aad`
///
/// `buf` is left in an unspecified state when the tag does not verify.
///
/// # Panics
///
/// Panics if `key` is not 16 or 32 bytes long.
pub(crate) fn open(
    key: &[u8],
    iv: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8],
) -> Result<(), SrtpError> {
    let tag: [u8; GCM_TAG_LEN] = tag.try_into().map_err(|_| SrtpError::MalformedPacket)?;
    let tag = Tag::from(tag);
    let nonce = Nonce::cast_from_core(iv);

    match key.len() {
        16 => Aes128Gcm::new_from_slice(key)
            .expect("lengths checked")
            .decrypt_inout_detached(nonce, aad, InOutBuf::from(buf), &tag),
        32 => Aes256Gcm::new_from_slice(key)
            .expect("lengths checked")
            .decrypt_inout_detached(nonce, aad, InOutBuf::from(buf), &tag),
        len => unreachable!("unsupported AES-GCM key length {len}"),
    }
    .map_err(|_| SrtpError::AuthFailed)
}
