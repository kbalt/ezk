//! Packet level test vectors from RFC 7714 sections 16 and 17.
//!
//! These are stated in terms of the session key and salt rather than the master key, so
//! they are applied below the key derivation function via
//! [`SessionKeys::from_session_material`]. Key derivation itself is pinned by the
//! RFC 3711 appendix B.3 vectors in [`crate::kdf`].

use crate::keys::SessionKeys;
use crate::{SrtpProfile, SrtpProtector, SrtpUnprotector, hex};

const KEY_128: &str = "000102030405060708090a0b0c0d0e0f";
const KEY_256: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const SALT: &str = "517569642070726f2071756f";

/// RFC 7714 section 16, a 12 octet header carrying sequence number 0xf17b and SSRC
/// 0x5501a0b2
const RTP: &str = "8040f17b8041f8d35501a0b247616c6c696120657374206f6d6e69732064697669736120696e207061727465732074726573";

/// RFC 7714 section 16.1.1
const SRTP_128: &str = "8040f17b8041f8d35501a0b2f24de3a3fb34de6cacba861c9d7e4bcabe633bd50d294e6f42a5f47a51c7d19b36de3adf8833899d7f27beb16a9152cf765ee4390cce";

/// RFC 7714 section 16.2.1
const SRTP_256: &str = "8040f17b8041f8d35501a0b232b1de78a822fe12ef9f78fa332e33aab18012389a58e2f3b50b2a0276ffae0f1ba63799b87b7aa3db36dfffd6b0f9bb7878d7a76c13";

/// The packet that RFC 7714 sections 17.1 to 17.4 operate on, SSRC "Mars"
///
/// The preamble of section 17 prints a different packet than the subsections encrypt and
/// decrypt. The subsections are internally consistent, so this follows them.
const RTCP: &str = "81c8000d4d6172734e5450314e545032525450200000042a0000e9304c756e61deadbeefdeadbeefdeadbeefdeadbeefdeadbeef";

/// RFC 7714 section 17.1
const SRTCP_128: &str = "81c8000d4d61727363e94885dcdab67ca727d7662f6b7e997ff5c0f76c06f32dc676a5f1730d6fda4ce09b4686303ded0bb9275bc84aa45896cf4d2fc5abf87245d9eade800005d4";

/// RFC 7714 section 17.2
const SRTCP_256: &str = "81c8000d4d617273d50ae4d1f5ce5d304ba297e47d470c282c3ece5dbffe0a50a2eaa5c1110555be8415f658c61de0476f1b6fad1d1eb30c4446839f57ff6f6cb26ac3be800005d4";

/// RFC 7714 section 17.3, tagged but not encrypted so the `E` flag is clear
const SRTCP_128_TAG_ONLY: &str = "81c8000d4d6172734e5450314e545032525450200000042a0000e9304c756e61deadbeefdeadbeefdeadbeefdeadbeefdeadbeef841dd9683dd78ec92ae58790125f62b3000005d4";

/// The SRTCP index every section 17 vector uses
const SRTCP_INDEX: u32 = 0x5d4;

fn protector(profile: SrtpProfile, key: &str) -> SrtpProtector {
    SrtpProtector::from_session_keys(SessionKeys::from_session_material(
        profile,
        &hex(key),
        &hex(SALT),
    ))
}

fn unprotector(profile: SrtpProfile, key: &str) -> SrtpUnprotector {
    SrtpUnprotector::from_session_keys(SessionKeys::from_session_material(
        profile,
        &hex(key),
        &hex(SALT),
    ))
}

#[test]
fn srtp_aead_aes_128_gcm() {
    check_srtp(SrtpProfile::AEAD_AES_128_GCM, KEY_128, SRTP_128);
}

#[test]
fn srtp_aead_aes_256_gcm() {
    check_srtp(SrtpProfile::AEAD_AES_256_GCM, KEY_256, SRTP_256);
}

fn check_srtp(profile: SrtpProfile, key: &str, expected: &str) {
    let rtp = hex(RTP);
    let expected = hex(expected);

    // First packet of its stream, so the rollover counter is zero as the vector assumes
    let mut buf = rtp.clone();
    protector(profile, key)
        .protect_rtp(&mut buf)
        .expect("protect");
    assert_eq!(to_hex(&buf), to_hex(&expected), "{profile:?} protect");

    let mut buf = expected.clone();
    unprotector(profile, key)
        .unprotect_rtp(&mut buf)
        .expect("unprotect");
    assert_eq!(to_hex(&buf), to_hex(&rtp), "{profile:?} unprotect");
}

#[test]
fn srtcp_aead_aes_128_gcm() {
    check_srtcp(SrtpProfile::AEAD_AES_128_GCM, KEY_128, SRTCP_128);
}

#[test]
fn srtcp_aead_aes_256_gcm() {
    check_srtcp(SrtpProfile::AEAD_AES_256_GCM, KEY_256, SRTCP_256);
}

fn check_srtcp(profile: SrtpProfile, key: &str, expected: &str) {
    let rtcp = hex(RTCP);
    let expected = hex(expected);

    // Unprotecting reads the index out of the packet, so it needs no setup
    let mut buf = expected.clone();
    unprotector(profile, key)
        .unprotect_rtcp(&mut buf)
        .expect("unprotect");
    assert_eq!(to_hex(&buf), to_hex(&rtcp), "{profile:?} unprotect");

    // Protecting counts up from index 1, so wind the stream forward to the vector's index
    let mut sender = protector(profile, key);
    for _ in 1..SRTCP_INDEX {
        let mut scratch = rtcp.clone();
        sender.protect_rtcp(&mut scratch).expect("protect");
    }

    let mut buf = rtcp.clone();
    sender.protect_rtcp(&mut buf).expect("protect");
    assert_eq!(to_hex(&buf), to_hex(&expected), "{profile:?} protect");
}

/// RFC 7714 section 17.3: with the `E` flag clear nothing is encrypted and the whole
/// packet plus the index trailer is associated data
#[test]
fn srtcp_tag_only_is_accepted() {
    let rtcp = hex(RTCP);
    let tagged = hex(SRTCP_128_TAG_ONLY);

    let mut buf = tagged.clone();
    unprotector(SrtpProfile::AEAD_AES_128_GCM, KEY_128)
        .unprotect_rtcp(&mut buf)
        .expect("unprotect");

    assert_eq!(to_hex(&buf), to_hex(&rtcp));
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
