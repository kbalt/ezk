//! Test vectors from RFC 9335 appendix A.

use crate::keys::SessionKeys;
use crate::{SrtpKeys, SrtpProfile, SrtpProtector, SrtpUnprotector, hex};

/// RFC 9335 appendix A.1
const CTR_MASTER_KEY: &str = "e1f97a0d3e018be0d64fa32c06de4139";
const CTR_MASTER_SALT: &str = "0ec675ad498afeebb6960b3aabe6";

/// Session material appendix A.1 prints for the pair above
const CTR_SESSION_KEY: &str = "c61e7a93744f39ee10734afe3ff7a087";
const CTR_SESSION_SALT: &str = "30cbbc08863d8c85d49db34a9ae1";
const CTR_AUTH_KEY: &str = "cebe321f6ff7716b6fd4ab49af256a156d38baa4";

/// RFC 9335 appendix A.2
const GCM_MASTER_KEY: &str = "000102030405060708090a0b0c0d0e0f";
const GCM_MASTER_SALT: &str = "a0a1a2a3a4a5a6a7a8a9aaab";

/// Session material appendix A.2 prints for the pair above
const GCM_SESSION_KEY: &str = "077c6143cb221bc355ff23d5f984a16e";
const GCM_SESSION_SALT: &str = "9af3e95364ebac9c99c5a7c4";

/// RFC 9335 appendix A.1.1 and A.2.1
const RTP_ONE_BYTE: &str = concat!(
    "900f1235", // X=1, CC=0, PT=15, seq 0x1235
    "decafbad", // timestamp
    "cafebabe", // ssrc
    "bede0001", // one byte framing, one word of data
    "51000200", "abababab", "abababab", "abababab", "abababab",
);

/// RFC 9335 appendix A.1.2 and A.2.2
const RTP_TWO_BYTE: &str = concat!(
    "900f1236", "decafbad", "cafebabe", "10000001", // two byte framing, appbits clear
    "05020002", "abababab", "abababab", "abababab", "abababab",
);

/// RFC 9335 appendix A.1.3 and A.2.3
const RTP_ONE_BYTE_CSRC: &str = concat!(
    "920f1238", "decafbad", "cafebabe", "0001e240", // csrc 0
    "0000b26e", // csrc 1
    "bede0001", "51000200", "abababab", "abababab", "abababab", "abababab",
);

/// RFC 9335 appendix A.1.4 and A.2.4
const RTP_TWO_BYTE_CSRC: &str = concat!(
    "920f1239", "decafbad", "cafebabe", "0001e240", "0000b26e", "10000001", "05020002", "abababab",
    "abababab", "abababab", "abababab",
);

/// RFC 9335 appendix A.1.5 and A.2.5, the empty block section 5.1 requires
const RTP_EMPTY_ONE_BYTE_CSRC: &str = concat!(
    "920f123a", "decafbad", "cafebabe", "0001e240", "0000b26e", "bede0000", "abababab", "abababab",
    "abababab", "abababab",
);

/// RFC 9335 appendix A.1.6 and A.2.6
const RTP_EMPTY_TWO_BYTE_CSRC: &str = concat!(
    "920f123b", "decafbad", "cafebabe", "0001e240", "0000b26e", "10000000", "abababab", "abababab",
    "abababab", "abababab",
);

/// RFC 9335 appendix A.1.1
const SRTP_CTR_ONE_BYTE: &str = concat!(
    "900f1235", "decafbad", "cafebabe", "c0de0001", "eb923652", "51c3e036", "f8de27e9", "c27ee3e0",
    "b4651d9f", "bc4218a7", "0244522f", "34a5",
);

/// RFC 9335 appendix A.1.2
const SRTP_CTR_TWO_BYTE: &str = concat!(
    "900f1236", "decafbad", "cafebabe", "c2de0001", "4ed9cc4e", "6a712b30", "96c5ca77", "339d4204",
    "ce0d7739", "6cab6958", "5fbce381", "94a5",
);

/// RFC 9335 appendix A.1.3, csrcs encrypted in place with the rewritten tag after them
const SRTP_CTR_ONE_BYTE_CSRC: &str = concat!(
    "920f1238", "decafbad", "cafebabe", "8bb6e12b", "5cff16dd", "c0de0001", "92838c8c", "09e58393",
    "e1de3a9a", "74734d67", "45671338", "c3acf11d", "a2df8423", "bee0",
);

/// RFC 9335 appendix A.1.4
const SRTP_CTR_TWO_BYTE_CSRC: &str = concat!(
    "920f1239", "decafbad", "cafebabe", "f70e513e", "b90b9b25", "c2de0001", "bbed4848", "faa64466",
    "5f3d7f34", "125914e9", "f4d0ae92", "3c6f479b", "95a0f7b5", "3133",
);

/// RFC 9335 appendix A.1.5
const SRTP_CTR_EMPTY_ONE_BYTE_CSRC: &str = concat!(
    "920f123a", "decafbad", "cafebabe", "7130b6ab", "fe2ab0e3", "c0de0000", "e3d9f64b", "25c9e74c",
    "b4cf8e43", "fb92e378", "1c2c0cea", "b6b3a499", "a14c",
);

/// RFC 9335 appendix A.1.6
const SRTP_CTR_EMPTY_TWO_BYTE_CSRC: &str = concat!(
    "920f123b", "decafbad", "cafebabe", "cbf24c12", "4330e1c8", "c2de0000", "599dd45b", "c9d687b6",
    "03e8b59d", "771fd38e", "88b170e0", "cd31e125", "eabe",
);

/// RFC 9335 appendix A.2.1
const SRTP_GCM_ONE_BYTE: &str = concat!(
    "900f1235", "decafbad", "cafebabe", "c0de0001", "39972dc9", "572c4d99", "e8fc355d", "e743fb2e",
    "94f9d8ff", "54e72f41", "93bbc5c7", "4ffab0fa", "9fa0fbeb",
);

/// RFC 9335 appendix A.2.2
const SRTP_GCM_TWO_BYTE: &str = concat!(
    "900f1236", "decafbad", "cafebabe", "c2de0001", "bb75a4c5", "45cd1f41", "3bdb7daa", "2b1e3263",
    "de313667", "c9632490", "81b35a65", "f5cb6c88", "b394235f",
);

/// RFC 9335 appendix A.2.3
const SRTP_GCM_ONE_BYTE_CSRC: &str = concat!(
    "920f1238", "decafbad", "cafebabe", "63bbccc4", "a7f695c4", "c0de0001", "8ad7c71f", "ac70a80c",
    "92866b4c", "6ba98546", "ef913586", "e95ffaaf", "fe956885", "bb0647a8", "bc094ac8",
);

/// RFC 9335 appendix A.2.4
const SRTP_GCM_TWO_BYTE_CSRC: &str = concat!(
    "920f1239", "decafbad", "cafebabe", "3680524f", "8d312b00", "c2de0001", "c78d1200", "38422bc1",
    "11a7187a", "18246f98", "0c059cc6", "bc9df8b6", "26394eca", "344e4b05", "d80fea83",
);

/// RFC 9335 appendix A.2.5
const SRTP_GCM_EMPTY_ONE_BYTE_CSRC: &str = concat!(
    "920f123a", "decafbad", "cafebabe", "15b6bb43", "37906fff", "c0de0000", "b7b96453", "7a2b03ab",
    "7ba5389c", "e9331712", "6b5d974d", "f30c6884", "dcb651c5", "e120c1da",
);

/// RFC 9335 appendix A.2.6
const SRTP_GCM_EMPTY_TWO_BYTE_CSRC: &str = concat!(
    "920f123b", "decafbad", "cafebabe", "dcb38c9e", "48bf95f4", "c2de0000", "61ee432c", "f9203170",
    "76613258", "d3ce4236", "c06ac429", "681ad084", "13512dc9", "8b5207d8",
);

#[test]
fn aes_ctr_one_byte_header_extension() {
    check_aes_ctr(RTP_ONE_BYTE, SRTP_CTR_ONE_BYTE);
}

#[test]
fn aes_ctr_two_byte_header_extension() {
    check_aes_ctr(RTP_TWO_BYTE, SRTP_CTR_TWO_BYTE);
}

#[test]
fn aes_ctr_one_byte_header_extension_with_csrcs() {
    check_aes_ctr(RTP_ONE_BYTE_CSRC, SRTP_CTR_ONE_BYTE_CSRC);
}

#[test]
fn aes_ctr_two_byte_header_extension_with_csrcs() {
    check_aes_ctr(RTP_TWO_BYTE_CSRC, SRTP_CTR_TWO_BYTE_CSRC);
}

#[test]
fn aes_ctr_empty_one_byte_header_extension_with_csrcs() {
    check_aes_ctr(RTP_EMPTY_ONE_BYTE_CSRC, SRTP_CTR_EMPTY_ONE_BYTE_CSRC);
}

#[test]
fn aes_ctr_empty_two_byte_header_extension_with_csrcs() {
    check_aes_ctr(RTP_EMPTY_TWO_BYTE_CSRC, SRTP_CTR_EMPTY_TWO_BYTE_CSRC);
}

#[test]
fn aes_gcm_one_byte_header_extension() {
    check_aes_gcm(RTP_ONE_BYTE, SRTP_GCM_ONE_BYTE);
}

#[test]
fn aes_gcm_two_byte_header_extension() {
    check_aes_gcm(RTP_TWO_BYTE, SRTP_GCM_TWO_BYTE);
}

#[test]
fn aes_gcm_one_byte_header_extension_with_csrcs() {
    check_aes_gcm(RTP_ONE_BYTE_CSRC, SRTP_GCM_ONE_BYTE_CSRC);
}

#[test]
fn aes_gcm_two_byte_header_extension_with_csrcs() {
    check_aes_gcm(RTP_TWO_BYTE_CSRC, SRTP_GCM_TWO_BYTE_CSRC);
}

#[test]
fn aes_gcm_empty_one_byte_header_extension_with_csrcs() {
    check_aes_gcm(RTP_EMPTY_ONE_BYTE_CSRC, SRTP_GCM_EMPTY_ONE_BYTE_CSRC);
}

#[test]
fn aes_gcm_empty_two_byte_header_extension_with_csrcs() {
    check_aes_gcm(RTP_EMPTY_TWO_BYTE_CSRC, SRTP_GCM_EMPTY_TWO_BYTE_CSRC);
}

#[test]
fn key_derivation_function() {
    let ctr = SessionKeys::derive(&master_keys(
        SrtpProfile::AES_CM_128_HMAC_SHA1_80,
        CTR_MASTER_KEY,
        CTR_MASTER_SALT,
    ));
    assert_eq!(to_hex(&ctr.rtp_key), CTR_SESSION_KEY, "A.1 session key");
    assert_eq!(to_hex(&ctr.rtp_salt), CTR_SESSION_SALT, "A.1 session salt");
    assert_eq!(
        to_hex(&ctr.rtp_auth),
        CTR_AUTH_KEY,
        "A.1 authentication key"
    );

    let gcm = SessionKeys::derive(&master_keys(
        SrtpProfile::AEAD_AES_128_GCM,
        GCM_MASTER_KEY,
        GCM_MASTER_SALT,
    ));
    assert_eq!(to_hex(&gcm.rtp_key), GCM_SESSION_KEY, "A.2 session key");
    assert_eq!(to_hex(&gcm.rtp_salt), GCM_SESSION_SALT, "A.2 session salt");
}

fn master_keys(profile: SrtpProfile, key: &str, salt: &str) -> SrtpKeys {
    SrtpKeys::new(profile, &hex(key), &hex(salt)).unwrap()
}

fn check_aes_ctr(rtp: &str, expected: &str) {
    check(
        SrtpProfile::AES_CM_128_HMAC_SHA1_80,
        CTR_MASTER_KEY,
        CTR_MASTER_SALT,
        rtp,
        expected,
    );
}

fn check_aes_gcm(rtp: &str, expected: &str) {
    check(
        SrtpProfile::AEAD_AES_128_GCM,
        GCM_MASTER_KEY,
        GCM_MASTER_SALT,
        rtp,
        expected,
    );
}

fn check(profile: SrtpProfile, key: &str, salt: &str, rtp: &str, expected: &str) {
    let rtp = hex(rtp);
    let expected = hex(expected);

    let mut sender = SrtpProtector::new(master_keys(profile, key, salt)).cryptex(true);
    let mut buf = rtp.clone();
    sender.protect_rtp(&mut buf).unwrap();
    assert_eq!(to_hex(&buf), to_hex(&expected), "{profile:?} protect");

    assert_eq!(
        buf.len(),
        rtp.len() + profile.rtp_overhead(),
        "{profile:?} cryptex adds nothing beyond the tag"
    );

    assert_eq!(buf[..12], rtp[..12], "{profile:?} fixed header stays clear");
    assert_ne!(
        buf[12..rtp.len()],
        rtp[12..],
        "{profile:?} csrcs and extension"
    );

    let mut buf = expected.clone();
    SrtpUnprotector::new(master_keys(profile, key, salt))
        .unprotect_rtp(&mut buf)
        .unwrap();
    assert_eq!(to_hex(&buf), to_hex(&rtp), "{profile:?} unprotect");
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
