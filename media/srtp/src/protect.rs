use crate::{
    SrtpError, auth,
    cipher::{aes_cm, aes_cm_iv, aes_gcm, aes_gcm_srtcp_iv, aes_gcm_srtp_iv},
    cryptex,
    index::{KEY_SOFT_LIMIT, MAX_RTCP_INDEX, MAX_RTP_INDEX, RtpIndex},
    keys::{SessionKeys, SrtpKeys},
    packet::{self, RTCP_HEADER_LEN},
    profile::{HMAC_SHA1_KEY_LEN, SRTCP_INDEX_LEN, SrtpProfile},
    replay::ReplayWindow,
};
use std::collections::HashMap;

/// Protects outbound RTP and RTCP packets
///
/// One protector covers every SSRC sent with the same master key. Per stream state is
/// created when the first packet for an SSRC is protected.
pub struct SrtpProtector {
    keys: SessionKeys,
    cryptex: bool,
    streams: HashMap<u32, OutboundStream>,
}

#[derive(Default)]
struct OutboundStream {
    rtp_index: RtpIndex,
    /// Records which SRTP indices have been used, so an index is never reused and a
    /// keystream never repeated
    rtp_used: ReplayWindow,
    /// 31 bit SRTCP index of the most recently sent packet
    rtcp_index: u32,
}

impl SrtpProtector {
    /// Create a protector for the outbound direction of a session
    pub fn new(keys: SrtpKeys) -> Self {
        Self {
            keys: SessionKeys::derive(&keys),
            cryptex: false,
            streams: HashMap::new(),
        }
    }

    /// Enable or disable cryptex [RFC 9335](https://datatracker.ietf.org/doc/html/rfc9335)
    ///
    /// false by default
    pub fn cryptex(mut self, enabled: bool) -> Self {
        self.cryptex = enabled;
        self
    }

    /// Enable or disable cryptex [RFC 9335](https://datatracker.ietf.org/doc/html/rfc9335)
    ///
    /// false by default
    pub fn set_cryptex(&mut self, enabled: bool) {
        self.cryptex = enabled;
    }

    /// Build from session keys directly, bypassing the key derivation function
    #[cfg(test)]
    pub(crate) fn from_session_keys(keys: crate::keys::SessionKeys) -> Self {
        Self {
            keys,
            cryptex: false,
            streams: std::collections::HashMap::new(),
        }
    }

    /// The profile in use
    pub fn profile(&self) -> SrtpProfile {
        self.keys.profile
    }

    /// Whether the current keys are approaching the limit RFC 3711 section 9.2 puts on a
    /// master key
    ///
    /// A master key may protect at most 2^48 SRTP and 2^31 SRTCP packets. This turns true
    /// once fewer than 2^16 of either are left on any stream. Past the limit
    /// [`SrtpProtector::protect_rtp`] and [`SrtpProtector::protect_rtcp`] fail with
    /// [`SrtpError::IndexExhausted`], so a caller that can rekey should do so while this
    /// is true.
    pub fn key_expiring(&self) -> bool {
        self.streams.values().any(|stream| {
            MAX_RTP_INDEX - stream.rtp_index.current() < KEY_SOFT_LIMIT
                || u64::from(MAX_RTCP_INDEX - stream.rtcp_index) < KEY_SOFT_LIMIT
        })
    }

    /// Replace the keys, keeping the rollover counter and SRTCP index of every stream
    ///
    /// The caller must not pass the same key material again: reusing a key with indices
    /// that have already been used repeats a keystream.
    pub fn rekey(&mut self, keys: SrtpKeys) {
        self.keys = SessionKeys::derive(&keys);
    }

    /// Protect an RTP packet in place, turning `buf` into the SRTP packet
    ///
    /// `buf` is cleared on error
    pub fn protect_rtp(&mut self, buf: &mut Vec<u8>) -> Result<(), SrtpError> {
        let result = self.protect_rtp_inner(buf);

        if result.is_err() {
            buf.clear();
        }

        result
    }

    fn protect_rtp_inner(&mut self, buf: &mut Vec<u8>) -> Result<(), SrtpError> {
        let profile = self.keys.profile;
        let header = packet::parse_rtp(buf)?;

        let cryptex_profile = if self.cryptex {
            cryptex::profile_to_cryptex_profile(&header)?
        } else {
            None
        };

        let enc_start = match cryptex_profile {
            Some(_) => cryptex::ENC_START,
            None => header.payload_offset,
        };

        profile.check_cipher_len(buf.len() - enc_start)?;

        let stream = self.streams.entry(header.ssrc).or_default();
        let index = stream.rtp_index.estimate(header.seq);
        if index >= MAX_RTP_INDEX {
            return Err(SrtpError::IndexExhausted);
        }

        stream.rtp_used.check(index)?;

        buf.reserve(profile.rtp_overhead());

        if let Some(cryptex_profile) = cryptex_profile {
            cryptex::set_extension_profile(buf, header.csrc_count, cryptex_profile);
            cryptex::to_cipher_order(buf, header.csrc_count);
        }

        if profile.is_aead() {
            // RFC 7714 section 9: the whole header, including CSRC list and header
            // extension, is the associated data and only the payload is encrypted
            let iv = aes_gcm_srtp_iv(&self.keys.rtp_salt, header.ssrc, index);
            let (aad, payload) = buf.split_at_mut(enc_start);
            let tag = aes_gcm::seal(&self.keys.rtp_key, &iv, aad, payload)?;

            if cryptex_profile.is_some() {
                cryptex::to_wire_order(buf, header.csrc_count);
            }

            buf.extend_from_slice(&tag);
        } else {
            let iv = aes_cm_iv(&self.keys.rtp_salt, header.ssrc, index);
            aes_cm::apply(&self.keys.rtp_key, &iv, &mut buf[enc_start..])?;

            // The tag covers the packet in wire order, so undo the swap before computing it
            if cryptex_profile.is_some() {
                cryptex::to_wire_order(buf, header.csrc_count);
            }

            // RFC 3711 section 4.2: the rollover counter is appended to the authenticated
            // portion but is not transmitted
            let roc = RtpIndex::roc_of(index).to_be_bytes();
            let tag_len = profile.rtp_auth_tag_len();
            let mut tag = [0u8; HMAC_SHA1_KEY_LEN];
            auth::tag(&self.keys.rtp_auth, &[&buf[..], &roc], &mut tag[..tag_len]);
            buf.extend_from_slice(&tag[..tag_len]);
        }

        stream.rtp_index.commit(index);
        stream.rtp_used.add(index);

        Ok(())
    }

    /// Protect an RTCP packet in place, turning `buf` into the SRTCP packet
    ///
    /// `buf` is cleared on error
    pub fn protect_rtcp(&mut self, buf: &mut Vec<u8>) -> Result<(), SrtpError> {
        let result = self.protect_rtcp_inner(buf);

        if result.is_err() {
            buf.clear();
        }

        result
    }

    fn protect_rtcp_inner(&mut self, buf: &mut Vec<u8>) -> Result<(), SrtpError> {
        let profile = self.keys.profile;
        let ssrc = packet::parse_rtcp_ssrc(buf)?;

        profile.check_cipher_len(buf.len() - RTCP_HEADER_LEN)?;

        let stream = self.streams.entry(ssrc).or_default();
        let index = stream.rtcp_index + 1;

        if index > MAX_RTCP_INDEX {
            return Err(SrtpError::IndexExhausted);
        }

        // The E flag marks the packet as encrypted (RFC 3711 section 3.4)
        let e_index = (index | 0x8000_0000).to_be_bytes();

        buf.reserve(profile.rtcp_overhead());

        if profile.is_aead() {
            // RFC 7714 section 9.1: the AAD is the 8 byte header plus the index trailer,
            // and the tag is written before the trailer
            let mut aad = [0u8; RTCP_HEADER_LEN + SRTCP_INDEX_LEN];
            aad[..RTCP_HEADER_LEN].copy_from_slice(&buf[..RTCP_HEADER_LEN]);
            aad[RTCP_HEADER_LEN..].copy_from_slice(&e_index);

            let iv = aes_gcm_srtcp_iv(&self.keys.rtcp_salt, ssrc, index);
            let tag = aes_gcm::seal(&self.keys.rtcp_key, &iv, &aad, &mut buf[RTCP_HEADER_LEN..])?;

            buf.extend_from_slice(&tag);
            buf.extend_from_slice(&e_index);
        } else {
            let iv = aes_cm_iv(&self.keys.rtcp_salt, ssrc, u64::from(index));
            aes_cm::apply(&self.keys.rtcp_key, &iv, &mut buf[RTCP_HEADER_LEN..])?;
            buf.extend_from_slice(&e_index);

            // The authenticated portion covers the header, the ciphertext and the trailer
            let tag_len = profile.rtcp_auth_tag_len();
            let mut tag = [0u8; HMAC_SHA1_KEY_LEN];
            auth::tag(&self.keys.rtcp_auth, &[&buf[..]], &mut tag[..tag_len]);
            buf.extend_from_slice(&tag[..tag_len]);
        }

        stream.rtcp_index = index;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::SrtpKeys;

    const SSRC: u32 = 0xdead_beef;

    fn protector() -> SrtpProtector {
        let profile = SrtpProfile::AEAD_AES_128_GCM;
        let material = vec![0x5au8; profile.key_and_salt_len()];

        SrtpProtector::new(SrtpKeys::from_concatenated(profile, &material).expect("valid keys"))
    }

    #[test]
    fn key_expiring_precedes_index_exhaustion() {
        let mut sender = protector();
        assert!(!sender.key_expiring(), "fresh keys");

        let stream = sender.streams.entry(SSRC).or_default();
        stream.rtp_index.commit(MAX_RTP_INDEX - KEY_SOFT_LIMIT);
        assert!(!sender.key_expiring(), "one packet before the soft limit");

        let stream = sender.streams.entry(SSRC).or_default();
        stream.rtp_index.commit(MAX_RTP_INDEX - KEY_SOFT_LIMIT + 1);
        assert!(sender.key_expiring(), "at the soft limit");
    }

    #[test]
    fn the_srtcp_index_has_its_own_soft_limit() {
        let mut sender = protector();

        let stream = sender.streams.entry(SSRC).or_default();
        stream.rtcp_index = MAX_RTCP_INDEX - u32::try_from(KEY_SOFT_LIMIT).unwrap();
        assert!(!sender.key_expiring());

        let stream = sender.streams.entry(SSRC).or_default();
        stream.rtcp_index = MAX_RTCP_INDEX - u32::try_from(KEY_SOFT_LIMIT).unwrap() + 1;
        assert!(sender.key_expiring());
    }

    #[test]
    fn key_expiring_reports_the_worst_stream() {
        let mut sender = protector();

        sender.streams.entry(1).or_default().rtp_index.commit(5);
        assert!(!sender.key_expiring());

        sender
            .streams
            .entry(2)
            .or_default()
            .rtp_index
            .commit(MAX_RTP_INDEX - 1);
        assert!(sender.key_expiring());
    }
}
