use std::collections::HashMap;

use crate::cipher::{aes_cm, aes_cm_iv, aes_gcm, aes_gcm_srtcp_iv, aes_gcm_srtp_iv};
use crate::index::{MAX_RTCP_INDEX, MAX_RTP_INDEX, RtpIndex};
use crate::keys::{SessionKeys, SrtpKeys};
use crate::packet::{self, RTCP_HEADER_LEN};
use crate::profile::{HMAC_SHA1_KEY_LEN, SRTCP_INDEX_LEN, SrtpProfile};
use crate::replay::ReplayWindow;
use crate::{SrtpError, auth};

/// Protects outbound RTP and RTCP packets
///
/// One protector covers every SSRC sent with the same master key. Per stream state, the
/// rollover counter and the SRTCP index, is created when the first packet for an SSRC is
/// protected.
pub struct SrtpProtector {
    keys: SessionKeys,
    streams: HashMap<u32, OutboundStream>,
}

#[derive(Default)]
struct OutboundStream {
    rtp_index: RtpIndex,
    /// Records which SRTP indices have been used. Reusing an index would repeat a
    /// keystream, which breaks confidentiality outright, so this is a hard error rather
    /// than a policy knob.
    rtp_used: ReplayWindow,
    /// 31 bit SRTCP index of the most recently sent packet
    rtcp_index: u32,
}

impl SrtpProtector {
    /// Create a protector for the outbound direction of a session
    pub fn new(keys: SrtpKeys) -> Self {
        Self {
            keys: SessionKeys::derive(&keys),
            streams: HashMap::new(),
        }
    }

    /// Build from session keys directly, for the RFC 7714 packet vectors
    #[cfg(test)]
    pub(crate) fn from_session_keys(keys: crate::keys::SessionKeys) -> Self {
        Self {
            keys,

            streams: std::collections::HashMap::new(),
        }
    }

    /// The profile in use
    pub fn profile(&self) -> SrtpProfile {
        self.keys.profile
    }

    /// Replace the keys, keeping the rollover counter and SRTCP index of every stream
    ///
    /// Preserving the indices is what makes a mid-session rekey transparent to the peer.
    /// The caller must not pass the same key material again: reusing a key with indices
    /// that have already been used repeats a keystream.
    pub fn rekey(&mut self, keys: SrtpKeys) {
        self.keys = SessionKeys::derive(&keys);
    }

    /// Protect an RTP packet, writing the SRTP packet into `out`
    ///
    /// `out` is cleared first and is left empty when an error is returned, so `rtp` can
    /// still be inspected by the caller.
    pub fn protect_rtp(&mut self, rtp: &[u8], out: &mut Vec<u8>) -> Result<(), SrtpError> {
        out.clear();

        let result = self.protect_rtp_inner(rtp, out);
        if result.is_err() {
            out.clear();
        }
        result
    }

    fn protect_rtp_inner(&mut self, rtp: &[u8], out: &mut Vec<u8>) -> Result<(), SrtpError> {
        let header = packet::parse_rtp(rtp)?;
        let profile = self.keys.profile;

        let stream = self.streams.entry(header.ssrc).or_default();

        let index = stream.rtp_index.estimate(header.seq);
        if index >= MAX_RTP_INDEX {
            return Err(SrtpError::IndexExhausted);
        }
        stream.rtp_used.check(index)?;

        out.reserve(rtp.len() + profile.rtp_overhead());
        out.extend_from_slice(rtp);

        if profile.is_aead() {
            // RFC 7714 section 9: the whole header, including CSRC list and header
            // extension, is the associated data and only the payload is encrypted
            let iv = aes_gcm_srtp_iv(&self.keys.rtp_salt, header.ssrc, index);
            let (aad, payload) = out.split_at_mut(header.payload_offset);
            let tag = aes_gcm::seal(&self.keys.rtp_key, &iv, aad, payload)?;
            out.extend_from_slice(&tag);
        } else {
            let iv = aes_cm_iv(&self.keys.rtp_salt, header.ssrc, index);
            aes_cm::apply(&self.keys.rtp_key, &iv, &mut out[header.payload_offset..]);

            // RFC 3711 section 4.2: the rollover counter is appended to the authenticated
            // portion but is not transmitted
            let roc = RtpIndex::roc_of(index).to_be_bytes();
            let tag_len = profile.rtp_auth_tag_len();
            let mut tag = [0u8; HMAC_SHA1_KEY_LEN];
            auth::tag(&self.keys.rtp_auth, &[&out[..], &roc], &mut tag[..tag_len]);
            out.extend_from_slice(&tag[..tag_len]);
        }

        stream.rtp_index.commit(index);
        stream.rtp_used.add(index);

        Ok(())
    }

    /// Protect an RTCP packet, writing the SRTCP packet into `out`
    ///
    /// `out` is cleared first and is left empty when an error is returned.
    pub fn protect_rtcp(&mut self, rtcp: &[u8], out: &mut Vec<u8>) -> Result<(), SrtpError> {
        out.clear();

        let result = self.protect_rtcp_inner(rtcp, out);
        if result.is_err() {
            out.clear();
        }
        result
    }

    fn protect_rtcp_inner(&mut self, rtcp: &[u8], out: &mut Vec<u8>) -> Result<(), SrtpError> {
        let ssrc = packet::parse_rtcp_ssrc(rtcp)?;
        let profile = self.keys.profile;

        let stream = self.streams.entry(ssrc).or_default();

        // libsrtp increments the index before using it, so the first SRTCP packet of a
        // stream carries index 1. Following it keeps the differential tests meaningful,
        // and the value only has to be consistent within a session.
        if stream.rtcp_index >= MAX_RTCP_INDEX {
            return Err(SrtpError::IndexExhausted);
        }
        let index = stream.rtcp_index + 1;

        // The E flag marks the packet as encrypted (RFC 3711 section 3.4)
        let e_index = (index | 0x8000_0000).to_be_bytes();

        out.reserve(rtcp.len() + profile.rtcp_overhead());
        out.extend_from_slice(rtcp);

        if profile.is_aead() {
            // RFC 7714 section 9.1: the AAD is the 8 byte header plus the index trailer,
            // and the tag is written before the trailer
            let mut aad = [0u8; RTCP_HEADER_LEN + SRTCP_INDEX_LEN];
            aad[..RTCP_HEADER_LEN].copy_from_slice(&rtcp[..RTCP_HEADER_LEN]);
            aad[RTCP_HEADER_LEN..].copy_from_slice(&e_index);

            let iv = aes_gcm_srtcp_iv(&self.keys.rtcp_salt, ssrc, index);
            let tag = aes_gcm::seal(&self.keys.rtcp_key, &iv, &aad, &mut out[RTCP_HEADER_LEN..])?;

            out.extend_from_slice(&tag);
            out.extend_from_slice(&e_index);
        } else {
            let iv = aes_cm_iv(&self.keys.rtcp_salt, ssrc, u64::from(index));
            aes_cm::apply(&self.keys.rtcp_key, &iv, &mut out[RTCP_HEADER_LEN..]);
            out.extend_from_slice(&e_index);

            // The authenticated portion covers the header, the ciphertext and the trailer
            let tag_len = profile.rtcp_auth_tag_len();
            let mut tag = [0u8; HMAC_SHA1_KEY_LEN];
            auth::tag(&self.keys.rtcp_auth, &[&out[..]], &mut tag[..tag_len]);
            out.extend_from_slice(&tag[..tag_len]);
        }

        stream.rtcp_index = index;

        Ok(())
    }
}
