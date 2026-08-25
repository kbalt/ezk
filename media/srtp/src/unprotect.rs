use std::collections::HashMap;

use crate::cipher::{aes_cm, aes_cm_iv, aes_gcm, aes_gcm_srtcp_iv, aes_gcm_srtp_iv};
use crate::index::RtpIndex;
use crate::keys::{SessionKeys, SrtpKeys};
use crate::packet::{self, RTCP_HEADER_LEN};
use crate::profile::{SRTCP_INDEX_LEN, SrtpProfile};
use crate::replay::{DEFAULT_WINDOW, ReplayWindow};
use crate::{SrtpError, auth};

/// Unprotects inbound SRTP and SRTCP packets
///
/// One unprotector covers every SSRC received under the same master key. Per stream
/// state, the rollover counter and the replay windows, is created when the first
/// *authentic* packet for an SSRC arrives; packets that fail to authenticate leave no
/// trace, so a peer cannot make the map grow by spoofing SSRCs.
pub struct SrtpUnprotector {
    keys: SessionKeys,
    window: u16,
    streams: HashMap<u32, InboundStream>,
}

struct InboundStream {
    rtp_index: RtpIndex,
    rtp_replay: ReplayWindow,
    rtcp_replay: ReplayWindow,
}

impl InboundStream {
    fn new(window: u16) -> Self {
        Self {
            rtp_index: RtpIndex::default(),
            rtp_replay: ReplayWindow::new(window),
            rtcp_replay: ReplayWindow::new(window),
        }
    }
}

impl SrtpUnprotector {
    /// Create an unprotector for the inbound direction of a session
    pub fn new(keys: SrtpKeys) -> Self {
        Self {
            keys: SessionKeys::derive(&keys),
            window: DEFAULT_WINDOW,
            streams: HashMap::new(),
        }
    }

    /// Set the replay window size in packets, rounded up to a multiple of 64
    ///
    /// Defaults to 128, which is what libsrtp uses. Has no effect on streams that have
    /// already received a packet.
    pub fn replay_window(mut self, packets: u16) -> Self {
        self.window = packets;
        self
    }

    /// Build from session keys directly, for the RFC 7714 packet vectors
    #[cfg(test)]
    pub(crate) fn from_session_keys(keys: crate::keys::SessionKeys) -> Self {
        Self {
            keys,
            window: crate::replay::DEFAULT_WINDOW,
            streams: std::collections::HashMap::new(),
        }
    }

    /// The profile in use
    pub fn profile(&self) -> SrtpProfile {
        self.keys.profile
    }

    /// Replace the keys, keeping the rollover counter and replay windows of every stream
    pub fn rekey(&mut self, keys: SrtpKeys) {
        self.keys = SessionKeys::derive(&keys);
    }

    /// Unprotect an SRTP packet, writing the RTP packet into `out`
    ///
    /// `out` is cleared first and is left empty when an error is returned, so `srtp` can
    /// still be inspected or logged by the caller.
    pub fn unprotect_rtp(&mut self, srtp: &[u8], out: &mut Vec<u8>) -> Result<(), SrtpError> {
        out.clear();

        let result = self.unprotect_rtp_inner(srtp, out);
        if result.is_err() {
            out.clear();
        }
        result
    }

    fn unprotect_rtp_inner(&mut self, srtp: &[u8], out: &mut Vec<u8>) -> Result<(), SrtpError> {
        let profile = self.keys.profile;
        let tag_len = profile.rtp_auth_tag_len();

        let body_len = srtp
            .len()
            .checked_sub(tag_len)
            .ok_or(SrtpError::PacketTooShort)?;

        let (body, tag) = srtp.split_at(body_len);
        let header = packet::parse_rtp(body)?;

        // An unknown SSRC is served from a provisional stream that is only inserted once
        // the packet authenticates. Inserting it up front would let anyone who can reach
        // the socket allocate per stream state for every spoofed SSRC they care to send,
        // which is unbounded growth for the cost of one small packet. libsrtp guards the
        // same way, cloning its template stream only after the auth check passes.
        let mut provisional = None;
        let stream = match self.streams.get_mut(&header.ssrc) {
            Some(stream) => stream,
            None => provisional.insert(InboundStream::new(self.window)),
        };

        // The index is only an estimate until the packet is authenticated, so neither the
        // rollover counter nor the replay window is updated before that succeeds
        let index = stream.rtp_index.estimate(header.seq);
        stream.rtp_replay.check(index)?;

        out.reserve(body.len());

        if profile.is_aead() {
            out.extend_from_slice(body);

            let iv = aes_gcm_srtp_iv(&self.keys.rtp_salt, header.ssrc, index);
            let (aad, ciphertext) = out.split_at_mut(header.payload_offset);
            aes_gcm::open(&self.keys.rtp_key, &iv, aad, ciphertext, tag)?;
        } else {
            let roc = RtpIndex::roc_of(index).to_be_bytes();
            if !auth::verify(&self.keys.rtp_auth, &[body, &roc], tag) {
                return Err(SrtpError::AuthFailed);
            }

            out.extend_from_slice(body);

            let iv = aes_cm_iv(&self.keys.rtp_salt, header.ssrc, index);
            aes_cm::apply(&self.keys.rtp_key, &iv, &mut out[header.payload_offset..]);
        }

        stream.rtp_index.commit(index);
        stream.rtp_replay.add(index);

        // The packet is genuine, so this SSRC has earned its state
        if let Some(stream) = provisional {
            self.streams.insert(header.ssrc, stream);
        }

        Ok(())
    }

    /// Unprotect an SRTCP packet, writing the RTCP packet into `out`
    ///
    /// `out` is cleared first and is left empty when an error is returned.
    pub fn unprotect_rtcp(&mut self, srtcp: &[u8], out: &mut Vec<u8>) -> Result<(), SrtpError> {
        out.clear();

        let result = self.unprotect_rtcp_inner(srtcp, out);
        if result.is_err() {
            out.clear();
        }
        result
    }

    fn unprotect_rtcp_inner(&mut self, srtcp: &[u8], out: &mut Vec<u8>) -> Result<(), SrtpError> {
        let profile = self.keys.profile;
        let tag_len = profile.rtcp_auth_tag_len();

        if srtcp.len() < RTCP_HEADER_LEN + tag_len + SRTCP_INDEX_LEN {
            return Err(SrtpError::PacketTooShort);
        }

        let ssrc = packet::parse_rtcp_ssrc(srtcp)?;

        // The AEAD profiles put the tag before the index trailer (RFC 7714 section 9.1),
        // the counter mode profiles put it after (RFC 3711 section 3.4)
        let (payload_end, e_index_bytes, tag) = if profile.is_aead() {
            let index_at = srtcp.len() - SRTCP_INDEX_LEN;
            let tag_at = index_at - tag_len;
            (tag_at, &srtcp[index_at..], &srtcp[tag_at..index_at])
        } else {
            let tag_at = srtcp.len() - tag_len;
            let index_at = tag_at - SRTCP_INDEX_LEN;
            (index_at, &srtcp[index_at..tag_at], &srtcp[tag_at..])
        };

        let e_index = u32::from_be_bytes(
            e_index_bytes
                .try_into()
                .map_err(|_| SrtpError::MalformedPacket)?,
        );
        let encrypted = e_index & 0x8000_0000 != 0;
        let index = e_index & 0x7fff_ffff;

        // Provisional until the packet authenticates, see `unprotect_rtp_inner`
        let mut provisional = None;
        let stream = match self.streams.get_mut(&ssrc) {
            Some(stream) => stream,
            None => provisional.insert(InboundStream::new(self.window)),
        };

        stream.rtcp_replay.check(u64::from(index))?;

        if profile.is_aead() {
            let iv = aes_gcm_srtcp_iv(&self.keys.rtcp_salt, ssrc, index);

            if encrypted {
                let mut aad = [0u8; RTCP_HEADER_LEN + SRTCP_INDEX_LEN];
                aad[..RTCP_HEADER_LEN].copy_from_slice(&srtcp[..RTCP_HEADER_LEN]);
                aad[RTCP_HEADER_LEN..].copy_from_slice(e_index_bytes);

                out.extend_from_slice(&srtcp[..payload_end]);
                aes_gcm::open(
                    &self.keys.rtcp_key,
                    &iv,
                    &aad,
                    &mut out[RTCP_HEADER_LEN..],
                    tag,
                )?;
            } else {
                // RFC 7714 section 9.2: with the E flag clear nothing is encrypted and
                // the entire packet is associated data
                let mut aad = Vec::with_capacity(payload_end + SRTCP_INDEX_LEN);
                aad.extend_from_slice(&srtcp[..payload_end]);
                aad.extend_from_slice(e_index_bytes);

                aes_gcm::open(&self.keys.rtcp_key, &iv, &aad, &mut [], tag)?;
                out.extend_from_slice(&srtcp[..payload_end]);
            }
        } else {
            // The authenticated portion covers the header, the payload and the trailer
            let authenticated = &srtcp[..payload_end + SRTCP_INDEX_LEN];
            if !auth::verify(&self.keys.rtcp_auth, &[authenticated], tag) {
                return Err(SrtpError::AuthFailed);
            }

            out.extend_from_slice(&srtcp[..payload_end]);

            if encrypted {
                let iv = aes_cm_iv(&self.keys.rtcp_salt, ssrc, u64::from(index));
                aes_cm::apply(&self.keys.rtcp_key, &iv, &mut out[RTCP_HEADER_LEN..]);
            }
        }

        stream.rtcp_replay.add(u64::from(index));

        if let Some(stream) = provisional {
            self.streams.insert(ssrc, stream);
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{SrtpKeys, SrtpProfile, SrtpProtector};

    fn keys(profile: SrtpProfile) -> SrtpKeys {
        let material = vec![0x5au8; profile.key_and_salt_len()];
        SrtpKeys::from_concatenated(profile, &material).expect("valid keys")
    }

    fn rtp_with_ssrc(ssrc: u32, seq: u16) -> Vec<u8> {
        let mut pkt = vec![0x80, 0x60];
        pkt.extend_from_slice(&seq.to_be_bytes());
        pkt.extend_from_slice(&[0, 0, 0, 0]);
        pkt.extend_from_slice(&ssrc.to_be_bytes());
        pkt.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        pkt
    }

    fn rtcp_with_ssrc(ssrc: u32) -> Vec<u8> {
        let mut pkt = vec![0x80, 0xc9, 0x00, 0x01];
        pkt.extend_from_slice(&ssrc.to_be_bytes());
        pkt
    }

    /// An attacker who can reach the socket must not be able to make us allocate per
    /// stream state, or every spoofed SSRC costs us memory for the price of one packet.
    /// libsrtp only clones its template stream after the auth check, and so do we.
    #[test]
    fn unauthenticated_packets_do_not_allocate_stream_state() {
        for &profile in SrtpProfile::ALL {
            // Protected with one key, received with another, so nothing authenticates
            let mut forger = SrtpProtector::new(keys(profile));
            let mut receiver = SrtpUnprotector::new(
                SrtpKeys::from_concatenated(profile, &vec![0xa5u8; profile.key_and_salt_len()])
                    .expect("valid keys"),
            );

            let mut out = Vec::new();

            for ssrc in 0..500u32 {
                let mut forged = Vec::new();
                forger
                    .protect_rtp(&rtp_with_ssrc(ssrc, 1), &mut forged)
                    .expect("protect");
                assert!(receiver.unprotect_rtp(&forged, &mut out).is_err());

                let mut forged = Vec::new();
                forger
                    .protect_rtcp(&rtcp_with_ssrc(ssrc), &mut forged)
                    .expect("protect");
                assert!(receiver.unprotect_rtcp(&forged, &mut out).is_err());
            }

            assert_eq!(
                receiver.streams.len(),
                0,
                "{profile:?} retained state for unauthenticated SSRCs"
            );
        }
    }

    /// The flip side: a genuine packet must still get lasting state, otherwise the
    /// rollover counter and replay window would reset on every packet
    #[test]
    fn authenticated_packets_do_allocate_stream_state() {
        for &profile in SrtpProfile::ALL {
            let mut sender = SrtpProtector::new(keys(profile));
            let mut receiver = SrtpUnprotector::new(keys(profile));
            let mut out = Vec::new();

            for ssrc in 0..3u32 {
                let mut protected = Vec::new();
                sender
                    .protect_rtp(&rtp_with_ssrc(ssrc, 1), &mut protected)
                    .expect("protect");
                receiver
                    .unprotect_rtp(&protected, &mut out)
                    .expect("unprotect");
            }

            assert_eq!(receiver.streams.len(), 3, "{profile:?}");

            // And the retained state must actually be used: a replay is now detected,
            // which is only possible if the window survived the first delivery
            let mut protected = Vec::new();
            sender
                .protect_rtp(&rtp_with_ssrc(0, 2), &mut protected)
                .expect("protect");
            receiver
                .unprotect_rtp(&protected, &mut out)
                .expect("unprotect");
            assert_eq!(
                receiver.unprotect_rtp(&protected, &mut out),
                Err(SrtpError::ReplayFail),
                "{profile:?}"
            );
        }
    }
}
