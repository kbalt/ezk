use std::collections::HashMap;

use crate::cipher::{aes_cm, aes_cm_iv, aes_gcm, aes_gcm_srtcp_iv, aes_gcm_srtp_iv};
use crate::index::RtpIndex;
use crate::keys::{SessionKeys, SrtpKeys};
use crate::packet::{self, RTCP_HEADER_LEN};
use crate::profile::{GCM_TAG_LEN, SRTCP_INDEX_LEN, SrtpProfile};
use crate::replay::{DEFAULT_WINDOW, MAX_WINDOW, MIN_WINDOW, ReplayWindow};
use crate::{SrtpError, auth};

/// Unprotects inbound SRTP and SRTCP packets
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

    /// Set the size of the replay windows in packets, rounded up to the next multiple of 64
    ///
    /// Clamped to 64..=32768: below 64 the window is smaller than RFC 3711 section 3.3.2
    /// allows, and above 2^15 it can never be filled by a genuine packet.
    pub fn replay_window(mut self, packets: u16) -> Self {
        self.window = packets.clamp(MIN_WINDOW, MAX_WINDOW);
        self
    }

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

    /// Replace the keys, keeping the state of every stream
    pub fn rekey(&mut self, keys: SrtpKeys) {
        self.keys = SessionKeys::derive(&keys);
    }

    /// State for `ssrc`, created if absent
    ///
    /// Must only be called once a packet has passed authentication, so a peer cannot make
    /// the receiver allocate by sending forged SSRCs.
    fn stream_mut(&mut self, ssrc: u32) -> &mut InboundStream {
        self.streams
            .entry(ssrc)
            .or_insert_with(|| InboundStream::new(self.window))
    }

    /// Unprotect an SRTP packet in place, turning `buf` into the RTP packet
    ///
    /// `buf` is cleared on error
    pub fn unprotect_rtp(&mut self, buf: &mut Vec<u8>) -> Result<(), SrtpError> {
        let result = self.unprotect_rtp_inner(buf);
        if result.is_err() {
            buf.clear();
        }
        result
    }

    fn unprotect_rtp_inner(&mut self, buf: &mut Vec<u8>) -> Result<(), SrtpError> {
        let profile = self.keys.profile;
        let tag_len = profile.rtp_auth_tag_len();

        let body_len = buf
            .len()
            .checked_sub(tag_len)
            .ok_or(SrtpError::PacketTooShort)?;

        let header = packet::parse_rtp(&buf[..body_len])?;
        profile.check_cipher_len(body_len - header.payload_offset)?;

        // An unseen SSRC has no state to consult: its index is just the sequence number
        // and its replay window is empty, so neither check can fail
        let index = match self.streams.get(&header.ssrc) {
            Some(stream) => {
                let index = stream.rtp_index.estimate(header.seq);
                stream.rtp_replay.check(index)?;
                index
            }
            None => u64::from(header.seq),
        };

        if profile.is_aead() {
            let iv = aes_gcm_srtp_iv(&self.keys.rtp_salt, header.ssrc, index);
            let (body, tag) = buf.split_at_mut(body_len);
            let (aad, ciphertext) = body.split_at_mut(header.payload_offset);
            aes_gcm::open(&self.keys.rtp_key, &iv, aad, ciphertext, tag)?;
        } else {
            let roc = RtpIndex::roc_of(index).to_be_bytes();
            let (body, tag) = buf.split_at(body_len);
            if !auth::verify(&self.keys.rtp_auth, &[body, &roc], tag) {
                return Err(SrtpError::AuthFailed);
            }

            let iv = aes_cm_iv(&self.keys.rtp_salt, header.ssrc, index);
            aes_cm::apply(
                &self.keys.rtp_key,
                &iv,
                &mut buf[header.payload_offset..body_len],
            )?;
        }

        buf.truncate(body_len);

        // Verified, so it is now worth keeping state for this SSRC
        let stream = self.stream_mut(header.ssrc);
        stream.rtp_index.commit(index);
        stream.rtp_replay.add(index);

        Ok(())
    }

    /// Unprotect an SRTCP packet in place, turning `buf` into the RTCP packet
    ///
    /// `buf` is cleared on error
    pub fn unprotect_rtcp(&mut self, buf: &mut Vec<u8>) -> Result<(), SrtpError> {
        let result = self.unprotect_rtcp_inner(buf);
        if result.is_err() {
            buf.clear();
        }
        result
    }

    fn unprotect_rtcp_inner(&mut self, buf: &mut Vec<u8>) -> Result<(), SrtpError> {
        let profile = self.keys.profile;
        let tag_len = profile.rtcp_auth_tag_len();

        if buf.len() < RTCP_HEADER_LEN + tag_len + SRTCP_INDEX_LEN {
            return Err(SrtpError::PacketTooShort);
        }

        let ssrc = packet::parse_rtcp_ssrc(buf)?;

        // The AEAD profiles put the tag before the index trailer (RFC 7714 section 9.1),
        // the counter mode profiles put it after (RFC 3711 section 3.4)
        let (payload_end, index_at, tag_at) = if profile.is_aead() {
            let index_at = buf.len() - SRTCP_INDEX_LEN;
            let tag_at = index_at - tag_len;
            (tag_at, index_at, tag_at)
        } else {
            let tag_at = buf.len() - tag_len;
            let index_at = tag_at - SRTCP_INDEX_LEN;
            (index_at, index_at, tag_at)
        };

        profile.check_cipher_len(payload_end - RTCP_HEADER_LEN)?;

        // Copied out of the buffer so that the rest can be decrypted in place
        let mut e_index_bytes = [0u8; SRTCP_INDEX_LEN];
        e_index_bytes.copy_from_slice(&buf[index_at..index_at + SRTCP_INDEX_LEN]);

        let mut tag = [0u8; GCM_TAG_LEN];
        let tag = &mut tag[..tag_len];
        tag.copy_from_slice(&buf[tag_at..tag_at + tag_len]);

        let e_index = u32::from_be_bytes(e_index_bytes);
        let encrypted = e_index & 0x8000_0000 != 0;
        let index = e_index & 0x7fff_ffff;

        // As for SRTP, an unseen SSRC has an empty replay window that accepts anything
        if let Some(stream) = self.streams.get(&ssrc) {
            stream.rtcp_replay.check(u64::from(index))?;
        }

        if profile.is_aead() {
            let iv = aes_gcm_srtcp_iv(&self.keys.rtcp_salt, ssrc, index);

            if encrypted {
                let mut aad = [0u8; RTCP_HEADER_LEN + SRTCP_INDEX_LEN];
                aad[..RTCP_HEADER_LEN].copy_from_slice(&buf[..RTCP_HEADER_LEN]);
                aad[RTCP_HEADER_LEN..].copy_from_slice(&e_index_bytes);

                aes_gcm::open(
                    &self.keys.rtcp_key,
                    &iv,
                    &aad,
                    &mut buf[RTCP_HEADER_LEN..payload_end],
                    tag,
                )?;
            } else {
                // RFC 7714 section 9.2: with the E flag clear nothing is encrypted and
                // the whole packet plus the index trailer is associated data. The two are
                // not adjacent on the wire, so the trailer is moved over the tag, which
                // has already been copied out.
                buf.copy_within(index_at..index_at + SRTCP_INDEX_LEN, payload_end);

                let aad_end = payload_end + SRTCP_INDEX_LEN;
                aes_gcm::open(&self.keys.rtcp_key, &iv, &buf[..aad_end], &mut [], tag)?;
            }
        } else {
            // The authenticated portion covers the header, the payload and the trailer
            let authenticated = &buf[..payload_end + SRTCP_INDEX_LEN];
            if !auth::verify(&self.keys.rtcp_auth, &[authenticated], tag) {
                return Err(SrtpError::AuthFailed);
            }

            if encrypted {
                let iv = aes_cm_iv(&self.keys.rtcp_salt, ssrc, u64::from(index));
                aes_cm::apply(
                    &self.keys.rtcp_key,
                    &iv,
                    &mut buf[RTCP_HEADER_LEN..payload_end],
                )?;
            }
        }

        buf.truncate(payload_end);

        // Verified, so it is now worth keeping state for this SSRC
        self.stream_mut(ssrc).rtcp_replay.add(u64::from(index));

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{SrtpKeys, SrtpProfile, SrtpProtector};
    use std::alloc::{GlobalAlloc, Layout, System};
    use std::cell::Cell;

    thread_local! {
        static ALLOCATIONS: Cell<u64> = const { Cell::new(0) };
    }

    struct CountingAllocator;

    unsafe impl GlobalAlloc for CountingAllocator {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            let _ = ALLOCATIONS.try_with(|c| c.set(c.get() + 1));
            unsafe { System.alloc(layout) }
        }

        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { System.dealloc(ptr, layout) }
        }

        unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
            let _ = ALLOCATIONS.try_with(|c| c.set(c.get() + 1));
            unsafe { System.realloc(ptr, layout, new_size) }
        }
    }

    #[global_allocator]
    static ALLOCATOR: CountingAllocator = CountingAllocator;

    fn generate_test_keys(profile: SrtpProfile, key: u8) -> SrtpKeys {
        let material = vec![key; profile.key_and_salt_len()];
        SrtpKeys::from_concatenated(profile, &material).expect("valid keys")
    }

    fn generate_test_rtp_packet(ssrc: u32, seq: u16) -> Vec<u8> {
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

    #[test]
    fn unauthenticated_packets_do_not_allocate_stream_state() {
        for &profile in SrtpProfile::ALL {
            let mut forger = SrtpProtector::new(generate_test_keys(profile, 0));
            let mut receiver = SrtpUnprotector::new(generate_test_keys(profile, 1));

            for ssrc in 0..500u32 {
                let mut forged = generate_test_rtp_packet(ssrc, 1);
                forger.protect_rtp(&mut forged).unwrap();
                assert!(receiver.unprotect_rtp(&mut forged).is_err());

                let mut forged = rtcp_with_ssrc(ssrc);
                forger.protect_rtcp(&mut forged).unwrap();
                assert!(receiver.unprotect_rtcp(&mut forged).is_err());
            }

            assert_eq!(
                receiver.streams.len(),
                0,
                "{profile:?} retained state for unauthenticated SSRCs"
            );
        }
    }

    #[test]
    fn the_replay_window_is_clamped_to_a_usable_range() {
        let profile = SrtpProfile::AEAD_AES_128_GCM;

        for (asked, expected) in [
            (0u16, MIN_WINDOW),
            (1, MIN_WINDOW),
            (63, MIN_WINDOW),
            (64, 64),
            (4096, 4096),
            (MAX_WINDOW, MAX_WINDOW),
            (u16::MAX, MAX_WINDOW),
        ] {
            let receiver =
                SrtpUnprotector::new(generate_test_keys(profile, 0)).replay_window(asked);

            assert_eq!(receiver.window, expected, "asked for {asked}");
        }
    }

    #[test]
    fn unauthenticated_packets_do_not_allocate() {
        for &profile in SrtpProfile::ALL {
            let mut forger = SrtpProtector::new(generate_test_keys(profile, 0));
            let mut receiver = SrtpUnprotector::new(generate_test_keys(profile, 1));

            // Warm the working buffer and stream map so the measurement sees only what
            // handling the packet itself costs. Unprotecting consumes the buffer, so the
            // forged packets are copied into it rather than passed directly.
            let mut buf = Vec::with_capacity(4096);
            receiver.streams.reserve(64);

            let mut forged_rtp = generate_test_rtp_packet(1, 1);
            forger.protect_rtp(&mut forged_rtp).unwrap();
            let mut forged_rtcp = rtcp_with_ssrc(1);
            forger.protect_rtcp(&mut forged_rtcp).unwrap();

            let before = ALLOCATIONS.with(|c| c.get());

            for ssrc in 0..200u32 {
                // Rewrite the SSRC in place so every packet looks like a new stream
                forged_rtp[8..12].copy_from_slice(&ssrc.to_be_bytes());
                buf.clear();
                buf.extend_from_slice(&forged_rtp);
                assert!(receiver.unprotect_rtp(&mut buf).is_err());

                forged_rtcp[4..8].copy_from_slice(&ssrc.to_be_bytes());
                buf.clear();
                buf.extend_from_slice(&forged_rtcp);
                assert!(receiver.unprotect_rtcp(&mut buf).is_err());
            }

            assert_eq!(
                ALLOCATIONS.with(|c| c.get()) - before,
                0,
                "{profile:?} allocated while rejecting forged packets"
            );
        }
    }

    /// A genuine packet must get lasting state, otherwise the rollover counter and replay
    /// window would reset on every packet
    #[test]
    fn authenticated_packets_do_allocate_stream_state() {
        for &profile in SrtpProfile::ALL {
            let mut sender = SrtpProtector::new(generate_test_keys(profile, 0));
            let mut receiver = SrtpUnprotector::new(generate_test_keys(profile, 0));

            for ssrc in 0..3u32 {
                let mut buf = generate_test_rtp_packet(ssrc, 1);
                sender.protect_rtp(&mut buf).expect("protect");
                receiver.unprotect_rtp(&mut buf).expect("unprotect");
            }

            assert_eq!(receiver.streams.len(), 3, "{profile:?}");

            // The retained state must be used: a replay is only detected if the window
            // survived the first delivery
            let mut protected = generate_test_rtp_packet(0, 2);
            sender.protect_rtp(&mut protected).expect("protect");

            let mut replay = protected.clone();
            receiver.unprotect_rtp(&mut protected).expect("unprotect");
            assert_eq!(
                receiver.unprotect_rtp(&mut replay),
                Err(SrtpError::ReplayFail),
                "{profile:?}"
            );
        }
    }
}
