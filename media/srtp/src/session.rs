use crate::{
    CryptoPolicy, SrtpError,
    ffi::{self, srtp_add_stream, srtp_update_stream},
};
use std::{borrow::Cow, ffi::c_void, mem::MaybeUninit, ptr};

/// Defines which RTP/RTCP stream a [`SrtpPolicy`] applies to
pub enum Ssrc {
    /// Policy applies to any inbound streams
    AnyInbound,
    /// Policy applies to any outbound streams
    AnyOutbound,
    /// Policy applies to RTP streams with the given SSRC
    Specific(u32),
}

/// Policy which defines how packets are protected.
///
/// May apply to one or more SRTP streams
pub struct SrtpPolicy<'a> {
    policy: ffi::srtp_policy_t,
    _key: Cow<'a, [u8]>,
}

unsafe impl Send for SrtpPolicy<'_> {}
unsafe impl Sync for SrtpPolicy<'_> {}

impl<'a> SrtpPolicy<'a> {
    /// Create a new SRTP policy
    ///
    /// `rtp` - Crypto policy for RTP protection
    /// `rtcp` - Crypto policy for RTCP protection
    /// `key` - Master key used for this policy
    /// `ssrc` - To which streams this policy applies
    pub fn new(
        rtp: CryptoPolicy,
        rtcp: CryptoPolicy,
        key: Cow<'a, [u8]>,
        ssrc: Ssrc,
    ) -> Result<Self, SrtpError> {
        let expected_key_length = [
            rtp.policy.cipher_key_len,
            rtp.policy.auth_key_len,
            rtcp.policy.cipher_key_len,
            rtcp.policy.auth_key_len,
        ]
        .into_iter()
        .max()
        .unwrap();

        if expected_key_length < 0 {
            log::error!("policy key length is negative");
            return Err(SrtpError::BAD_PARAM);
        }

        if key.len() < expected_key_length as usize {
            log::error!(
                "key is too short, expected: {expected_key_length}, got: {}",
                key.len()
            );
            return Err(SrtpError::BAD_PARAM);
        }

        let ssrc = match ssrc {
            Ssrc::AnyInbound => ffi::srtp_ssrc_t {
                type_: ffi::srtp_ssrc_type_t_ssrc_any_inbound,
                value: 0,
            },
            Ssrc::AnyOutbound => ffi::srtp_ssrc_t {
                type_: ffi::srtp_ssrc_type_t_ssrc_any_outbound,
                value: 0,
            },
            Ssrc::Specific(value) => ffi::srtp_ssrc_t {
                type_: ffi::srtp_ssrc_type_t_ssrc_specific,
                value,
            },
        };

        let policy = ffi::srtp_policy_t {
            ssrc,
            rtp: rtp.policy,
            rtcp: rtcp.policy,
            key: key.as_ptr().cast_mut(),
            keys: ptr::null_mut(),
            num_master_keys: 0,
            deprecated_ekt: ptr::null_mut(),
            window_size: 0,
            allow_repeat_tx: 0,
            enc_xtn_hdr: ptr::null_mut(),
            enc_xtn_hdr_count: 0,
            next: ptr::null_mut(),
        };

        Ok(Self { policy, _key: key })
    }

    /// Window size for replay protection
    pub fn window_size(mut self, size: u32) -> Self {
        self.policy.window_size = size.into();
        self
    }

    /// Wether retransmissions of packets with the same sequence number are allowed
    ///
    /// > Note that such repeated transmissions must have the same RTP payload, or a severe security weakness is introduced!
    pub fn allow_repeat_tx(mut self, allow: bool) -> Self {
        self.policy.allow_repeat_tx = allow as _;
        self
    }

    /// List of header ids to encrypt
    pub fn encrypt_header_ids(mut self, header_ids: &'a [i32]) -> Self {
        self.policy.enc_xtn_hdr = header_ids.as_ptr().cast_mut();
        self.policy.enc_xtn_hdr_count = header_ids.len().try_into().unwrap_or(i32::MAX);

        self
    }
}

/// SRTP session
///
/// Contains a list of streams which are configured and matched to [`SrtpPolicy`]
pub struct SrtpSession {
    ctx: *mut ffi::srtp_ctx_t,
}

unsafe impl Send for SrtpSession {}
unsafe impl Sync for SrtpSession {}

impl SrtpSession {
    /// Create a new SRTP context and add the given streams to it
    pub fn new(mut streams: Vec<SrtpPolicy<'_>>) -> Result<Self, SrtpError> {
        crate::init()?;

        let policies = if streams.is_empty() {
            ptr::null_mut()
        } else {
            // Set the `next` field of each policy to the next one
            for i in 0..streams.len() - 1 {
                streams[i].policy.next = &raw mut streams[i + 1].policy;
            }

            &raw mut streams[0].policy
        };

        let mut ctx: MaybeUninit<*mut ffi::srtp_ctx_t> = MaybeUninit::uninit();

        unsafe {
            ff!(ffi::srtp_create(ctx.as_mut_ptr(), policies))?;

            // Make sure stream live beyond the create call
            drop(streams);

            Ok(Self {
                ctx: ctx.assume_init(),
            })
        }
    }

    fn process(
        &mut self,
        buf: &mut Vec<u8>,
        f: impl FnOnce(*mut ffi::srtp_ctx_t, *mut c_void, *mut i32) -> Result<(), SrtpError>,
    ) -> Result<(), SrtpError> {
        let mut len = buf.len().try_into().map_err(|_| {
            log::error!("given buf's len does not fit into i32");
            SrtpError::BAD_PARAM
        })?;

        let capacity = buf.capacity();

        if let Err(e) = f(self.ctx, buf.as_mut_ptr().cast(), &raw mut len) {
            buf.clear();
            return Err(e);
        }

        let len = len.try_into().map_err(|_| {
            log::error!("packet len is outside of usize bounds");
            SrtpError::FAIL
        })?;

        assert!(
            capacity >= len,
            "function mut not set len outside of buf's capacity"
        );

        unsafe { buf.set_len(len) };

        Ok(())
    }

    /// Protect a RTP packet into a SRTP packet
    pub fn protect_rtp(&mut self, buf: &mut Vec<u8>) -> Result<(), SrtpError> {
        buf.reserve(ffi::SRTP_MAX_TRAILER_LEN as usize);

        self.process(buf, |ctx, hdr, len| {
            // ffi::SRTP_MAX_TRAILER_LEN must be reserved
            unsafe { ff!(ffi::srtp_protect(ctx, hdr, len)) }
        })
    }

    /// Protect a RTCP packet into a SRTCP packet
    pub fn protect_rtcp(&mut self, buf: &mut Vec<u8>) -> Result<(), SrtpError> {
        buf.reserve(ffi::SRTP_MAX_SRTCP_TRAILER_LEN as usize);

        self.process(buf, |ctx, hdr, len| unsafe {
            // ffi::SRTP_MAX_TRAILER_LEN must be reserved
            ff!(ffi::srtp_protect_rtcp(ctx, hdr, len))
        })
    }

    /// Unprotect a received SRTP packet into a RTP packet
    pub fn unprotect_rtp(&mut self, buf: &mut Vec<u8>) -> Result<(), SrtpError> {
        self.process(buf, |ctx, hdr, len| unsafe {
            ff!(ffi::srtp_unprotect(ctx, hdr, len))
        })
    }

    /// Unprotect a received SRTCP packet into a RTCP packet
    pub fn unprotect_rtcp(&mut self, buf: &mut Vec<u8>) -> Result<(), SrtpError> {
        self.process(buf, |ctx, hdr, len| unsafe {
            ff!(ffi::srtp_unprotect_rtcp(ctx, hdr, len))
        })
    }

    /// Add a new stream to an existing session
    pub fn add_stream(&mut self, policy: SrtpPolicy<'_>) -> Result<(), SrtpError> {
        unsafe { ff!(srtp_add_stream(self.ctx, &raw const policy.policy)) }
    }

    /// Updates the stream(s) in the session that match applying the given policy and key.
    /// The existing ROC value of all stream(s) will be preserved.
    pub fn update_stream(&mut self, policy: SrtpPolicy<'_>) -> Result<(), SrtpError> {
        unsafe { ff!(srtp_update_stream(self.ctx, &raw const policy.policy)) }
    }

    /// Remove stream from the session with the given ssrc
    ///
    /// Wildcard stream cannot be removed.
    pub fn remove_stream(&mut self, ssrc: u32) -> Result<(), SrtpError> {
        unsafe { ff!(ffi::srtp_remove_stream(self.ctx, ssrc)) }
    }

    /// Get the roll-over-counter on a session for a given SSRC
    pub fn stream_roc(&mut self, ssrc: u32) -> Result<u32, SrtpError> {
        unsafe {
            let mut roc = 0;
            ff!(ffi::srtp_get_stream_roc(self.ctx, ssrc, &raw mut roc))?;
            Ok(roc)
        }
    }

    /// Set the roll-over-counter on a session for a given SSRC
    pub fn set_stream_roc(&mut self, ssrc: u32, roc: u32) -> Result<(), SrtpError> {
        unsafe { ff!(ffi::srtp_set_stream_roc(self.ctx, ssrc, roc)) }
    }
}

impl Drop for SrtpSession {
    fn drop(&mut self) {
        unsafe {
            ff_log_error!(ffi::srtp_dealloc(self.ctx));
        }
    }
}
