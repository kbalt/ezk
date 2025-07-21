//! Wrapper around libsrtp

use std::{
    ffi::{CStr, c_char, c_void},
    ptr,
    sync::LazyLock,
};

mod ffi {
    #![allow(unreachable_pub, dead_code, nonstandard_style)]

    include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
}

#[macro_use]
mod error;
mod crypto_policy;
mod dtls;
mod session;

pub use crypto_policy::CryptoPolicy;
pub use dtls::{DtlsSrtpPolicies, SrtpFromSslError};
pub use error::SrtpError;
pub use session::{SrtpPolicy, SrtpSession, Ssrc};

/// Install log handlers that delegate libsrtp output to the `log` crate
///
/// # Safety
///
/// Log handlers are installed in a static variable without any synchronization between reading & writing.
///
/// Should only be called once per program before [`init`].
pub unsafe fn install_log_handler() {
    unsafe extern "C" fn on_log(
        level: ffi::srtp_log_level_t,
        msg: *const c_char,
        _data: *mut c_void,
    ) {
        match level {
            ffi::srtp_log_level_t_srtp_log_level_error => {
                log::error!("{:?}", unsafe { CStr::from_ptr(msg) })
            }
            ffi::srtp_log_level_t_srtp_log_level_warning => {
                log::warn!("{:?}", unsafe { CStr::from_ptr(msg) })
            }
            ffi::srtp_log_level_t_srtp_log_level_info => {
                log::info!("{:?}", unsafe { CStr::from_ptr(msg) })
            }
            ffi::srtp_log_level_t_srtp_log_level_debug => {
                log::debug!("{:?}", unsafe { CStr::from_ptr(msg) })
            }
            _ => {}
        }
    }

    // Discard status since the function can't actually fail
    unsafe { ffi::srtp_install_log_handler(Some(on_log), ptr::null_mut()) };
}

/// Initialize libsrtp
pub fn init() -> Result<(), SrtpError> {
    static INIT: LazyLock<Result<(), SrtpError>> =
        LazyLock::new(|| unsafe { ff!(ffi::srtp_init()) });

    *INIT
}

#[doc(hidden)]
#[deprecated = "only exists to make sure openssl is linked"]
pub fn ensure_openssl_is_linked() {
    let _f = openssl_sys::EVP_CIPHER_CTX_new;
}
