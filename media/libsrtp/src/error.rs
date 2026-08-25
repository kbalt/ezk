use crate::ffi;
use core::fmt;
use std::error::Error;

/// Catch-all error type returned by most functions
#[derive(Clone, Copy)]
pub struct SrtpError {
    expr: Option<&'static str>,
    status: ffi::srtp_err_status_t,
}

impl Error for SrtpError {}

impl SrtpError {
    pub(crate) fn new(expr: &'static str, status: ffi::srtp_err_status_t) -> Self {
        SrtpError {
            expr: Some(expr),
            status,
        }
    }
}

impl PartialEq for SrtpError {
    fn eq(&self, other: &Self) -> bool {
        self.status == other.status
    }
}

macro_rules! ff {
    ($expr:expr) => {
        match $expr {
            ffi::srtp_err_status_t_srtp_err_status_ok => Ok(()),
            status => Err(SrtpError::new(stringify!($expr), status)),
        }
    };
}

macro_rules! ff_log_error {
    ($expr:expr) => {
        match $expr {
            ffi::srtp_err_status_t_srtp_err_status_ok => {}
            status => log::warn!("{}", SrtpError::new(stringify!($expr), status)),
        }
    };
}

macro_rules! error_codes {
    ($($rust:ident, $c:ident, $c_doc:literal;)*) => {
        impl SrtpError {
            $(
                pub const $rust: SrtpError = SrtpError { expr: None, status: ffi::$c };
            )*
        }

        impl fmt::Debug for SrtpError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {

                let dbg: &dyn fmt::Debug = match self.status {
                    $(ffi::$c => &concat!(stringify!($rust), " (",  $c_doc, ")"),)*
                    _ => &self.status,
                };

                f.debug_struct("SrtpError")
                    .field("expr", &self.expr)
                    .field("status", dbg)
                    .finish()
            }
        }

        impl fmt::Display for SrtpError {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                if let Some(expr) = self.expr {
                    write!(f, "`{expr}` returned status ")?;
                }

                match self.status {
                    $(ffi::$c => f.write_str(concat!(stringify!($rust), " - ",  $c_doc)),)*
                    status => {
                        write!(f, "UNKNOWN: {status}")
                    }
                }
            }
        }
    }
}

error_codes! {
    FAIL, srtp_err_status_t_srtp_err_status_fail, "unspecified failure";
    BAD_PARAM, srtp_err_status_t_srtp_err_status_bad_param, "unsupported parameter";
    ALLOC_FAIL, srtp_err_status_t_srtp_err_status_alloc_fail, "couldn't allocate memory";
    DEALLOC_FAIL, srtp_err_status_t_srtp_err_status_dealloc_fail, "couldn't deallocate properly";
    INIT_FAIL, srtp_err_status_t_srtp_err_status_init_fail, "couldn't initialize";
    TERMINUS, srtp_err_status_t_srtp_err_status_terminus, "can't process as much data as requested";
    AUTH_FAIL, srtp_err_status_t_srtp_err_status_auth_fail, "authentication failure";
    CIPHER_FAIL, srtp_err_status_t_srtp_err_status_cipher_fail, "cipher failure";
    REPLAY_FAIL, srtp_err_status_t_srtp_err_status_replay_fail, "replay check failed (bad index)";
    REPLAY_OLD, srtp_err_status_t_srtp_err_status_replay_old, "replay check failed (index too old)";
    ALGO_FAIL, srtp_err_status_t_srtp_err_status_algo_fail, "algorithm failed test routine";
    NO_SUCH_OP, srtp_err_status_t_srtp_err_status_no_such_op, "unsupported operation";
    NO_CTX, srtp_err_status_t_srtp_err_status_no_ctx, "no appropriate context found";
    CANT_CHECK, srtp_err_status_t_srtp_err_status_cant_check, "unable to perform desired validation";
    KEY_EXPIRED, srtp_err_status_t_srtp_err_status_key_expired, "can't use key any more";
    SOCKET_ERR, srtp_err_status_t_srtp_err_status_socket_err, "error in use of socket";
    SIGNAL_ERR, srtp_err_status_t_srtp_err_status_signal_err, "error in use POSIX signals";
    NONCE_BAD, srtp_err_status_t_srtp_err_status_nonce_bad, "nonce check failed";
    READ_FAIL, srtp_err_status_t_srtp_err_status_read_fail, "couldn't read data";
    WRITE_FAIL, srtp_err_status_t_srtp_err_status_write_fail, "couldn't write data";
    PARSE_ERR, srtp_err_status_t_srtp_err_status_parse_err, "error parsing data";
    ENCODE_ERR, srtp_err_status_t_srtp_err_status_encode_err, "error encoding data";
    SEMAPHORE_ERR, srtp_err_status_t_srtp_err_status_semaphore_err, "error while using semaphores";
    PFKEY_ERR, srtp_err_status_t_srtp_err_status_pfkey_err, "error while using pfkey";
    BAD_MKI, srtp_err_status_t_srtp_err_status_bad_mki, "error MKI present in packet is invalid";
    PKT_IDX_OLD, srtp_err_status_t_srtp_err_status_pkt_idx_old, "packet index is too old to consider";
    PKT_IDX_ADV, srtp_err_status_t_srtp_err_status_pkt_idx_adv,"packet index advanced, reset needed";
}
