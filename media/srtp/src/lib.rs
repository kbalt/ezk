//! Pure Rust SRTP and SRTCP
//!
//! Implements the Secure Real-time Transport Protocol of [RFC 3711] and its AEAD
//! profiles from [RFC 7714], covering the three protection profiles that DTLS-SRTP can
//! negotiate ([RFC 5764]) plus the AES counter mode suites used by SDES ([RFC 4568],
//! [RFC 6188]). See [`SrtpProfile`] for the full list.
//!
//! Protection is split by direction: [`SrtpProtector`] holds the sending key and
//! [`SrtpUnprotector`] the receiving key, which is how both DTLS-SRTP and SDES hand out
//! keying material in the first place.
//!
//! ```
//! use ezk_srtp::{SrtpKeys, SrtpProfile, SrtpProtector, SrtpUnprotector};
//!
//! let profile = SrtpProfile::AEAD_AES_128_GCM;
//! let keys = SrtpKeys::new(profile, &[0; 16], &[0; 12])?;
//!
//! let mut sender = SrtpProtector::new(keys.clone());
//! let mut receiver = SrtpUnprotector::new(keys);
//!
//! let rtp = [
//!     0x80, 0x60, 0x12, 0x34, 0, 0, 0, 1, 0xde, 0xad, 0xbe, 0xef, b'h', b'i',
//! ];
//!
//! let mut srtp = Vec::new();
//! sender.protect_rtp(&rtp, &mut srtp)?;
//! assert_eq!(srtp.len(), rtp.len() + profile.rtp_overhead());
//!
//! let mut plain = Vec::new();
//! receiver.unprotect_rtp(&srtp, &mut plain)?;
//! assert_eq!(plain, rtp);
//! # Ok::<(), ezk_srtp::SrtpError>(())
//! ```
//!
//! [RFC 3711]: https://www.rfc-editor.org/rfc/rfc3711
//! [RFC 4568]: https://www.rfc-editor.org/rfc/rfc4568
//! [RFC 5764]: https://www.rfc-editor.org/rfc/rfc5764
//! [RFC 6188]: https://www.rfc-editor.org/rfc/rfc6188
//! [RFC 7714]: https://www.rfc-editor.org/rfc/rfc7714

mod auth;
mod cipher;
mod error;
mod index;
mod kdf;
mod keys;
mod packet;
mod profile;
mod protect;
mod replay;
#[cfg(test)]
mod rfc7714;
mod unprotect;

pub use error::SrtpError;
pub use keys::SrtpKeys;
pub use profile::SrtpProfile;
pub use protect::SrtpProtector;
pub use unprotect::SrtpUnprotector;
