use byteorder::ReadBytesExt;
use header::{MessageHead, MessageId};
use std::io::{self, Cursor};
use std::num::TryFromIntError;
use std::str::Utf8Error;

pub mod attributes;
pub mod builder;
pub mod header;
pub mod parse;

type NE = byteorder::NetworkEndian;

const COOKIE: u32 = 0x2112A442;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid input data, {0}")]
    InvalidData(&'static str),
    #[error("failed to convert integer")]
    TryFromInt(#[from] TryFromIntError),
    #[error(transparent)]
    Utf8(#[from] Utf8Error),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::UnexpectedEof => Self::InvalidData("buffer seems incomplete"),
            _ => Self::InvalidData("failed to read from buffer"),
        }
    }
}

fn padding_u16(n: u16) -> u16 {
    match n % 4 {
        0 => 0,
        1 => 3,
        2 => 2,
        3 => 1,
        _ => unreachable!(),
    }
}

fn padding_usize(n: usize) -> usize {
    match n % 4 {
        0 => 0,
        1 => 3,
        2 => 2,
        3 => 1,
        _ => unreachable!(),
    }
}

/// Returns a random 96 bit number.
pub fn transaction_id() -> u128 {
    rand::random::<u128>() & !((u32::MAX as u128) << 96)
}

/// Return value of [`is_stun_message`]
#[derive(Debug)]
pub enum IsStunMessageInfo {
    /// Message is shorter than 20 bytes (STUN message header length),
    /// making it impossible to check.
    TooShort,

    /// Buffer does not contain a STUN message.
    No,

    /// Buffer contains a STUN message.
    /// Variant contains the remaining amount of bytes.
    Yes { remaining: usize },

    /// Buffer contains a STUN message, but its incomplete.
    /// Variant contains the needed amount of bytes message.
    YesIncomplete { needed: usize },
}

/// Inspect the given input to find out if it contains a STUN message.
///
/// Does not perform any kind of searching, to detect the
/// STUN message it must begin at the start of the input.
pub fn is_stun_message(i: &[u8]) -> IsStunMessageInfo {
    if i.len() < 20 {
        return IsStunMessageInfo::TooShort;
    }

    let mut cursor = Cursor::new(i);

    let head = cursor.read_u32::<NE>().unwrap();
    let head = MessageHead(head);

    if head.z() != 0 {
        return IsStunMessageInfo::No;
    }

    let id = cursor.read_u128::<NE>().unwrap();
    let id = MessageId(id);

    if id.cookie() != COOKIE {
        return IsStunMessageInfo::No;
    }

    let expected_msg_len = head.len() as usize + 20;

    if i.len() < expected_msg_len {
        let needed = expected_msg_len - i.len();
        IsStunMessageInfo::YesIncomplete { needed }
    } else {
        let remaining = i.len() - expected_msg_len;
        IsStunMessageInfo::Yes { remaining }
    }
}
