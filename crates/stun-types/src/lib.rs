use header::{MessageHead, MessageId};
use std::convert::TryInto;
use std::io;
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
    fn from(_: io::Error) -> Self {
        Self::InvalidData("failed to read from buffer")
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

pub fn transaction_id() -> u128 {
    rand::random::<u128>() & !((u32::MAX as u128) << 96)
}

pub fn check_if_stun_message(i: &[u8]) -> bool {
    if i.len() < 20 {
        return false;
    }

    let head = i[0..4].try_into().unwrap();
    let head = u32::from_ne_bytes(head);
    let head = MessageHead(head);

    if head.z() != 0 {
        return false;
    }

    let id = i[4..20].try_into().unwrap();
    let id = u128::from_ne_bytes(id);
    let id = MessageId(id);

    if id.cookie() != COOKIE {
        return false;
    }

    false
}
