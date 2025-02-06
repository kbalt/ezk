use crate::Error;
use bitfield::bitfield;
use std::convert::TryFrom;

pub(crate) const STUN_HEADER_LENGTH: usize = 20;

bitfield! {
    /// Internal bitfield representing the STUN message head
    pub struct MessageHead(u32);

    u8;
    pub z, _: 31, 30;

    u16;
    pub typ, set_typ: 29, 16;

    #[allow(clippy::len_without_is_empty)]
    pub len, set_len: 15, 0;
}

/// STUN class
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum Class {
    Request,
    Indication,
    Success,
    Error,
}

impl Class {
    const MASK: u16 = 0x110;

    const REQUEST: u16 = 0x000;
    const INDICATION: u16 = 0x010;
    const SUCCESS: u16 = 0x100;
    const ERROR: u16 = 0x110;

    pub(crate) fn set_bits(&self, typ: &mut u16) {
        *typ &= Method::MASK;

        match self {
            Class::Request => *typ |= Self::REQUEST,
            Class::Indication => *typ |= Self::INDICATION,
            Class::Success => *typ |= Self::SUCCESS,
            Class::Error => *typ |= Self::ERROR,
        }
    }
}

impl TryFrom<u16> for Class {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Error> {
        match value & Self::MASK {
            Self::REQUEST => Ok(Self::Request),
            Self::INDICATION => Ok(Self::Indication),
            Self::SUCCESS => Ok(Self::Success),
            Self::ERROR => Ok(Self::Error),
            _ => Err(Error::InvalidData("unknown class")),
        }
    }
}

/// STUN/TURN Methods
#[derive(Debug, Copy, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub enum Method {
    // === STUN ===
    Binding,

    // === TURN ===
    Allocate,
    Refresh,
    Send,
    Data,
    CreatePermission,
    ChannelBind,
}

impl Method {
    const MASK: u16 = 0x3EEF;

    // === STUN ===
    const BINDING: u16 = 0x1;

    // === TURN ===
    const ALLOCATE: u16 = 0x3;
    const REFRESH: u16 = 0x4;
    const SEND: u16 = 0x6;
    const DATA: u16 = 0x7;
    const CREATE_PERMISSION: u16 = 0x8;
    const CHANNEL_BIND: u16 = 0x9;

    pub(crate) fn set_bits(&self, typ: &mut u16) {
        *typ &= Class::MASK;

        match self {
            // === STUN ===
            Method::Binding => *typ |= Self::BINDING,
            // === TURN ===
            Method::Allocate => *typ |= Self::ALLOCATE,
            Method::Refresh => *typ |= Self::REFRESH,
            Method::Send => *typ |= Self::SEND,
            Method::Data => *typ |= Self::DATA,
            Method::CreatePermission => *typ |= Self::CREATE_PERMISSION,
            Method::ChannelBind => *typ |= Self::CHANNEL_BIND,
        }
    }
}

impl TryFrom<u16> for Method {
    type Error = Error;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value & Self::MASK {
            Self::BINDING => Ok(Self::Binding),
            Self::ALLOCATE => Ok(Self::Allocate),
            Self::REFRESH => Ok(Self::Refresh),
            Self::SEND => Ok(Self::Send),
            Self::DATA => Ok(Self::Data),
            Self::CREATE_PERMISSION => Ok(Self::CreatePermission),
            Self::CHANNEL_BIND => Ok(Self::ChannelBind),
            _ => Err(Error::InvalidData("unknown method")),
        }
    }
}
