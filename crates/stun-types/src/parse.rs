use crate::attributes::{Attribute, Fingerprint, MessageIntegrity, MessageIntegritySha256};
use crate::header::{Class, MessageHead, Method};
use crate::{padding_usize, Error, TransactionId, COOKIE, NE};
use byteorder::ReadBytesExt;
use bytes::Buf;
use std::convert::TryFrom;
use std::io::{Cursor, Read};

#[derive(Debug, Clone, Copy)]
pub struct AttrSpan {
    /// Index where the attribute's value begins
    pub begin: usize,

    /// Index of end of the attribute's value
    pub end: usize,

    /// End of the attribute's value including padding
    pub padding_end: usize,

    /// Attribute type id
    pub typ: u16,
}

impl AttrSpan {
    pub fn get_value<'b>(&self, buf: &'b [u8]) -> &'b [u8] {
        &buf[self.begin..self.end]
    }
}

pub struct Message {
    buffer: Vec<u8>,

    head: MessageHead,
    id: u128,

    class: Class,
    method: Method,
    transaction_id: TransactionId,

    attributes: Vec<AttrSpan>,
}

impl Message {
    pub fn class(&self) -> Class {
        self.class
    }

    pub fn method(&self) -> Method {
        self.method
    }

    pub fn transaction_id(&self) -> TransactionId {
        self.transaction_id
    }

    pub(crate) fn id(&self) -> u128 {
        self.id
    }

    pub fn parse(buffer: impl Into<Vec<u8>>) -> Result<Message, Error> {
        let mut cursor = Cursor::new(buffer.into());

        let head = cursor.read_u32::<NE>()?;
        let head = MessageHead(head);

        if head.z() != 0 {
            return Err(Error::InvalidData("not a stun message"));
        }

        let id = cursor.read_u128::<NE>()?;

        let (cookie, transaction_id) = {
            let mut cursor = Cursor::new(id.to_be_bytes());
            let cookie = cursor.read_u32::<NE>()?;
            let mut transaction_id = [0u8; 12];
            cursor.read_exact(&mut transaction_id)?;
            (cookie, transaction_id)
        };

        if cookie != COOKIE {
            return Err(Error::InvalidData("not a stun message"));
        }

        let class = Class::try_from(head.typ())?;
        let method = Method::try_from(head.typ())?;

        let mut attributes = vec![];

        while cursor.has_remaining() {
            let attr_typ = cursor.read_u16::<NE>()?;
            let attr_len = usize::from(cursor.read_u16::<NE>()?);
            let padding = padding_usize(attr_len);

            let value_begin = usize::try_from(cursor.position())?;
            let value_end = value_begin + attr_len;
            let padding_end = value_end + padding;

            if padding_end > cursor.get_ref().len() {
                return Err(Error::InvalidData(
                    "Invalid attribute length in STUN message",
                ));
            }

            let attr = AttrSpan {
                begin: value_begin,
                end: value_end,
                padding_end,
                typ: attr_typ,
            };

            attributes.push(attr);

            cursor.set_position(u64::try_from(padding_end)?);
        }

        Ok(Message {
            buffer: cursor.into_inner(),
            head,
            id,
            class,
            method,
            transaction_id: TransactionId(transaction_id),
            attributes,
        })
    }

    /// Try to read an attribute from the message
    pub fn attribute<'a, A>(&'a mut self) -> Option<Result<A, Error>>
    where
        A: Attribute<'a, Context = ()> + 'a,
    {
        self.attribute_with(())
    }

    /// Try to read an attribute from the message with a required context (like a key to verify the integrity of the message)
    pub fn attribute_with<'a, A>(&'a mut self, ctx: A::Context) -> Option<Result<A, Error>>
    where
        A: Attribute<'a> + 'a,
    {
        let mut after_integrity = false;

        for attr in self.attributes.iter().copied() {
            if after_integrity
                && !matches!(attr.typ, MessageIntegritySha256::TYPE | Fingerprint::TYPE)
            {
                // ignore attributes after integrity
                // excluding MESSAGE-INTEGRITY-SHA256 & FINGERPRINT
                return None;
            }

            if attr.typ == A::TYPE {
                return Some(A::decode(ctx, self, attr));
            } else if matches!(
                attr.typ,
                MessageIntegrity::TYPE | MessageIntegritySha256::TYPE
            ) {
                after_integrity = true;
            }
        }

        None
    }

    fn set_msg_len(&mut self, len: u16) {
        self.head.set_len(len);

        let [b0, b1, b2, b3] = u32::to_be_bytes(self.head.0);

        self.buffer[0] = b0;
        self.buffer[1] = b1;
        self.buffer[2] = b2;
        self.buffer[3] = b3;
    }

    /// Access the message with the given length set.
    ///
    /// E.g. Integrity of the message is computed with the length set to the end of previous attribute
    pub fn with_msg_len<F, R>(&mut self, len: u16, f: F) -> R
    where
        F: FnOnce(&mut Self) -> R,
    {
        let old_len = self.head.len();
        self.set_msg_len(len);

        let result = f(self);

        self.set_msg_len(old_len);

        result
    }

    /// Return the raw message
    pub fn buffer(&self) -> &[u8] {
        &self.buffer
    }

    /// Header of the STUN message
    pub fn head(&self) -> &MessageHead {
        &self.head
    }
}
