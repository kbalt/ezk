use crate::attributes::Attribute;
use crate::header::{Class, MessageHead, MessageId, Method};
use crate::{padding_usize, Error, COOKIE, NE};
use byteorder::ReadBytesExt;
use bytes::{Buf, BytesMut};
use std::convert::TryFrom;
use std::io::Cursor;

#[derive(Debug, Clone, Copy)]
pub struct ParsedAttr {
    /// Index where the attribute begins
    pub begin: usize,

    /// Index of end of the attribute
    pub end: usize,

    /// End of the attribute including padding
    pub padding_end: usize,

    /// Attribute type id
    pub typ: u16,
}

impl ParsedAttr {
    pub fn get_value<'b>(&self, buf: &'b [u8]) -> &'b [u8] {
        &buf[self.begin..self.end]
    }
}

pub struct ParsedMessage {
    buffer: BytesMut,

    head: MessageHead,
    id: MessageId,

    pub class: Class,
    pub method: Method,
    pub tsx_id: u128,

    pub attributes: Vec<ParsedAttr>,
}

impl ParsedMessage {
    pub fn parse(buffer: BytesMut) -> Result<Option<ParsedMessage>, Error> {
        let mut cursor = Cursor::new(buffer);

        let head = cursor.read_u32::<NE>()?;
        let head = MessageHead(head);

        if head.z() != 0 {
            return Ok(None);
        }

        let id = cursor.read_u128::<NE>()?;
        let id = MessageId(id);

        if id.cookie() != COOKIE {
            return Ok(None);
        }

        let class = Class::try_from(head.typ())?;
        let method = Method::try_from(head.typ())?;

        let mut attributes = vec![];

        while cursor.has_remaining() {
            let attr_typ = cursor.read_u16::<NE>()?;
            let attr_len = usize::from(cursor.read_u16::<NE>()?);
            let padding = padding_usize(attr_len);

            let value_begin = usize::try_from(cursor.position())?;
            let mut value_end = value_begin + attr_len;
            let padding_end = value_end + padding;

            if padding_end > cursor.get_ref().len() {
                return Err(Error::InvalidData(
                    "Invalid attribute length in STUN message",
                ));
            }

            // https://datatracker.ietf.org/doc/html/rfc8489#section-14
            // explicitly states that the length field must contain the
            // value length __prior__ to padding. Some stun agents have
            // the padding included in the length anyway. This double
            // checks and removes all bytes from the end of the value.
            if padding == 0 {
                let value = &cursor.get_ref()[value_begin..value_end];

                // count all zero bytes at the end of the value
                let counted_padding = value.iter().rev().take_while(|&&b| b == 0).count();

                value_end -= counted_padding;
            }

            let attr = ParsedAttr {
                begin: value_begin,
                end: value_end,
                padding_end,
                typ: attr_typ,
            };

            attributes.push(attr);

            cursor.set_position(u64::try_from(padding_end)?);
        }

        let tsx_id = id.tsx_id();

        Ok(Some(ParsedMessage {
            buffer: cursor.into_inner(),
            head,
            id,
            class,
            method,
            tsx_id,
            attributes,
        }))
    }

    pub fn get_attr<'a, A>(&'a mut self) -> Option<Result<A, Error>>
    where
        A: Attribute<'a, Context = ()> + 'a,
    {
        self.get_attr_with(())
    }

    pub fn get_attr_with<'a, A>(&'a mut self, ctx: A::Context) -> Option<Result<A, Error>>
    where
        A: Attribute<'a> + 'a,
    {
        for attr in self.attributes.iter().copied() {
            if attr.typ == A::TYPE {
                return Some(A::decode(ctx, self, attr));
            }
        }

        None
    }

    fn set_msg_len(&mut self, len: u16) {
        self.head.set_len(len);

        let [b0, b1, b2, b3] = u32::to_ne_bytes(self.head.0);

        self.buffer[0] = b3;
        self.buffer[1] = b2;
        self.buffer[2] = b1;
        self.buffer[3] = b0;
    }

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

    pub fn buffer(&self) -> &BytesMut {
        &self.buffer
    }

    pub fn head(&self) -> &MessageHead {
        &self.head
    }

    pub fn id(&self) -> &MessageId {
        &self.id
    }
}
