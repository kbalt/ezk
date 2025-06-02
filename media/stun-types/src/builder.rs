use crate::attributes::Attribute;
use crate::header::{Class, MessageHead, Method, STUN_HEADER_LENGTH};
use crate::{padding_u16, padding_usize, TransactionId, COOKIE};
use bytes::BufMut;

/// Builder for a STUN message
pub struct MessageBuilder {
    head: MessageHead,
    transaction_id: TransactionId,

    padding_in_value_len: bool,

    buffer: Vec<u8>,
}

impl MessageBuilder {
    /// Create a new message builder.
    pub fn new(class: Class, method: Method, transaction_id: TransactionId) -> Self {
        let mut buffer = Vec::new();

        let mut typ = 0;
        method.set_bits(&mut typ);
        class.set_bits(&mut typ);

        let mut head = MessageHead(0);
        head.set_typ(typ);
        buffer.put_u32(head.0);

        buffer.put_u32(COOKIE);
        buffer.put_slice(&transaction_id.0);

        Self {
            head,
            transaction_id,
            padding_in_value_len: false,
            buffer,
        }
    }

    pub fn padding_in_value_len(&mut self, b: bool) {
        self.padding_in_value_len = b;
    }

    /// Set the length of the message
    pub fn set_len(&mut self, len: u16) {
        self.head.set_len(len);

        let [b0, b1, b2, b3] = u32::to_be_bytes(self.head.0);

        self.buffer[0] = b0;
        self.buffer[1] = b1;
        self.buffer[2] = b2;
        self.buffer[3] = b3;
    }

    /// Serialize the attribute into the builder
    pub fn add_attr<'a, A>(&mut self, attr: A)
    where
        A: Attribute<'a, Context = ()>,
    {
        self.add_attr_with(attr, ())
    }

    /// Serialize the attribute into the builder with a given context (e.g. a key to calculate the integrity)
    pub fn add_attr_with<'a, A>(&mut self, attr: A, ctx: A::Context)
    where
        A: Attribute<'a>,
    {
        let enc_len = attr.encode_len().expect("Failed to get encode_len");
        let padding = padding_u16(enc_len);

        self.buffer.put_u16(A::TYPE);

        if self.padding_in_value_len {
            self.buffer.put_u16(enc_len + padding);
        } else {
            self.buffer.put_u16(enc_len);
        }

        attr.encode(ctx, self);

        let padding_bytes = std::iter::repeat_n(0, padding_usize(usize::from(enc_len)));
        self.buffer.extend(padding_bytes);
    }

    pub fn id(&self) -> u128 {
        let cookie = COOKIE.to_be_bytes();
        let tsx = self.transaction_id.0;

        let mut id = [0u8; 16];

        id[..4].copy_from_slice(&cookie);
        id[4..].copy_from_slice(&tsx);

        u128::from_be_bytes(id)
    }

    pub fn finish(mut self) -> Vec<u8> {
        self.set_len((self.buffer.len() - STUN_HEADER_LENGTH).try_into().unwrap());
        self.buffer
    }

    pub fn buffer(&mut self) -> &mut Vec<u8> {
        &mut self.buffer
    }
}
