use super::{Attribute, ATTRIBUTE_HEADER_LEN};
use crate::builder::MessageBuilder;
use crate::header::STUN_HEADER_LENGTH;
use crate::parse::{AttrSpan, Message};
use crate::{Error, NE};
use byteorder::ReadBytesExt;
use bytes::BufMut;

/// [RFC8489](https://datatracker.ietf.org/doc/html/rfc8489#section-14.7)
pub struct Fingerprint;

impl Fingerprint {
    const CRC32_TABLE: [u32; 256] = Self::crc32_table();

    const fn crc32_table() -> [u32; 256] {
        let mut table = [0u32; 256];

        let mut c;

        let mut n = 0;
        while n < 256 {
            c = n;

            let mut k = 0;
            while k < 8 {
                if c & 1 == 1 {
                    c = 0xedb88320 ^ (c >> 1);
                } else {
                    c >>= 1;
                }

                k += 1;
            }

            table[n as usize] = c;

            n += 1;
        }

        table
    }

    const fn update_crc32(crc: u32, buf: &[u8]) -> u32 {
        let mut c = crc ^ 0xffffffff;

        let mut n = 0;
        while n < buf.len() {
            c = Self::CRC32_TABLE[((c ^ buf[n] as u32) & 0xff) as usize] ^ (c >> 8);

            n += 1;
        }

        c ^ 0xffffffff
    }

    const fn crc32(buf: &[u8]) -> u32 {
        Self::update_crc32(0, buf)
    }
}

impl Attribute<'_> for Fingerprint {
    type Context = ();
    const TYPE: u16 = 0x8028;

    fn decode(_: Self::Context, msg: &mut Message, attr: AttrSpan) -> Result<Self, Error> {
        msg.with_msg_len(
            u16::try_from(attr.padding_end - STUN_HEADER_LENGTH)?,
            |msg| {
                let mut value = attr.get_value(msg.buffer());

                if value.len() != 4 {
                    return Err(Error::InvalidData("fingerprint value must be 4 bytes"));
                }

                let attr_value = value.read_u32::<NE>()?;
                let data = &msg.buffer()[..attr.begin - ATTRIBUTE_HEADER_LEN];
                let crc = Self::crc32(data) ^ 0x5354554e;

                if crc != attr_value {
                    return Err(Error::InvalidData("failed to verify message fingerprint"));
                }

                Ok(Self)
            },
        )
    }

    fn encode(&self, _: Self::Context, builder: &mut MessageBuilder) -> Result<(), Error> {
        // First set the length of the message to the end of the fingerprint attribute
        // 4 bytes containing type and length is already written into the buffer
        let message_length_with_fingerprint_attribute =
            (builder.buffer().len() + 4) - STUN_HEADER_LENGTH;

        builder.set_len(message_length_with_fingerprint_attribute.try_into()?);

        // Calculate the checksum
        let data = builder.buffer();
        let data = &data[..data.len() - ATTRIBUTE_HEADER_LEN];
        let crc = Self::crc32(data) ^ 0x5354554e;

        builder.buffer().put_u32(crc);

        Ok(())
    }

    fn encode_len(&self) -> Result<u16, Error> {
        Ok(4)
    }
}
