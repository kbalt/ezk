use bytes::BufMut;

pub struct RtpExtensionsWriter {
    buffer: Vec<u8>,
    len: usize,
    two_byte: bool,
}

impl RtpExtensionsWriter {
    pub fn new(two_byte: bool) -> Self {
        Self {
            buffer: Vec::new(),
            len: 0,
            two_byte,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    pub fn write(&mut self, id: u8, data: &[u8]) {
        if self.two_byte {
            assert!(id >= 1);
            assert!(data.len() <= 255);

            self.buffer.put_slice(&[id, data.len() as u8]);

            self.len += data.len() + 2;
        } else {
            assert!(id >= 1);
            assert!(id <= 14);

            assert!(!data.is_empty());
            assert!(data.len() <= 16);

            assert!(!data.is_empty());

            let mut b = (data.len() - 1) as u8;
            b |= id << 4;

            self.buffer.put_u8(b);

            self.len += data.len() + 1;
        }

        self.buffer.put_slice(data);
    }

    pub fn finish(mut self) -> (u16, Vec<u8>) {
        let id = if self.two_byte { 0x0100 } else { 0xBEDE };

        let padding = padding_32_bit_boundry(self.len);
        self.buffer.put_bytes(0, padding);

        (id, self.buffer)
    }
}

enum ExtensionsIter<T, U> {
    OneByte(T),
    TwoBytes(U),
    None,
}

impl<T: Iterator, U: Iterator<Item = T::Item>> Iterator for ExtensionsIter<T, U> {
    type Item = T::Item;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            ExtensionsIter::OneByte(iter) => iter.next(),
            ExtensionsIter::TwoBytes(iter) => iter.next(),
            ExtensionsIter::None => None,
        }
    }
}

pub fn parse_extensions(profile: u16, data: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    if profile == 0xBEDE {
        ExtensionsIter::OneByte(parse_onebyte(data))
    } else if (profile & 0xFFF) == 0x100 {
        ExtensionsIter::TwoBytes(parse_twobyte(data))
    } else {
        ExtensionsIter::None
    }
}

// https://www.rfc-editor.org/rfc/rfc8285#section-4.2
fn parse_onebyte(mut data: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    std::iter::from_fn(move || {
        let &[b, ref remaining @ ..] = data else {
            return None;
        };

        if b == 0 {
            return None;
        }

        let id = (b & 0xF0) >> 4;
        if id == 15 {
            return None;
        }

        let len = (b & 0x0F) as usize + 1;

        if remaining.len() >= len {
            data = &remaining[len..];
            Some((id, &remaining[..len]))
        } else {
            None
        }
    })
}

// https://www.rfc-editor.org/rfc/rfc5285#section-4.3
fn parse_twobyte(mut data: &[u8]) -> impl Iterator<Item = (u8, &[u8])> {
    std::iter::from_fn(move || {
        let &[id, len, ref remaining @ ..] = data else {
            return None;
        };

        if id == 0 && len == 0 {
            return None;
        }

        let len = len as usize;

        if remaining.len() >= len {
            data = &remaining[len..];
            Some((id, &remaining[..len]))
        } else {
            None
        }
    })
}

fn padding_32_bit_boundry(i: usize) -> usize {
    match i % 4 {
        0 => 0,
        1 => 3,
        2 => 2,
        3 => 1,
        _ => unreachable!(),
    }
}
