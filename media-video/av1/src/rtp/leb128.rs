use bytes::BufMut;

pub(super) fn expected_size(v: u32) -> usize {
    if v <= 0x7F {
        1
    } else if v <= 0x7F_FF {
        2
    } else if v <= 0x7F_FF_FF {
        3
    } else if v <= 0x7F_FF_FF_FF {
        4
    } else {
        5
    }
}

pub(super) fn read_leb128(bytes: &[u8]) -> Option<(usize, u32)> {
    let mut value: u32 = 0;

    for (i, leb128_byte) in bytes.iter().take(8).enumerate() {
        let part = *leb128_byte & 0x7F;

        if i == 4 && part > 0x0F {
            // Setting any of the high 4 bits at byte index 4 would shift past bit 31.
            return None;
        }
        if i >= 5 && part != 0 {
            return None;
        }

        if i < 5 {
            value |= u32::from(part) << (i * 7);
        }

        if leb128_byte & 0x80 == 0 {
            return Some((i + 1, value));
        }
    }

    None
}

pub(super) fn write_leb128(mut buf: impl BufMut, mut value: u32) {
    while {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        let more_bytes = value != 0;

        byte |= (more_bytes as u8) << 7;
        buf.put_u8(byte);

        more_bytes
    } {}
}

#[test]
fn write_and_parse_the_world() {
    fn write_and_parse(num: u32) {
        let mut buf = Vec::new();

        write_leb128(&mut buf, num);
        assert_eq!(read_leb128(&buf).unwrap().1, num);
    }

    for i in (0..u32::MAX).step_by(100) {
        write_and_parse(i);
    }
}

#[test]
fn read_rejects_overflow_in_byte_4() {
    // 5 bytes where the last byte has its 5th bit set -> would shift past bit 31.
    let bytes = [0x80, 0x80, 0x80, 0x80, 0x10];
    assert!(read_leb128(&bytes).is_none());
}

#[test]
fn read_rejects_nonzero_high_bytes() {
    // 6+ bytes with non-zero data must overflow u32.
    let bytes = [0x80, 0x80, 0x80, 0x80, 0x80, 0x01];
    assert!(read_leb128(&bytes).is_none());
}

#[test]
fn read_accepts_padded_zero_bytes() {
    // Spec permits trailing zero continuation bytes up to 8 total.
    let bytes = [0x81, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00];
    let (consumed, value) = read_leb128(&bytes).unwrap();
    assert_eq!(consumed, 8);
    assert_eq!(value, 1);
}
