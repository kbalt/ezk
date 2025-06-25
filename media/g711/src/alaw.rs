//! G.711 A-law algorithm aka. PCMA

/// Encode an i16 audio sample to a A-law sample
pub fn encode(x: i16) -> u8 {
    let mut ix = if x < 0 { (!x) >> 4 } else { x >> 4 };

    if ix > 15 {
        let mut iexp = 1;

        while ix > 16 + 15 {
            ix >>= 1;
            iexp += 1;
        }
        ix -= 16;
        ix += iexp << 4;
    }

    if x >= 0 {
        ix |= 0x0080;
    }

    ((ix ^ 0x55) & 0xFF) as u8
}

/// Decode a A-law sample to an i16 audio sample
pub fn decode(y: u8) -> i16 {
    let mut ix = y ^ 0x55;
    ix &= 0x7F;

    let iexp = ix >> 4;
    let mut mant = (ix & 0xF) as i16;
    if iexp > 0 {
        mant += 16;
    }

    mant = (mant << 4) + 0x8;

    if iexp > 1 {
        mant <<= iexp - 1;
    }

    if y > 127 { mant } else { -mant }
}
