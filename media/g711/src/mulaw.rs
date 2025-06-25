//! G.711 μ-law algorithm aka. PCMU

/// Encode an i16 audio sample to a μ-law sample
pub fn encode(x: i16) -> u8 {
    let mut absno = if x < 0 {
        ((!x) >> 2) + 33
    } else {
        (x >> 2) + 33
    };

    if absno > 0x1FFF {
        absno = 0x1FFF;
    }

    let mut i = absno >> 6;
    let mut segno = 1;
    while i != 0 {
        segno += 1;
        i >>= 1;
    }

    let high_nibble = 0x8 - segno;
    let low_nibble = (absno >> segno) & 0xF;
    let low_nibble = 0xF - low_nibble;

    let mut ret = (high_nibble << 4) | low_nibble;

    if x >= 0 {
        ret |= 0x0080;
    }

    ret as u8
}

/// Decode a μ-law sample to an i16 audio sample
pub fn decode(y: u8) -> i16 {
    let y = y as i16;
    let sign: i16 = if y < 0x0080 { -1 } else { 1 };

    let mantissa = !y;
    let exponent = (mantissa >> 4) & 0x7;
    let segment = exponent + 1;
    let mantissa = mantissa & 0xF;

    let step = 4 << segment;

    sign * ((0x0080 << exponent) + step * mantissa + step / 2 - 4 * 33)
}
