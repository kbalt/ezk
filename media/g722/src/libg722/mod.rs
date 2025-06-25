//
// SpanDSP - a series of DSP components for telephony
//
// g722.h - The ITU G.722 codec.
//
// Written by Steve Underwood <steveu@coppice.org>
//
// Copyright (C) 2005 Steve Underwood
//
//  Despite my general liking of the GPL, I place my own contributions
//  to this code in the public domain for the benefit of all mankind -
//  even the slimy ones who might try to proprietize my work and use it
//  to my detriment.
//
// Based on a single channel G.722 codec which is:
//
//****    Copyright (c) CMU    1993      *****
// Computer Science, Speech Group
// Chengxiang Lu and Alex Hauptmann
//
// $Id: g722.h,v 1.1 2012/08/07 11:33:45 sobomax Exp $
//

//! G.722 Codec implementation translated from C to safe Rust
//!
//! Source: <https://github.com/sippy/libg722>

mod decoder;
mod encoder;

pub use decoder::Decoder;
pub use encoder::Encoder;

pub enum Bitrate {
    Mode1_64000,
    Mode2_56000,
    Mode3_48000,
}

impl Bitrate {
    fn bits_per_sample(&self) -> i32 {
        match self {
            Bitrate::Mode1_64000 => 8,
            Bitrate::Mode2_56000 => 7,
            Bitrate::Mode3_48000 => 6,
        }
    }
}

#[derive(Default)]
struct G722Band {
    s: i32,
    sp: i32,
    sz: i32,
    r: [i32; 3],
    a: [i32; 3],
    ap: [i32; 3],
    p: [i32; 3],
    d: [i32; 7],
    b: [i32; 7],
    bp: [i32; 7],
    sg: [i32; 7],
    nb: i32,
    det: i32,
}

fn saturate(amp: i32) -> i32 {
    amp.clamp(i16::MIN as i32, i16::MAX as i32)
}

fn block4(band: &mut G722Band, d: i32) {
    let mut wd1: i32;
    let mut wd2: i32;
    let mut wd3: i32;
    let mut i: usize;

    // Block 4, RECONS
    band.d[0] = d;
    band.r[0] = saturate(band.s + d);

    // Block 4, PARREC
    band.p[0] = saturate(band.sz + d);

    // Block 4, UPPOL2
    for i in 0..3 {
        band.sg[i] = band.p[i] >> 15;
    }
    wd1 = saturate(band.a[1] << 2);

    wd2 = if band.sg[0] == band.sg[1] { -wd1 } else { wd1 };
    if wd2 > 32767 {
        wd2 = 32767;
    }
    wd3 = (wd2 >> 7) + (if band.sg[0] == band.sg[2] { 128 } else { -128 });
    wd3 += (band.a[2] * 32512) >> 15;
    wd3 = wd3.clamp(-12288, 12288);
    band.ap[2] = wd3;

    // Block 4, UPPOL1
    band.sg[0] = band.p[0] >> 15;
    band.sg[1] = band.p[1] >> 15;
    wd1 = if band.sg[0] == band.sg[1] { 192 } else { -192 };
    wd2 = (band.a[1] * 32640) >> 15;

    band.ap[1] = saturate(wd1 + wd2);
    wd3 = saturate(15360 - band.ap[2]);
    if band.ap[1] > wd3 {
        band.ap[1] = wd3;
    } else if band.ap[1] < -wd3 {
        band.ap[1] = -wd3;
    }

    // Block 4, UPZERO
    wd1 = if d == 0 { 0 } else { 128 };
    band.sg[0] = d >> 15;
    i = 1;
    while i < 7 {
        band.sg[i] = band.d[i] >> 15;
        wd2 = if band.sg[i] == band.sg[0] { wd1 } else { -wd1 };
        wd3 = (band.b[i] * 32640) >> 15;
        band.bp[i] = saturate(wd2 + wd3);
        i += 1;
    }

    // Block 4, DELAYA
    i = 6;
    while i > 0 {
        band.d[i] = band.d[i - 1];
        band.b[i] = band.bp[i];
        i -= 1;
    }
    i = 2;
    while i > 0 {
        band.r[i] = band.r[i - 1];
        band.p[i] = band.p[i - 1];
        band.a[i] = band.ap[i];
        i -= 1;
    }

    // Block 4, FILTEP
    wd1 = saturate(band.r[1] + band.r[1]);
    wd1 = (band.a[1] * wd1) >> 15;
    wd2 = saturate(band.r[2] + band.r[2]);
    wd2 = (band.a[2] * wd2) >> 15;
    band.sp = saturate(wd1 + wd2);

    // Block 4, FILTEZ
    band.sz = 0;
    i = 6;
    while i > 0 {
        wd1 = saturate(band.d[i] + band.d[i]);
        band.sz += (band.b[i] * wd1) >> 15;
        i -= 1;
    }
    band.sz = saturate(band.sz);

    // Block 4, PREDIC
    band.s = saturate(band.sp + band.sz);
}
