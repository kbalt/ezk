//
// SpanDSP - a series of DSP components for telephony
//
// g722_decode.c - The ITU G.722 codec, decode part.
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
// Based in part on a single channel G.722 codec which is:
//
// Copyright (c) CMU 1993
// Computer Science, Speech Group
// Chengxiang Lu and Alex Hauptmann
//
// The Carnegie Mellon ADPCM program is Copyright (c) 1993 by Carnegie Mellon
// University. Use of this program, for any research or commercial purpose, is
// completely unrestricted. If you make use of or redistribute this material,
// we would appreciate acknowlegement of its origin.
//

use super::{Bitrate, G722Band, block4, saturate};

static WL: [i32; 8] = [-60, -30, 58, 172, 334, 538, 1198, 3042];
static RL42: [i32; 16] = [0, 7, 6, 5, 4, 3, 2, 1, 7, 6, 5, 4, 3, 2, 1, 0];
static ILB: [i32; 32] = [
    2048, 2093, 2139, 2186, 2233, 2282, 2332, 2383, 2435, 2489, 2543, 2599, 2656, 2714, 2774, 2834,
    2896, 2960, 3025, 3091, 3158, 3228, 3298, 3371, 3444, 3520, 3597, 3676, 3756, 3838, 3922, 4008,
];
static WH: [i32; 3] = [0, -214, 798];
static RH2: [i32; 4] = [2, 1, 2, 1];
static QM2: [i32; 4] = [-7408, -1616, 7408, 1616];
static QM4: [i32; 16] = [
    0, -20456, -12896, -8968, -6288, -4240, -2584, -1200, 20456, 12896, 8968, 6288, 4240, 2584,
    1200, 0,
];
static QM5: [i32; 32] = [
    -280, -280, -23352, -17560, -14120, -11664, -9752, -8184, -6864, -5712, -4696, -3784, -2960,
    -2208, -1520, -880, 23352, 17560, 14120, 11664, 9752, 8184, 6864, 5712, 4696, 3784, 2960, 2208,
    1520, 880, 280, -280,
];
static QM6: [i32; 64] = [
    -136, -136, -136, -136, -24808, -21904, -19008, -16704, -14984, -13512, -12280, -11192, -10232,
    -9360, -8576, -7856, -7192, -6576, -6000, -5456, -4944, -4464, -4008, -3576, -3168, -2776,
    -2400, -2032, -1688, -1360, -1040, -728, 24808, 21904, 19008, 16704, 14984, 13512, 12280,
    11192, 10232, 9360, 8576, 7856, 7192, 6576, 6000, 5456, 4944, 4464, 4008, 3576, 3168, 2776,
    2400, 2032, 1688, 1360, 1040, 728, 432, 136, -432, -136,
];
static QMF_COEFFS: [i32; 12] = [3, -11, 12, 32, -210, 951, 3876, -805, 362, -156, 53, -11];

pub struct Decoder {
    itu_test_mode: bool,
    packed: bool,
    eight_k: bool,
    bits_per_sample: i32,
    x: [i32; 24],
    band: [G722Band; 2],
    in_buffer: u32,
    in_bits: i32,
}

impl Decoder {
    pub fn new(rate: Bitrate, packed: bool, eight_k: bool) -> Self {
        Self {
            itu_test_mode: false,
            packed,
            eight_k,
            bits_per_sample: rate.bits_per_sample(),
            x: Default::default(),
            band: Default::default(),
            in_buffer: 0,
            in_bits: 0,
        }
    }

    pub fn decode(&mut self, g722_data: &[u8], out: &mut Vec<i16>) {
        let mut dlowt: i32;
        let mut rlow: i32;
        let mut ihigh: i32;
        let mut dhigh: i32;
        let mut rhigh: i32;
        let mut xout1: i32;
        let mut xout2: i32;
        let mut wd1: i32;
        let mut wd2: i32;
        let mut wd3: i32;
        let mut code: i32;
        let mut i: usize;
        let mut j: usize;

        rhigh = 0;
        j = 0;
        while j < g722_data.len() {
            if self.packed {
                /* Unpack the code bits */
                if self.in_bits < self.bits_per_sample {
                    self.in_buffer |= (g722_data[j] as u32) << self.in_bits;
                    j += 1;
                    self.in_bits += 8;
                }
                code = (self.in_buffer & ((1 << self.bits_per_sample) - 1) as u32) as i32;
                self.in_buffer >>= self.bits_per_sample;
                self.in_bits -= self.bits_per_sample;
            } else {
                code = g722_data[j] as i32;
                j += 1;
            }

            match self.bits_per_sample {
                7 => {
                    wd1 = code & 0x1f;
                    ihigh = code >> 5 & 0x3;
                    wd2 = QM5[wd1 as usize];
                    wd1 >>= 1;
                }
                6 => {
                    wd1 = code & 0xf;
                    ihigh = code >> 4 & 0x3;
                    wd2 = QM4[wd1 as usize];
                }
                _ => {
                    wd1 = code & 0x3f;
                    ihigh = code >> 6 & 0x3;
                    wd2 = QM6[wd1 as usize];
                    wd1 >>= 2;
                }
            }

            // Block 5L, LOW BAND INVQBL
            wd2 = (self.band[0].det * wd2) >> 15;

            // Block 5L, RECONS
            rlow = self.band[0].s + wd2;

            // Block 6L, LIMIT
            rlow = rlow.clamp(-16384, 16383);

            // Block 2L, INVQAL
            wd2 = QM4[wd1 as usize];
            dlowt = (self.band[0].det * wd2) >> 15;

            // Block 3L, LOGSCL
            wd2 = RL42[wd1 as usize];
            wd1 = (self.band[0].nb * 127) >> 7;
            wd1 += WL[wd2 as usize];
            wd1 = wd1.clamp(0, 18432);
            self.band[0].nb = wd1;

            // Block 3L, SCALEL
            wd1 = self.band[0].nb >> 6 & 31;
            wd2 = 8 - (self.band[0].nb >> 11);
            wd3 = if wd2 < 0 {
                ILB[wd1 as usize] << -wd2
            } else {
                ILB[wd1 as usize] >> wd2
            };
            self.band[0].det = wd3 << 2;

            block4(&mut self.band[0], dlowt);

            if !self.eight_k {
                // Block 2H, INVQAH
                wd2 = QM2[ihigh as usize];
                dhigh = (self.band[1].det * wd2) >> 15;

                // Block 5H, RECONS
                rhigh = dhigh + self.band[1].s;

                // Block 6H, LIMIT
                rhigh = rhigh.clamp(-(16384), 16383);

                // Block 2H, INVQAH
                wd2 = RH2[ihigh as usize];
                wd1 = (self.band[1].nb * 127) >> 7;
                wd1 += WH[wd2 as usize];
                wd1 = wd1.clamp(0, 22528);
                self.band[1].nb = wd1;

                // Block 3H, SCALEH
                wd1 = self.band[1].nb >> 6 & 31;
                wd2 = 10 - (self.band[1].nb >> 11);
                wd3 = if wd2 < 0 {
                    ILB[wd1 as usize] << -wd2
                } else {
                    ILB[wd1 as usize] >> wd2
                };
                self.band[1].det = wd3 << 2;

                block4(&mut self.band[1], dhigh);
            }

            if self.itu_test_mode {
                out.push((rlow << 1) as i16);
                out.push((rhigh << 1) as i16);
            } else if self.eight_k {
                out.push((rlow << 1) as i16);
            } else {
                // Apply the receive QMF
                for i in 0..22 {
                    self.x[i] = self.x[i + 2];
                }
                self.x[22] = rlow + rhigh;
                self.x[23] = rlow - rhigh;

                xout1 = 0;
                xout2 = 0;
                i = 0;
                while i < 12 {
                    xout2 += self.x[2 * i] * QMF_COEFFS[i];
                    xout1 += self.x[2 * i + 1] * QMF_COEFFS[11 - i];
                    i += 1;
                }

                out.push(saturate(xout1 >> 11) as i16);
                out.push(saturate(xout2 >> 11) as i16);
            }
        }
    }
}
