//
// g722_encode.c - The ITU G.722 codec, encode part.
//
// Written by Steve Underwood <steveu@coppice.org>
//
// Copyright (C) 2005 Steve Underwood
//
// All rights reserved.
//
//  Despite my general liking of the GPL, I place my own contributions
//  to this code in the public domain for the benefit of all mankind -
//  even the slimy ones who might try to proprietize my work and use it
//  to my detriment.
//
// Based on a single channel 64kbps only G.722 codec which is:
//
//****    Copyright (c) CMU    1993      *****
// Computer Science, Speech Group
// Chengxiang Lu and Alex Hauptmann
//
// The Carnegie Mellon ADPCM program is Copyright (c) 1993 by Carnegie Mellon
// University. Use of this program, for any research or commercial purpose, is
// completely unrestricted. If you make use of or redistribute this material,
// we would appreciate acknowlegement of its origin.
//****
//

use super::{Bitrate, G722Band, block4, saturate};

static Q6: [i32; 32] = [
    0, 35, 72, 110, 150, 190, 233, 276, 323, 370, 422, 473, 530, 587, 650, 714, 786, 858, 940,
    1023, 1121, 1219, 1339, 1458, 1612, 1765, 1980, 2195, 2557, 2919, 0, 0,
];
static ILN: [i32; 32] = [
    0, 63, 62, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21, 20, 19, 18, 17, 16, 15, 14, 13, 12, 11,
    10, 9, 8, 7, 6, 5, 4, 0,
];
static ILP: [i32; 32] = [
    0, 61, 60, 59, 58, 57, 56, 55, 54, 53, 52, 51, 50, 49, 48, 47, 46, 45, 44, 43, 42, 41, 40, 39,
    38, 37, 36, 35, 34, 33, 32, 0,
];
static WL: [i32; 8] = [-60, -30, 58, 172, 334, 538, 1198, 3042];
static RL42: [i32; 16] = [0, 7, 6, 5, 4, 3, 2, 1, 7, 6, 5, 4, 3, 2, 1, 0];
static ILB: [i32; 32] = [
    2048, 2093, 2139, 2186, 2233, 2282, 2332, 2383, 2435, 2489, 2543, 2599, 2656, 2714, 2774, 2834,
    2896, 2960, 3025, 3091, 3158, 3228, 3298, 3371, 3444, 3520, 3597, 3676, 3756, 3838, 3922, 4008,
];
static QM4: [i32; 16] = [
    0, -20456, -12896, -8968, -6288, -4240, -2584, -1200, 20456, 12896, 8968, 6288, 4240, 2584,
    1200, 0,
];
static QM2: [i32; 4] = [-7408, -1616, 7408, 1616];
static QMF_COEFFS: [i32; 12] = [3, -11, 12, 32, -210, 951, 3876, -805, 362, -156, 53, -11];
static IHN: [i32; 3] = [0, 1, 0];
static IHP: [i32; 3] = [0, 3, 2];
static WH: [i32; 3] = [0, -214, 798];
static RH2: [i32; 4] = [2, 1, 2, 1];

pub struct Encoder {
    /// TRUE if the operating in the special ITU test mode, with the band split filters  disabled.
    itu_test_mode: bool,
    /// TRUE if the G.722 data is packed
    packed: bool,
    /// TRUE if encode from 8k samples/second
    eight_k: bool,
    /// 6 for 48000kbps, 7 for 56000kbps, or 8 for 64000kbps.
    bits_per_sample: i32,

    //// Signal history for the QMF
    x: [i32; 24],

    band: [G722Band; 2],

    out_buffer: u32,
    out_bits: i32,
}

impl Encoder {
    pub fn new(rate: Bitrate, eight_k: bool, packed: bool) -> Self {
        Self {
            itu_test_mode: false,
            packed,
            eight_k,
            bits_per_sample: rate.bits_per_sample(),
            x: Default::default(),
            band: Default::default(),
            out_buffer: 0,
            out_bits: 0,
        }
    }

    pub fn encode(&mut self, amp: &[i16], out: &mut Vec<u8>) {
        let mut dlow: i32;
        let mut dhigh: i32;
        let mut el: i32;
        let mut wd: i32;
        let mut wd1: i32;
        let mut ril: i32;
        let mut wd2: i32;
        let mut il4: i32;
        let mut ih2: i32;
        let mut wd3: i32;
        let mut eh: i32;
        let mut mih: i32;
        let mut i: usize;
        let mut j: usize;
        let mut xlow: i32;
        let mut xhigh: i32;
        let mut sumeven: i32;
        let mut sumodd: i32;
        let mut ihigh: i32;
        let mut ilow: i32;
        let mut code: i32;

        xhigh = 0;
        j = 0;
        while j < amp.len() {
            if self.itu_test_mode {
                xhigh = amp[j] as i32 >> 1;
                xlow = xhigh;
                j += 1;
            } else if self.eight_k {
                xlow = amp[j] as i32 >> 1;
                j += 1;
            } else {
                /* Apply the transmit QMF */
                /* Shuffle the buffer down */
                for i in 0..22 {
                    self.x[i] = self.x[i + 2];
                }
                self.x[22] = amp[j] as i32;
                j += 1;
                self.x[23] = amp[j] as i32;
                j += 1;

                // Discard every other QMF output
                sumeven = 0;
                sumodd = 0;
                for i in 0..12 {
                    sumodd += self.x[2 * i] * QMF_COEFFS[i];
                    sumeven += self.x[2 * i + 1] * QMF_COEFFS[11 - i];
                }
                xlow = (sumeven + sumodd) >> 14;
                xhigh = (sumeven - sumodd) >> 14;
            }

            // Block 1L, SUBTRA
            el = saturate(xlow - self.band[0].s);

            // Block 1L, QUANTL
            wd = if el >= 0 { el } else { -(el + 1) };

            i = 1;
            while i < 30 {
                wd1 = (Q6[i] * self.band[0].det) >> 12;
                if wd < wd1 {
                    break;
                }
                i += 1;
            }
            ilow = if el < 0 { ILN[i] } else { ILP[i] };

            // Block 2L, INVQAL
            ril = ilow >> 2;
            wd2 = QM4[ril as usize];
            dlow = (self.band[0].det * wd2) >> 15;

            // Block 3L, LOGSCL
            il4 = RL42[ril as usize];
            wd = (self.band[0].nb * 127) >> 7;
            self.band[0].nb = wd + WL[il4 as usize];
            self.band[0].nb = self.band[0].nb.clamp(0, 18432);

            // Block 3L, SCALEL
            wd1 = self.band[0].nb >> 6 & 31;
            wd2 = 8 - (self.band[0].nb >> 11);
            wd3 = if wd2 < 0 {
                ILB[wd1 as usize] << -wd2
            } else {
                ILB[wd1 as usize] >> wd2
            };
            self.band[0].det = wd3 << 2;

            block4(&mut self.band[0], dlow);

            if self.eight_k {
                // Just leave the high bits as zero
                code = ((0xc0 | ilow) >> 8) - self.bits_per_sample;
            } else {
                // Block 1H, SUBTRA
                eh = saturate(xhigh - self.band[1].s);

                // Block 1H, QUANTH
                wd = if eh >= 0 { eh } else { -(eh + 1) };
                wd1 = (564 * self.band[1].det) >> 12;
                mih = if wd >= wd1 { 2 } else { 1 };
                ihigh = if eh < 0 {
                    IHN[mih as usize]
                } else {
                    IHP[mih as usize]
                };

                // Block 2H, INVQAH
                wd2 = QM2[ihigh as usize];
                dhigh = (self.band[1].det * wd2) >> 15;

                // Block 3H, LOGSCH
                ih2 = RH2[ihigh as usize];
                wd = (self.band[1].nb * 127) >> 7;
                self.band[1].nb = wd + WH[ih2 as usize];
                self.band[1].nb = self.band[1].nb.clamp(0, 22528);

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
                code = (ihigh << 6 | ilow) >> (8 - self.bits_per_sample);
            }

            if self.packed {
                /* Pack the code bits */
                self.out_buffer |= (code << self.out_bits) as u32;
                self.out_bits += self.bits_per_sample;
                if self.out_bits >= 8 {
                    self.out_bits -= 8;
                    self.out_buffer >>= 8;
                }
            } else {
                out.push(code as u8);
            }
        }
    }
}
