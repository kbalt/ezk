/// H.264 encoding levels with their corresponding capabilities.
#[derive(Debug, Clone, Copy)]
#[allow(non_camel_case_types)]
pub enum Level {
    /// Level 1.0: Max resolution 176x144 (QCIF), 15 fps, 64 kbps (Main), 80 kbps (High)
    Level_1_0,
    /// Level 1.B: Specialized low-complexity baseline level.
    Level_1_B,
    /// Level 1.1: Max resolution 176x144 (QCIF), 30 fps, 192 kbps (Main), 240 kbps (High)
    Level_1_1,
    /// Level 1.2: Max resolution 320x240 (QVGA), 30 fps, 384 kbps (Main), 480 kbps (High)
    Level_1_2,
    /// Level 1.3: Reserved in standard, similar to Level 2.0.
    Level_1_3,

    /// Level 2.0: Max resolution 352x288 (CIF), 30 fps, 2 Mbps (Main), 2.5 Mbps (High)
    Level_2_0,
    /// Level 2.1: Max resolution 352x288 (CIF), 30 fps, 4 Mbps (Main), 5 Mbps (High)
    Level_2_1,
    /// Level 2.2: Max resolution 352x288 (CIF), 30 fps, 10 Mbps (Main), 12.5 Mbps (High)
    Level_2_2,

    /// Level 3.0: Max resolution 720x576 (SD), 30 fps, 10 Mbps (Main), 12.5 Mbps (High)
    Level_3_0,
    /// Level 3.1: Max resolution 1280x720 (HD), 30 fps, 14 Mbps (Main), 17.5 Mbps (High)
    Level_3_1,
    /// Level 3.2: Max resolution 1280x720 (HD), 60 fps, 20 Mbps (Main), 25 Mbps (High)
    Level_3_2,

    /// Level 4.0: Max resolution 1920x1080 (Full HD), 30 fps, 20 Mbps (Main), 25 Mbps (High)
    Level_4_0,
    /// Level 4.1: Max resolution 1920x1080 (Full HD), 60 fps, 50 Mbps (Main), 62.5 Mbps (High)
    Level_4_1,
    /// Level 4.2: Max resolution 1920x1080 (Full HD), 120 fps, 100 Mbps (Main), 125 Mbps (High)
    Level_4_2,

    /// Level 5.0: Max resolution 3840x2160 (4K), 30 fps, 135 Mbps (Main), 168.75 Mbps (High)
    Level_5_0,
    /// Level 5.1: Max resolution 3840x2160 (4K), 60 fps, 240 Mbps (Main), 300 Mbps (High)
    Level_5_1,
    /// Level 5.2: Max resolution 4096x2160 (4K Cinema), 60 fps, 480 Mbps (Main), 600 Mbps (High)
    Level_5_2,

    /// Level 6.0: Max resolution 8192x4320 (8K UHD), 30 fps, 240 Mbps (Main), 240 Mbps (High)
    Level_6_0,
    /// Level 6.1: Max resolution 8192x4320 (8K UHD), 60 fps, 480 Mbps (Main), 480 Mbps (High)
    Level_6_1,
    /// Level 6.2: Max resolution 8192x4320 (8K UHD), 120 fps, 800 Mbps (Main), 800 Mbps (High)
    Level_6_2,
}

impl Level {
    /// Returns the level idc as specified in H.264 for this level
    ///
    /// Note that level 1.1 & 1.b have the same value
    pub fn level_idc(self) -> u8 {
        match self {
            Level::Level_1_0 => 10,
            Level::Level_1_B => 11,
            Level::Level_1_1 => 11,
            Level::Level_1_2 => 12,
            Level::Level_1_3 => 13,
            Level::Level_2_0 => 20,
            Level::Level_2_1 => 21,
            Level::Level_2_2 => 22,
            Level::Level_3_0 => 30,
            Level::Level_3_1 => 31,
            Level::Level_3_2 => 32,
            Level::Level_4_0 => 40,
            Level::Level_4_1 => 41,
            Level::Level_4_2 => 42,
            Level::Level_5_0 => 50,
            Level::Level_5_1 => 51,
            Level::Level_5_2 => 52,
            Level::Level_6_0 => 60,
            Level::Level_6_1 => 61,
            Level::Level_6_2 => 62,
        }
    }

    pub fn max_mbps(self) -> u32 {
        self.limits().0
    }

    pub fn max_fs(self) -> u32 {
        self.limits().1
    }

    pub fn max_br(self) -> u32 {
        self.limits().3
    }

    /// ITU-T H.264 Table A-1 Level Limits
    ///
    /// 0 - Max macroblock processing rate MaxMBPS (MB/s)
    /// 1 - Max frame size MaxFS (MBs)
    /// 2 - Max decoded picture buffer size MaxDpbMbs (MBs)
    /// 3 - Max video bit rate MaxBR (1000 bits/s, 1200 bits/s, cpbBrVclFactor bits/s, or cpbBrNalFactor bits/s)
    /// 4 - Max CPB size MaxCPB (1000 bits, 1200 bits, cpbBrVclFactor bits, or cpbBrNalFactor bits)
    /// 5 - Vertical MV component limit MaxVmvR (luma frame samples)
    /// 6 - Min compression ratio MinCR
    /// 7 - Max number of motion vectors per two consecutive MBs MaxMvsPer2Mb
    fn limits(self) -> (u32, u32, u32, u32, u32, u32, u32, Option<u32>) {
        match self {
            Level::Level_1_0 => (1485, 99, 396, 64, 175, 64, 2, None),
            Level::Level_1_B => (1485, 99, 396, 128, 350, 64, 2, None),
            Level::Level_1_1 => (3000, 396, 900, 192, 500, 128, 2, None),
            Level::Level_1_2 => (6000, 396, 2376, 384, 1000, 128, 2, None),
            Level::Level_1_3 => (11880, 396, 2376, 768, 2000, 128, 2, None),
            Level::Level_2_0 => (11880, 396, 2376, 2000, 2000, 128, 2, None),
            Level::Level_2_1 => (19800, 792, 4752, 4000, 4000, 256, 2, None),
            Level::Level_2_2 => (20250, 1620, 8100, 4000, 4000, 256, 2, None),
            Level::Level_3_0 => (40500, 1620, 8100, 10000, 10000, 256, 2, Some(32)),
            Level::Level_3_1 => (108000, 3600, 18000, 14000, 14000, 512, 4, Some(16)),
            Level::Level_3_2 => (216000, 5120, 20480, 20000, 20000, 512, 4, Some(16)),
            Level::Level_4_0 => (245760, 8192, 32768, 20000, 25000, 512, 4, Some(16)),
            Level::Level_4_1 => (245760, 8192, 32768, 50000, 62500, 512, 2, Some(16)),
            Level::Level_4_2 => (522240, 8704, 34816, 50000, 62500, 512, 2, Some(16)),
            Level::Level_5_0 => (589824, 22080, 110400, 135000, 135000, 512, 2, Some(16)),
            Level::Level_5_1 => (983040, 36864, 184320, 240000, 240000, 512, 2, Some(16)),
            Level::Level_5_2 => (2073600, 36864, 184320, 240000, 240000, 512, 2, Some(16)),
            Level::Level_6_0 => (4177920, 139264, 696320, 240000, 240000, 8192, 2, Some(16)),
            Level::Level_6_1 => (8355840, 139264, 696320, 480000, 480000, 8192, 2, Some(16)),
            Level::Level_6_2 => (16711680, 139264, 696320, 800000, 800000, 8192, 2, Some(16)),
        }
    }
}
