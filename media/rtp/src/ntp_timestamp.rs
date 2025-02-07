use std::ops::Sub;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NtpTimestamp {
    // Duration since 01.01.1900
    inner: time::Duration,
}

impl NtpTimestamp {
    pub const ZERO: Self = Self {
        inner: time::Duration::ZERO,
    };

    pub fn now() -> Self {
        let epoch = time::Date::from_calendar_date(1900, time::Month::January, 1).unwrap();
        let epoch = time::OffsetDateTime::new_utc(epoch, time::Time::MIDNIGHT);

        Self {
            inner: time::OffsetDateTime::now_utc() - epoch,
        }
    }

    pub fn as_seconds_f64(self) -> f64 {
        self.inner.as_seconds_f64()
    }

    pub fn to_fixed_u64(self) -> u64 {
        let seconds = self.inner.whole_seconds() as u64;
        let subseconds =
            (self.inner.subsec_nanoseconds() as f64 / 1_000_000_000.) * u32::MAX as f64;
        let subseconds = subseconds as u64;

        (seconds << 32) | subseconds
    }

    pub fn to_fixed_u32(self) -> u32 {
        ((self.to_fixed_u64() >> 16) & u64::from(u32::MAX)) as u32
    }

    pub fn from_fixed_u64(fixed: u64) -> Self {
        let seconds = (fixed >> 32) as i64;

        let subseconds = (fixed & u64::from(u32::MAX)) as u32;
        let subseconds = subseconds as f64 / (u32::MAX as f64);

        Self {
            inner: time::Duration::new(seconds, (subseconds * 1_000_000_000.) as i32),
        }
    }

    pub fn from_fixed_u32(fixed: u32) -> Self {
        let seconds = (fixed >> 16) as i64;

        let subseconds = (fixed & u32::from(u16::MAX)) as u16;
        let subseconds = subseconds as f64 / (u16::MAX as f64);

        Self {
            inner: time::Duration::new(seconds, (subseconds * 1_000_000_000.) as i32),
        }
    }
}

impl Sub for NtpTimestamp {
    type Output = time::Duration;

    fn sub(self, rhs: Self) -> Self::Output {
        self.inner - rhs.inner
    }
}
