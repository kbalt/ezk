use std::{
    ops::Sub,
    sync::LazyLock,
    time::{Duration, Instant, SystemTime},
};
use time::{Date, Duration as SignedDuration, Month, OffsetDateTime, ext::InstantExt};

static SYSTEM_TIME_TO_INSTANT: LazyLock<(SystemTime, Instant)> = LazyLock::new(|| {
    let time = SystemTime::now();
    let instant = Instant::now();

    (time, instant)
});

const NTP_EPOCH: OffsetDateTime = const {
    let date = match Date::from_calendar_date(1900, Month::January, 1) {
        Ok(date) => date,
        Err(_e) => panic!("invalid date"),
    };

    OffsetDateTime::new_utc(date, time::Time::MIDNIGHT)
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct NtpTimestamp {
    // Duration since 01.01.1900
    inner: SignedDuration,
}

impl NtpTimestamp {
    pub(super) fn from_instant(now: Instant) -> Self {
        let (ref_time, ref_instant) = &*SYSTEM_TIME_TO_INSTANT;
        let system_time = *ref_time + now.signed_duration_since(*ref_instant);

        Self {
            inner: system_time - NTP_EPOCH,
        }
    }

    pub(super) fn as_seconds_f64(self) -> f64 {
        self.inner.as_seconds_f64()
    }

    pub(super) fn to_fixed_u64(self) -> u64 {
        let seconds = self.inner.whole_seconds() as u64;

        let subseconds = self.inner.as_seconds_f64().fract() * u32::MAX as f64;
        let subseconds = subseconds as u64;

        (seconds << 32) | subseconds
    }

    /// Returns the middle 32 bits of [`to_fixed_u64`](Self::to_fixed_u64)
    pub(super) fn to_fixed_u32(self) -> u32 {
        ((self.to_fixed_u64() >> 16) & u64::from(u32::MAX)) as u32
    }

    // Not a fan of commented out code, but I don't know if or when I might need this
    //pub(super) fn from_fixed_u64(fixed: u64) -> Self {
    //    let seconds = (fixed >> 32) as i64;
    //    let subseconds = (fixed & u64::from(u32::MAX)) as u32;
    //    let subseconds = subseconds as f64 / (u32::MAX as f64);
    //    Self {
    //        inner: SignedDuration::new(seconds, (subseconds * 1_000_000_000.) as i32),
    //    }
    //}

    pub(super) fn from_fixed_u32(fixed: u32) -> Self {
        let seconds = (fixed >> 16) as i64;

        let subseconds = (fixed & u32::from(u16::MAX)) as u16;
        let subseconds = subseconds as f64 / (u16::MAX as f64);

        Self {
            inner: SignedDuration::new(seconds, (subseconds * 1_000_000_000.) as i32),
        }
    }

    pub(super) fn to_std_duration(self) -> Option<Duration> {
        self.inner.try_into().ok()
    }
}

impl Sub for NtpTimestamp {
    type Output = NtpTimestamp;

    fn sub(self, rhs: Self) -> Self::Output {
        NtpTimestamp {
            inner: self.inner - rhs.inner,
        }
    }
}
