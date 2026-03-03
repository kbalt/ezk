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

    pub(super) fn to_instant(self) -> Instant {
        let (ref_time, ref_instant) = &*SYSTEM_TIME_TO_INSTANT;
        let system_time = NTP_EPOCH + self.inner;
        let offset = system_time - *ref_time;

        *ref_instant + offset
    }

    pub(super) fn as_seconds_f64(self) -> f64 {
        self.inner.as_seconds_f64()
    }

    pub(super) fn to_fixed_u64(self) -> u64 {
        let total_nanos = self.inner.whole_nanoseconds();

        let seconds = total_nanos.div_euclid(1_000_000_000) as u64;
        let nanos = total_nanos.rem_euclid(1_000_000_000) as f64;

        let subseconds = (nanos / 1_000_000_000.0 * 2f64.powi(32)) as u64;

        (seconds << 32) | subseconds
    }

    /// Returns the middle 32 bits of [`to_fixed_u64`](Self::to_fixed_u64)
    pub(super) fn to_fixed_u32(self) -> u32 {
        ((self.to_fixed_u64() >> 16) & u64::from(u32::MAX)) as u32
    }

    pub(super) fn from_fixed_u64(fixed: u64) -> Self {
        let seconds = (fixed >> 32) as i64;
        let subseconds = (fixed & u64::from(u32::MAX)) as f64;
        let subseconds = subseconds / (2f64.powi(32));
        Self {
            inner: SignedDuration::new(seconds, (subseconds * 1_000_000_000.) as i32),
        }
    }

    pub(super) fn from_fixed_u32(fixed: u32) -> Self {
        let seconds = (fixed >> 16) as i64;

        let subseconds = (fixed & u32::from(u16::MAX)) as f64;
        let subseconds = subseconds / (2f64.powi(16));

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

#[test]
fn self_test_fixed_u64() {
    let now = NtpTimestamp::from_instant(Instant::now());

    let converted_and_back = NtpTimestamp::from_fixed_u64(now.to_fixed_u64());

    let diff = converted_and_back - now;

    assert!(diff.inner < time::Duration::nanoseconds(5));
    assert!(diff.inner > time::Duration::nanoseconds(-5));
}
