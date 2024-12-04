use internal::ws;
use internal::IResult;
use nom::character::complete::digit1;
use nom::combinator::map;
use nom::combinator::map_res;
use nom::error::context;
use std::fmt;
use std::str::FromStr;

/// Time field (`t=`)
///
/// [RFC8866](https://www.rfc-editor.org/rfc/rfc8866.html#section-5.9)
#[derive(Debug, Clone)]
pub struct Time {
    /// The time, in seconds since January 1 1900 UTC, when the session is supposed to start.
    ///
    /// If 0 is specified the session should start immediately or
    /// whenever the parent signaling protocol signals to.
    pub start: u64,

    /// The time, in seconds since January 1 1900 UTC, when the session is supposed to end.
    ///
    /// If 0 is specified the session will run forever
    /// or until torn down by the parent signaling protocol.
    pub stop: u64,
}

impl Time {
    pub fn parse(i: &str) -> IResult<&str, Self> {
        context(
            "parsing time field",
            map(
                ws((
                    map_res(digit1, FromStr::from_str),
                    map_res(digit1, FromStr::from_str),
                )),
                |(start, stop)| Time { start, stop },
            ),
        )(i)
    }
}

impl fmt::Display for Time {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} {}", self.start, self.stop)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn time() {
        let (rem, time) = Time::parse("0 0").unwrap();

        assert!(rem.is_empty());

        assert_eq!(time.start, 0);
        assert_eq!(time.stop, 0);
    }

    #[test]
    fn time_print() {
        let time = Time { start: 0, stop: 0 };

        assert_eq!(time.to_string(), "t=0 0");
    }
}
