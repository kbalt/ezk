use crate::Direction;
use bytes::Bytes;
use bytesstr::BytesStr;
use internal::IResult;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_while},
    character::complete::digit1,
    combinator::{map, map_res, opt},
    sequence::{preceded, tuple},
};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone)]
pub struct ExtMap {
    pub id: u8,
    pub uri: BytesStr,
    pub direction: Direction,
}

impl ExtMap {
    pub fn parse<'i>(src: &Bytes, i: &'i str) -> IResult<&'i str, Self> {
        map(
            tuple((
                // id
                map_res(digit1, FromStr::from_str),
                // direction
                opt(alt((
                    map(tag("/sendrecv"), |_| Direction::SendRecv),
                    map(tag("/recvonly"), |_| Direction::RecvOnly),
                    map(tag("/sendonly"), |_| Direction::SendOnly),
                    map(tag("/inactive"), |_| Direction::Inactive),
                ))),
                // uri
                preceded(
                    take_while(char::is_whitespace),
                    take_while(|c: char| !c.is_whitespace()),
                ),
            )),
            |(id, direction, uri)| Self {
                id,
                uri: BytesStr::from_parse(src, uri.trim()),
                direction: direction.unwrap_or(Direction::SendRecv),
            },
        )(i)
    }
}

impl fmt::Display for ExtMap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.id)?;

        if self.direction == Direction::SendRecv {
            write!(f, " {}", self.uri)
        } else {
            write!(f, "/{} {}", self.direction, self.uri)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn extmap() {
        let input = BytesStr::from_static("1 myuri");

        let (rem, extmap) = ExtMap::parse(input.as_ref(), &input).unwrap();

        assert!(rem.is_empty());

        assert_eq!(extmap.id, 1);
        assert_eq!(extmap.uri, "myuri");
        assert_eq!(extmap.direction, Direction::SendRecv);
    }

    #[test]
    fn extmap_print() {
        let extmap = ExtMap {
            id: 3,
            uri: "myuri".into(),
            direction: Direction::SendRecv,
        };

        assert_eq!(extmap.to_string(), "3 myuri");
    }

    #[test]
    fn extmap_print_with_direction() {
        let extmap = ExtMap {
            id: 3,
            uri: "myuri".into(),
            direction: Direction::SendOnly,
        };

        assert_eq!(extmap.to_string(), "3/sendonly myuri");
    }
}
