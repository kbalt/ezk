use crate::Direction;
use bytes::Bytes;
use bytesstr::BytesStr;
use internal::IResult;
use nom::{
    branch::alt,
    bytes::complete::{tag, take_while1},
    character::complete::digit1,
    combinator::{map, map_res, opt},
    multi::many0,
    sequence::{preceded, tuple},
};
use std::{fmt, str::FromStr};

#[derive(Debug, Clone)]
#[cfg_attr(test, derive(PartialEq))]
pub struct ExtMap {
    pub id: u8,
    pub direction: Direction,
    pub extension_name: BytesStr,
    pub extension_attributes: Vec<BytesStr>,
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
                    take_while1(char::is_whitespace),
                    take_while1(|c: char| !c.is_whitespace()),
                ),
                // attributes
                many0(preceded(
                    take_while1(char::is_whitespace),
                    map(take_while1(|c: char| !c.is_whitespace()), |attr| {
                        BytesStr::from_parse(src, attr)
                    }),
                )),
            )),
            |(id, direction, extension_name, extension_attributes)| Self {
                id,
                direction: direction.unwrap_or(Direction::SendRecv),
                extension_name: BytesStr::from_parse(src, extension_name.trim()),
                extension_attributes,
            },
        )(i)
    }
}

impl fmt::Display for ExtMap {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.id)?;

        if self.direction == Direction::SendRecv {
            write!(f, " {}", self.extension_name)?;
        } else {
            write!(f, "/{} {}", self.direction, self.extension_name)?;
        }

        for attribute in &self.extension_attributes {
            write!(f, " {attribute}")?;
        }

        Ok(())
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
        assert_eq!(extmap.extension_name, "myuri");
        assert_eq!(extmap.direction, Direction::SendRecv);
    }

    #[test]
    fn extmap_print() {
        let extmap = ExtMap {
            id: 3,
            direction: Direction::SendRecv,
            extension_name: "myuri".into(),
            extension_attributes: vec![],
        };

        assert_eq!(extmap.to_string(), "3 myuri");
    }

    #[test]
    fn extmap_print_with_direction() {
        let extmap = ExtMap {
            id: 3,
            direction: Direction::SendOnly,
            extension_name: "myuri".into(),
            extension_attributes: vec![],
        };

        assert_eq!(extmap.to_string(), "3/sendonly myuri");
    }

    #[test]
    fn extmap_print_with_attribute() {
        let extmap = ExtMap {
            id: 3,
            direction: Direction::SendOnly,
            extension_name: "myuri".into(),
            extension_attributes: vec!["test-attribute".into()],
        };

        let string = BytesStr::from(extmap.to_string());
        assert_eq!(string, "3/sendonly myuri test-attribute");

        assert_eq!(ExtMap::parse(string.as_ref(), &string).unwrap().1, extmap);
    }
}
