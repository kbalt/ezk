//! Contains SIP message parts and parser

use crate::code::Code;
use crate::method::Method;
use crate::parse::{token, whitespace, ParseCtx};
use crate::print::{AppendCtx, Print, PrintCtx};
use crate::uri::Uri;
use crate::Name;
use anyhow::Result;
use bytes::Bytes;
use bytesstr::BytesStr;
use internal::ws;
use internal::IResult;
use memchr::memchr2;
use nom::branch::alt;
use nom::bytes::complete::{tag, take_while};
use nom::character::complete::char;
use nom::combinator::{map, map_res, opt};
use nom::sequence::{preceded, separated_pair, terminated, tuple};
use nom::AsChar;
use std::fmt;
use std::str::FromStr;

fn not_newline(c: char) -> bool {
    !matches!(c, '\n' | '\r')
}

/// Represents a header `header-name: header-value` line inside a message
///
/// When using [`PullParser`] to extract lines from a SIP message this type should be used to
/// parse the [`Name`] and remaining value from it.
///
/// # Example
///
/// ```rust
/// use ezk_sip_types::msg::{PullParser, Line};
/// use ezk_sip_types::Name;
/// use bytes::Bytes;
///
/// let msg = Bytes::from_static( b"REGISTER sips:ss2.biloxi.example.com SIP/2.0
/// Via: SIP/2.0/TLS client.biloxi.example.com:5061;branch=z9hG4bKnashds7
/// Max-Forwards: 70
/// From: Bob <sips:bob@biloxi.example.com>;tag=a73kszlfl
/// To: Bob <sips:bob@biloxi.example.com>
/// Call-ID: 1j9FpLxk3uxtm8tn@biloxi.example.com
/// CSeq: 1 REGISTER
/// Contact: <sips:bob@client.biloxi.example.com>
/// Content-Length: 0
///
/// ");
///
/// let mut parser = PullParser::new(&msg, 0);
///
/// // skip the first line
/// parser.next().unwrap();
///
/// let via_line = parser.next().unwrap().unwrap();
///
/// match Line::parse(&msg, std::str::from_utf8(via_line).unwrap()) {
///     Ok((_, line)) => {
///         assert_eq!(line.name, Name::VIA);
///         assert_eq!(line.value, "SIP/2.0/TLS client.biloxi.example.com:5061;branch=z9hG4bKnashds7")
///     }
///     Err(e) => panic!("{:?}", e)
/// }
/// ```
pub struct Line {
    pub name: Name,
    pub value: BytesStr,
}

impl Line {
    pub fn parse<'i>(src: &Bytes, i: &'i str) -> IResult<&'i str, Self> {
        map(
            ws((take_while(token), char(':'), |i| Ok(("", i)))),
            |(name, _, value)| Line {
                name: BytesStr::from_parse(src, name).into(),
                value: BytesStr::from_parse(src, value),
            },
        )(i)
    }
}

/// The leading line of any SIP message
#[derive(Debug, Clone)]
pub enum MessageLine {
    Request(RequestLine),
    Response(StatusLine),
}

impl MessageLine {
    /// takes a buffer containing a complete message-head buffer and returns a function which parses
    /// the message line of a sip message.
    pub fn parse<'p>(ctx: ParseCtx<'p>) -> impl Fn(&'p str) -> IResult<&'p str, Self> + 'p {
        move |i| {
            alt((
                map(StatusLine::parse(ctx), MessageLine::Response),
                map(RequestLine::parse(ctx), MessageLine::Request),
            ))(i)
        }
    }

    pub fn is_request(&self) -> bool {
        matches!(self, Self::Request(..))
    }

    pub fn request_method(&self) -> Option<&Method> {
        match self {
            MessageLine::Request(line) => Some(&line.method),
            MessageLine::Response(_) => None,
        }
    }
}

impl Print for MessageLine {
    fn print(&self, f: &mut fmt::Formatter<'_>, ctx: PrintCtx<'_>) -> fmt::Result {
        use std::fmt::Display;

        match &self {
            MessageLine::Request(l) => l.print(f, ctx),
            MessageLine::Response(l) => l.fmt(f),
        }
    }
}

/// The leading line of a SIP request message
#[derive(Debug, Clone)]
pub struct RequestLine {
    pub method: Method,
    pub uri: Box<dyn Uri>,
}

impl Print for RequestLine {
    fn print(&self, f: &mut fmt::Formatter<'_>, ctx: PrintCtx<'_>) -> fmt::Result {
        write!(f, "{} {} SIP/2.0", self.method, self.uri.print_ctx(ctx))
    }
}

impl RequestLine {
    pub(crate) fn parse<'p>(ctx: ParseCtx<'p>) -> impl Fn(&'p str) -> IResult<&'p str, Self> + 'p {
        move |i| {
            map(
                separated_pair(
                    Method::parse(ctx),
                    take_while(whitespace),
                    terminated(
                        ctx.parse_uri(),
                        tuple((take_while(whitespace), tag("SIP/2.0"))),
                    ),
                ),
                |(method, uri)| RequestLine { method, uri },
            )(i)
        }
    }
}

/// The leading line of a SIP response message
#[derive(Debug, Clone)]
pub struct StatusLine {
    pub code: Code,
    pub reason: Option<BytesStr>,
}

impl fmt::Display for StatusLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SIP/2.0 {}", self.code.into_u16())?;

        if let Some(reason) = &self.reason {
            write!(f, " {}", reason)?;
        }

        Ok(())
    }
}

impl StatusLine {
    pub(crate) fn parse(ctx: ParseCtx<'_>) -> impl Fn(&str) -> IResult<&str, Self> + '_ {
        move |i| {
            map(
                preceded(
                    tuple((tag("SIP/2.0"), take_while(whitespace))),
                    tuple((
                        map_res(take_while(char::is_dec_digit), u16::from_str),
                        take_while(whitespace),
                        opt(take_while(not_newline)),
                    )),
                ),
                move |(code, _, reason): (_, _, Option<&str>)| -> StatusLine {
                    StatusLine {
                        code: Code::from(code),
                        reason: reason.and_then(|reason| match reason.trim() {
                            "" => None,
                            s => Some(BytesStr::from_parse(ctx.src, s)),
                        }),
                    }
                },
            )(i)
        }
    }
}

/// Simple pull parser which returns all lines in a SIP message.
///
/// > __Note:__ Lines are terminated with either `\n` or `\r\n` followed by anything but a whitespace.
///
/// This is a SIP message feature allowing multi-line headers.
///
/// # Examples
///
/// ```
/// use ezk_sip_types::msg::PullParser;
///
/// // message taken from torture message rfc
/// let msg = b"OPTIONS sip:user;par=u%40example.net@example.com SIP/2.0
/// To: sip:j_user@example.com
/// From: sip:caller@example.org;tag=33242
/// Max-Forwards: 3
/// Call-ID: semiuri.0ha0isndaksdj
/// CSeq: 8 OPTIONS
/// Accept: application/sdp, application/pkcs7-mime,
///         multipart/mixed, multipart/signed,
///         message/sip, message/sipfrag
/// Via: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bKkdjuw
/// l: 0
///
/// ";
///
/// let mut parser = PullParser::new(msg, 0);
///
/// assert_eq!(parser.next(), Some(Ok(&b"OPTIONS sip:user;par=u%40example.net@example.com SIP/2.0"[..])));
/// assert_eq!(parser.next(), Some(Ok(&b"To: sip:j_user@example.com"[..])));
/// assert_eq!(parser.next(), Some(Ok(&b"From: sip:caller@example.org;tag=33242"[..])));
/// assert_eq!(parser.next(), Some(Ok(&b"Max-Forwards: 3"[..])));
/// assert_eq!(parser.next(), Some(Ok(&b"Call-ID: semiuri.0ha0isndaksdj"[..])));
/// assert_eq!(parser.next(), Some(Ok(&b"CSeq: 8 OPTIONS"[..])));
/// assert_eq!(parser.next(), Some(Ok(&b"Accept: application/sdp, application/pkcs7-mime,\n        multipart/mixed, multipart/signed,\n        message/sip, message/sipfrag"[..])));
/// assert_eq!(parser.next(), Some(Ok(&b"Via: SIP/2.0/UDP 192.0.2.1;branch=z9hG4bKkdjuw"[..])));
/// assert_eq!(parser.next(), Some(Ok(&b"l: 0"[..])));
/// assert_eq!(parser.next(), None);
/// ```
///
/// The parser can also be used to detect incomplete messages. Note that this parser only detects
/// if a SIP message __head__ is incomplete. To detect incomplete message bodies you need to parse
/// the content-length header and go from there.
///
/// ```
/// use ezk_sip_types::msg::PullParser;
///
/// // message taken from torture message rfc and randomly cut off
/// let msg = b"OPTIONS sip:user@example.com SIP/2.0
/// To: sip:user@example.com
/// From: caller<si";
///
/// let mut parser = PullParser::new(msg, 0);
///
/// assert_eq!(parser.next(), Some(Ok(&b"OPTIONS sip:user@example.com SIP/2.0"[..])));
/// assert_eq!(parser.next(), Some(Ok(&b"To: sip:user@example.com"[..])));
/// // since the parser cannot find a new line and didnt detect a message-head end yet
/// // it will return an error
/// assert!(parser.next().unwrap().is_err());
/// ```
#[derive(Clone)]
pub struct PullParser<'i> {
    input: &'i [u8],
    progress: usize,
}

/// semi-error type that just signals that the input is incomplete
#[derive(Debug, PartialEq, Eq)]
pub struct Incomplete(());

impl<'i> PullParser<'i> {
    /// Returns a new PullParser with input and progress
    pub fn new(input: &'i [u8], progress: usize) -> Self {
        Self { input, progress }
    }

    /// Returns the index of the last character of the message-head inside the slice
    /// only valid after parser returned None
    pub fn head_end(&self) -> usize {
        match self.input[self.progress..] {
            [b'\r', b'\n', b'\r', b'\n', ..] => self.progress + 4,
            [b'\n', b'\n', ..] => self.progress + 2,
            _ => self.progress,
        }
    }

    /// Returns the current progress.
    ///
    /// Saving the parser progress when encountering a incomplete message inside a streaming
    /// transport might be useful. It avoids having to parse the same lines multiple times.
    pub fn progress(&self) -> usize {
        self.progress
    }

    /// Perform a dry run of the parser to check if the input is incomplete
    pub fn check_complete(&mut self) -> Result<(), Incomplete> {
        for res in self {
            let _ = res?;
        }

        Ok(())
    }
}

impl<'i> Iterator for PullParser<'i> {
    type Item = Result<&'i [u8], Incomplete>;

    fn next(&mut self) -> Option<Self::Item> {
        let line_begin = self.progress;

        let mut skip = 0;

        loop {
            let progress = match memchr2(b'\n', b'\r', &self.input[line_begin + skip..]) {
                None => return Some(Err(Incomplete(()))),
                Some(progress) => progress,
            };

            let pos = progress + line_begin + skip;

            match self.input[pos..] {
                [b'\n', b' ' | b'\t', ..] | [b'\r', b'\n', b' ' | b'\t', ..] => {
                    // whitespace after newline means its not a new line
                    skip += progress + 1;
                }
                [b'\n', b, ..] => {
                    let slice = &self.input[line_begin..pos];

                    if slice.is_empty() {
                        return None;
                    }

                    if b == b'\n' {
                        self.progress = pos;
                    } else {
                        self.progress = pos + 1;
                    }

                    return Some(Ok(slice));
                }
                [b'\r', b'\n', b1, b2, ..] => {
                    let slice = &self.input[line_begin..pos];

                    if slice.is_empty() {
                        return None;
                    }

                    if b1 == b'\r' && b2 == b'\n' {
                        self.progress = pos;
                    } else {
                        self.progress = pos + 2;
                    }

                    return Some(Ok(slice));
                }
                _ => {
                    // this means there is a missing char after newline,
                    // since this is required the message is incomplete
                    return Some(Err(Incomplete(())));
                }
            }
        }
    }
}
