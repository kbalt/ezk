use crate::Result;
use bytes::{Bytes, BytesMut};
use internal::Finish;
use sip_types::msg::{Line, MessageLine, PullParser};
use sip_types::parse::{ParseCtx, Parser};
use sip_types::Headers;
use std::io;
use std::mem::replace;
use std::str::{from_utf8, Utf8Error};
use tokio_util::codec::Decoder;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io(io::Error),
    #[error("receiving message too large")]
    MessageTooLarge,
    #[error("received message is malformed")]
    Malformed,
}

impl From<Utf8Error> for Error {
    fn from(_: Utf8Error) -> Self {
        Self::Malformed
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub struct DecodedMessage {
    pub line: MessageLine,
    pub headers: Headers,
    pub body: Bytes,

    pub buffer: Bytes,
}

pub struct StreamingDecoder {
    head_progress: usize,
    parser: Parser,
}

impl StreamingDecoder {
    pub fn new(parser: Parser) -> Self {
        Self {
            head_progress: 0,
            parser,
        }
    }
}

impl Decoder for StreamingDecoder {
    type Item = DecodedMessage;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        if &src[..] == b"\r\n" {
            src.clear();
            return Ok(None);
        }

        if src.len() > 4096 {
            // do not allow a message head larger than that
            src.clear();

            return Err(Error::MessageTooLarge);
        }

        let mut parser = PullParser::new(src, self.head_progress);

        let mut content_len = 0;

        for line in &mut parser {
            if let Ok(line) = line {
                // try to find content-length field
                // so the complete message size can be calculated
                let mut split = line.splitn(2, |&c| c == b':');

                if let Some(name) = split.next() {
                    if name.eq_ignore_ascii_case(b"content-length") || name.starts_with(b"l") {
                        let value = split.next().ok_or(Error::Malformed)?;
                        let value = from_utf8(value)?;

                        content_len = value
                            .trim()
                            .parse::<usize>()
                            .map_err(|_| Error::Malformed)?;

                        if content_len > (u16::MAX as usize) {
                            return Err(Error::MessageTooLarge);
                        }
                    }
                }
            } else {
                // cannot parse complete message head yet
                self.head_progress = parser.progress();
                return Ok(None);
            }
        }

        // parser completed without errors
        // message head should be complete

        // Calculate the complete message size
        let expected_complete_message_size = parser.head_end() + content_len;

        // if the message is not completely inside the buffer, allocate the rest
        // and return
        if src.len() < expected_complete_message_size {
            src.reserve(expected_complete_message_size - src.len());
            return Ok(None);
        }

        // copy remaining bytes into new buffer
        let new_src = BytesMut::from(&src[expected_complete_message_size..]);

        // Truncate all bytes which are not related
        // to the current message and are stored inside new_src
        src.truncate(expected_complete_message_size);

        // freeze buffer
        let src_bytes = replace(src, new_src).freeze();

        // reset state
        self.head_progress = 0;

        // reset parser
        parser = PullParser::new(&src_bytes, 0);

        // Now properly parse the message
        let mut message_line = None;
        let mut headers = Headers::new();

        for item in &mut parser {
            let item = item.expect("got error when input was already checked");

            let line = from_utf8(item)?;

            if message_line.is_none() {
                let ctx = ParseCtx::new(&src_bytes, self.parser);

                match MessageLine::parse(ctx)(line) {
                    Ok((_, line)) => message_line = Some(line),
                    Err(_) => return Err(Error::Malformed),
                }
            } else {
                match Line::parse(&src_bytes, line).finish() {
                    Ok((_, line)) => headers.insert(line.name, line.value),
                    Err(e) => {
                        log::error!("Incoming SIP message has malformed header line, {}", e);
                    }
                }
            }
        }

        let head_end = parser.head_end();

        // slice remaining bytes
        let body = src_bytes.slice(head_end..head_end + content_len);
        assert_eq!(content_len, body.len());

        Ok(Some(DecodedMessage {
            line: message_line.ok_or(Error::Malformed)?,
            headers,
            body,
            buffer: src_bytes,
        }))
    }
}
