use crate::transport::parse_line;
use crate::{Error, Result, WithStatus};
use anyhow::anyhow;
use bytes::{Bytes, BytesMut};
use sip_types::msg::{MessageLine, PullParser};
use sip_types::parse::{ParseCtx, Parser};
use sip_types::{Code, Headers};
use std::mem::replace;
use std::str::from_utf8;
use tokio_util::codec::Decoder;

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
        if src.len() > 4096 {
            // do not allow a message head larger than that
            src.clear();

            return Err(Error::new(Code::MESSAGE_TOO_LARGE));
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
                        let value = split.next().status(Code::BAD_REQUEST)?;
                        let value = from_utf8(value)?;

                        content_len = value.trim().parse::<usize>().status(Code::BAD_REQUEST)?;

                        if content_len > (u16::MAX as usize) {
                            return Err(Error::new(Code::MESSAGE_TOO_LARGE));
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
                    Err(_) => {
                        return Err(Error {
                            status: Code::BAD_REQUEST,
                            error: Some(anyhow!("Invalid Message Line")),
                        })
                    }
                }
            } else {
                parse_line(&src_bytes, line, &mut headers)?;
            }
        }

        let head_end = parser.head_end();

        // slice remaining bytes
        let body = src_bytes.slice(head_end..head_end + content_len);
        assert_eq!(content_len, body.len());

        Ok(Some(DecodedMessage {
            line: message_line.status(Code::BAD_REQUEST)?,
            headers,
            body,
            buffer: src_bytes,
        }))
    }
}
