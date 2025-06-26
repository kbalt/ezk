use crate::Result;
use bytes::{Buf, Bytes, BytesMut};
use internal::Finish;
use sip_types::Headers;
use sip_types::msg::{Line, MessageLine, PullParser};
use sip_types::parse::Parse;
use std::io;
use std::str::{Utf8Error, from_utf8};
use tokio_util::codec::Decoder;

#[derive(Debug, thiserror::Error)]
pub(crate) enum Error {
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

#[allow(clippy::large_enum_variant)]
pub(crate) enum Item {
    DecodedMessage(DecodedMessage),
    KeepAliveRequest,
    KeepAliveResponse,
}

pub(crate) struct DecodedMessage {
    pub line: MessageLine,
    pub headers: Headers,
    pub body: Bytes,

    pub buffer: Bytes,
}

#[derive(Default)]
pub(crate) struct StreamingDecoder {
    head_progress: usize,
}

impl Decoder for StreamingDecoder {
    type Item = Item;
    type Error = Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // strip leading newlines
        let whitespace_count = src.iter().take_while(|b| b.is_ascii_whitespace()).count();
        if whitespace_count > 0 {
            let is_keep_alive_request = src.starts_with(b"\r\n\r\n");
            let is_keep_alive_response = src.starts_with(b"\r\n");

            src.advance(whitespace_count);

            if is_keep_alive_request {
                return Ok(Some(Item::KeepAliveRequest));
            } else if is_keep_alive_response {
                return Ok(Some(Item::KeepAliveResponse));
            }
        }

        // limit message size
        if src.len() > 65535 {
            src.clear();

            return Err(Error::MessageTooLarge);
        }

        let mut parser = PullParser::new(src, self.head_progress);

        let mut content_len = 0;

        for line in &mut parser {
            let Ok(line) = line else {
                // cannot parse complete message head yet
                self.head_progress = parser.progress();
                return Ok(None);
            };

            // try to find content-length field
            // so the complete message size can be calculated
            let mut split = line.splitn(2, |&c| c == b':');

            let Some(name) = split.next() else {
                continue;
            };

            let content_length_possible_names = sip_types::Name::CONTENT_LENGTH
                .as_parse_strs()
                .unwrap_or_default();

            if content_length_possible_names
                .iter()
                .any(|str| name.eq_ignore_ascii_case(str.as_bytes()))
            {
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

        // Truncate all bytes which are not related
        // to the current message and are stored inside new_src
        let src_bytes = src.split_to(expected_complete_message_size).freeze();

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
                match MessageLine::parse(&src_bytes)(line) {
                    Ok((_, line)) => message_line = Some(line),
                    Err(_) => return Err(Error::Malformed),
                }
            } else {
                match Line::parse(&src_bytes, line).finish() {
                    Ok((_, line)) => headers.insert(line.name, line.value),
                    Err(e) => {
                        log::error!("Incoming SIP message has malformed header line, {e}");
                    }
                }
            }
        }

        let head_end = parser.head_end();

        // slice remaining bytes
        let body = src_bytes.slice(head_end..head_end + content_len);
        assert_eq!(content_len, body.len());

        Ok(Some(Item::DecodedMessage(DecodedMessage {
            line: message_line.ok_or(Error::Malformed)?,
            headers,
            body,
            buffer: src_bytes,
        })))
    }
}
