use bytes::Bytes;
use internal::Finish;
use sip_types::header::typed::ContentLength;
use sip_types::msg::{Line, MessageLine, PullParser};
use sip_types::parse::{ParseCtx, Parser};
use sip_types::Headers;
use std::str::from_utf8;
use stun_types::is_stun_message;
use stun_types::parse::ParsedMessage;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the given input was invalid in this context and couldn't be parsed")]
    FailedToParse,
}

pub enum CompleteItem {
    KeepAliveRequest,
    KeepAliveResponse,
    Stun(ParsedMessage),
    Sip {
        line: MessageLine,
        headers: Headers,
        body: Bytes,
        buffer: Bytes,
    },
}

pub fn parse_complete(parser: Parser, bytes: &[u8]) -> Result<CompleteItem, Error> {
    if bytes == b"\r\n\r\n" {
        return Ok(CompleteItem::KeepAliveRequest);
    } else if bytes == b"\r\n" {
        return Ok(CompleteItem::KeepAliveResponse);
    }

    match is_stun_message(bytes) {
        stun_types::IsStunMessageInfo::TooShort
        | stun_types::IsStunMessageInfo::YesIncomplete { needed: _ } => Err(Error::FailedToParse),
        stun_types::IsStunMessageInfo::Yes { remaining } => {
            parse_complete_stun(&bytes[..bytes.len() - remaining])
        }
        stun_types::IsStunMessageInfo::No => parse_complete_sip(parser, bytes),
    }
}

fn parse_complete_stun(bytes: &[u8]) -> Result<CompleteItem, Error> {
    let msg = match ParsedMessage::parse(bytes.into()) {
        Ok(msg) => msg,
        Err(e) => {
            log::warn!("failed to parse complete stun message, {}", e);
            return Err(Error::FailedToParse);
        }
    };

    Ok(CompleteItem::Stun(msg))
}

fn parse_complete_sip(parser_: Parser, bytes: &[u8]) -> Result<CompleteItem, Error> {
    let buffer = Bytes::copy_from_slice(bytes);

    let mut parser = PullParser::new(&buffer, 0);

    let mut message_line = None;
    let mut headers = Headers::new();

    for item in &mut parser {
        let line = match item {
            Ok(line) => line,
            Err(_) => {
                log::warn!("Incoming SIP messages is incomplete");
                return Err(Error::FailedToParse);
            }
        };

        let line = from_utf8(line).map_err(|_| {
            log::warn!("Incoming SIP message contained invalid UTF8 in header line");
            Error::FailedToParse
        })?;

        if message_line.is_none() {
            let ctx = ParseCtx::new(&buffer, parser_);

            match MessageLine::parse(ctx)(line) {
                Ok((_, line)) => {
                    message_line = Some(line);
                }
                Err(_) => {
                    log::warn!(
                        "Incoming SIP message contained invalid Request/Status Line: {:?}",
                        line
                    );
                    return Err(Error::FailedToParse);
                }
            }
        } else {
            match Line::parse(&buffer, line).finish() {
                Ok((_, line)) => headers.insert(line.name, line.value),
                Err(e) => {
                    log::error!("Incoming SIP message has malformed header line, {}", e);
                    return Err(Error::FailedToParse);
                }
            }
        }
    }

    let head_end = parser.head_end();

    // look for optional content-length header
    let body = match headers.get_named::<ContentLength>() {
        Ok(len) => {
            if len.0 == 0 {
                Bytes::new()
            } else if buffer.len() >= head_end + len.0 {
                buffer.slice(head_end..head_end + len.0)
            } else {
                log::warn!("Incoming SIP message has an incomplete body");
                return Err(Error::FailedToParse);
            }
        }
        Err(_) => {
            log::trace!("no valid content-length given, guessing body length from udp frame");

            if head_end == buffer.len() {
                Bytes::new()
            } else {
                buffer.slice(head_end..)
            }
        }
    };

    Ok(CompleteItem::Sip {
        line: message_line.ok_or(Error::FailedToParse)?,
        headers,
        body,
        buffer,
    })
}
