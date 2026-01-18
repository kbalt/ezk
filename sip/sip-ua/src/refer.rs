use sip_core::IncomingRequest;
use sip_types::{
    header::{HeaderError, typed::ContentType},
    msg::StatusLine,
    parse::Parse,
};

use crate::subscription::SipEvent;

/// REFER made progress
pub struct ReferEvent {
    /// represents the last response to the INVITE request of the call's peer to the REFER target
    pub status_line: StatusLine,
}

#[derive(Debug, thiserror::Error)]
pub enum ReferEventFromNotifyError {
    #[error("NOTIFY does not contain valid content-type header {0:?}")]
    InvalidContentTypeHeader(HeaderError),
    #[error("NOTIFY does not contain content-type message/sipfrag")]
    InvalidContentType,
    #[error("NOTIFY body contains invalid UTF8")]
    InvalidUTF8,
    #[error("NOTIFY body does not contain valid message/sipfrag content")]
    InvalidContent,
}

impl SipEvent for ReferEvent {
    type Error = ReferEventFromNotifyError;

    fn from_notify(notify: IncomingRequest) -> Result<Self, Self::Error> {
        let content_type = notify
            .headers
            .get_named::<ContentType>()
            .map_err(ReferEventFromNotifyError::InvalidContentTypeHeader)?;

        if !content_type.0.contains("message/sipfrag") {
            return Err(ReferEventFromNotifyError::InvalidContentType);
        }

        let body = std::str::from_utf8(&notify.body)
            .map_err(|_| ReferEventFromNotifyError::InvalidUTF8)?;

        let body = body.lines().next().unwrap_or(body);

        let status_line =
            StatusLine::parse_str(body).map_err(|_| ReferEventFromNotifyError::InvalidContent)?;

        Ok(Self { status_line })
    }
}
