use bytesstr::BytesStr;
use sdp_types::SessionDescription;
use sip_types::header::typed::ContentType;
use std::{error::Error, fmt::Debug, future::Future};

pub(crate) const CONTENT_TYPE_SDP: ContentType =
    ContentType(BytesStr::from_static("application/sdp"));

/// SDP based media backend used by [`Call`](crate::Call), [`OutboundCall`](crate::OutboundCall) and [`InboundCall`](crate::InboundCall)
pub trait MediaBackend {
    type Error: Debug + Error;
    type Event;

    /// Returns if any media is already configured. This information is used to determine if
    /// an SDP offer is sent or requested when sending an INVITE.
    fn has_media(&self) -> bool;

    fn create_sdp_offer(
        &mut self,
    ) -> impl Future<Output = Result<SessionDescription, Self::Error>> + Send;
    fn receive_sdp_answer(
        &mut self,
        sdp: SessionDescription,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;
    fn receive_sdp_offer(
        &mut self,
        sdp: SessionDescription,
    ) -> impl Future<Output = Result<SessionDescription, Self::Error>> + Send;

    /// Run until a media event is received
    fn run(&mut self) -> impl Future<Output = Result<Self::Event, Self::Error>> + Send;
}
