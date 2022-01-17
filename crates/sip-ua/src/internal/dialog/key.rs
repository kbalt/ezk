use bytesstr::BytesStr;
use sip_core::IncomingRequest;

#[derive(Debug, Clone, Ord, PartialOrd, Eq, PartialEq, Hash)]
pub struct DialogKey {
    pub call_id: BytesStr,
    pub peer_tag: Option<BytesStr>,
    pub local_tag: BytesStr,
}

impl DialogKey {
    pub(crate) fn from_incoming(request: &IncomingRequest) -> Option<Self> {
        let base_headers = &request.base_headers;
        Some(Self {
            call_id: base_headers.call_id.0.clone_detach(),
            peer_tag: base_headers.from.tag.as_ref().map(|tag| tag.clone_detach()),
            local_tag: base_headers.to.tag.as_ref()?.clone_detach(),
        })
    }
}
