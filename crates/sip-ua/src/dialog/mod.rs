use crate::dialog::layer::DialogEntry;
use crate::util::random_sequence_number;
use bytesstr::BytesStr;
use sip_core::transport::OutgoingResponse;
use sip_core::{Endpoint, IncomingRequest, LayerKey, Request, Result};
use sip_types::header::typed::{CSeq, CallID, Contact, From, RecordRoute, To};
use sip_types::{Code, Method};

mod key;
mod layer;

pub use key::DialogKey;
pub use layer::{register_usage, DialogLayer, Usage, UsageGuard};

#[derive(Debug)]
pub struct Dialog {
    pub endpoint: Endpoint,

    dialog_layer: LayerKey<DialogLayer>,

    /// Local CSeq number, increments with every request constructed using this dialog
    pub local_cseq: u32,

    /// Remote CSeq number as seen in first request
    pub peer_cseq: u32,

    /// From header used to construct requests inside the dialog
    ///
    /// All dialog code assumes that the tag is some
    pub from: From,

    /// To header used to construct requests inside the dialog
    ///
    /// Tag may be `None` to provide backwards compatibility
    pub to: To,

    /// Local Contact header, used to construct requests inside the dialog
    pub local_contact: Contact,

    /// Remote Contact header, used to construct requests inside the dialog
    /// as its the target URI.
    pub peer_contact: Contact,

    /// CallID of the Dialog which is part of the dialog key
    pub call_id: CallID,

    /// Dialog's Route set, must be set with every request
    pub route_set: Vec<RecordRoute>,

    /// Was a secure transport used to construct this dialog
    /// Requires all future requests to also use secure transports
    // TODO use this
    pub secure: bool,
}

impl Dialog {
    /// Create a dialog from an incoming request (may be early)
    #[allow(clippy::too_many_arguments)]
    pub fn new_server(
        endpoint: Endpoint,
        dialog_layer: LayerKey<DialogLayer>,
        peer_cseq: u32,
        from: From,
        to: To,
        local_contact: Contact,
        peer_contact: Contact,
        call_id: CallID,
        route_set: Vec<RecordRoute>,
        secure: bool,
    ) -> Self {
        assert!(to.tag.is_some());

        let dialog = Self {
            endpoint,
            dialog_layer,
            local_cseq: random_sequence_number(),
            peer_cseq,

            // On server dialogs the from/to headers are reversed
            // since they are taken from an incoming request
            from: From(to.0),
            to: To(from.0),
            local_contact,
            peer_contact,
            call_id,
            route_set,
            secure,
        };

        let entry = DialogEntry::new(dialog.peer_cseq);

        dialog.endpoint[dialog_layer]
            .dialogs
            .lock()
            .insert(dialog.key(), entry);

        dialog
    }

    /// Create a key that the dialog can be identified with
    pub fn key(&self) -> DialogKey {
        DialogKey {
            call_id: self.call_id.0.clone(),
            peer_tag: self.to.tag.clone(),
            local_tag: self.from.tag.clone().unwrap(),
        }
    }

    pub fn create_request(&mut self, method: Method) -> Request {
        let mut request = Request::new(method.clone(), self.peer_contact.uri.uri.clone());

        let cseq = CSeq::new(self.local_cseq, method);
        self.local_cseq += 1;

        request.headers.insert_type(&self.from);
        request.headers.insert_type(&self.to);
        request.headers.insert_type(&self.call_id);
        request.headers.insert_type(&cseq);
        request.headers.insert_type(&self.route_set);

        request
    }

    pub async fn create_response(
        &self,
        request: &IncomingRequest,
        code: Code,
        reason: Option<BytesStr>,
    ) -> Result<OutgoingResponse> {
        let mut response = self.endpoint.create_response(request, code, reason).await?;

        if code == Code::TRYING {
            // remove tag from 100 response
            response.msg.headers.edit(|to: &mut To| to.tag = None)?;
        }

        if request.line.method == Method::INVITE {
            let code = code.into_u16();

            if let 101..=399 | 485 = code {
                if !response.msg.headers.contains::<Contact>() {
                    response.msg.headers.insert_type(&self.local_contact);
                }
            }

            if let 180..=189 | 200..=299 | 405 = code {
                response.msg.headers.insert_type(self.endpoint.allowed());
            }

            if let 200..=299 = code {
                response.msg.headers.insert_type(self.endpoint.supported());
            }
        }

        Ok(response)
    }
}

impl Drop for Dialog {
    fn drop(&mut self) {
        self.endpoint[self.dialog_layer]
            .dialogs
            .lock()
            .remove(&self.key());
    }
}
