use sip_core::transport::udp::Udp;
use sip_core::{Endpoint, IncomingRequest, Layer, LayerKey, MayTake, Result};
use sip_types::header::typed::Contact;
use sip_types::uri::sip::SipUri;
use sip_types::uri::NameAddr;
use sip_types::{Code, Method};
use sip_ua::dialog::{Dialog, DialogLayer};
use sip_ua::invite::acceptor::Acceptor;
use sip_ua::invite::session::Event;
use sip_ua::invite::InviteLayer;
use std::time::Duration;
use tokio::time::sleep;

/// Custom layer which we use to accept incoming invites
struct InviteAcceptLayer {
    dialog_layer: LayerKey<DialogLayer>,
    invite_layer: LayerKey<InviteLayer>,
}

#[async_trait::async_trait]
impl Layer for InviteAcceptLayer {
    fn name(&self) -> &'static str {
        "invite-accept-layer"
    }

    async fn receive(&self, endpoint: &Endpoint, request: MayTake<'_, IncomingRequest>) {
        let invite = if request.line.method == Method::INVITE {
            request.take()
        } else {
            return;
        };

        let contact: SipUri = "sip:bob@example.com".parse().unwrap();
        let contact = Contact::new(NameAddr::uri(contact));

        let dialog =
            Dialog::new_server(endpoint.clone(), self.dialog_layer, &invite, contact).unwrap();

        let acceptor = Acceptor::new(
            dialog,
            self.invite_layer,
            invite,
            Some(Box::new(|| {
                println!("Call was cancelled");
            })),
        )
        .unwrap();

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        let response = acceptor.create_response(Code::OK, None).await.unwrap();

        // Here goes SDP handling

        let (mut session, _ack) = acceptor.respond_success(response).await.unwrap();

        loop {
            match session.drive().await.unwrap() {
                Event::RefreshNeeded(event) => {
                    event.process_default().await.unwrap();
                }
                Event::ReInviteReceived(event) => {
                    let response = endpoint.create_response(&event.invite, Code::OK, None);

                    event.respond_success(response).await.unwrap();
                }
                Event::Bye(event) => {
                    event.process_default().await.unwrap();
                }
                Event::Terminated => {
                    break;
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let mut builder = Endpoint::builder();

    let dialog_layer = builder.add_layer(DialogLayer::default());
    let invite_layer = builder.add_layer(InviteLayer::default());

    builder.add_layer(InviteAcceptLayer {
        dialog_layer,
        invite_layer,
    });

    Udp::spawn(&mut builder, "127.0.0.1:5060").await?;

    // Build endpoint to start the SIP Stack
    let _endpoint = builder.build();

    // Busy sleep loop
    loop {
        sleep(Duration::from_secs(1)).await;
    }
}
