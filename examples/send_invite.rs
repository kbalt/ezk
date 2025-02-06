use sip_auth::{ClientAuthenticator, DigestAuthenticator, DigestCredentials, DigestUser};
use sip_core::transport::udp::Udp;
use sip_core::{Endpoint, Result};
use sip_types::header::typed::Contact;
use sip_types::uri::NameAddr;
use sip_ua::dialog::DialogLayer;
use sip_ua::invite::InviteLayer;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let mut builder = Endpoint::builder();

    builder.add_layer(DialogLayer::default());
    builder.add_layer(InviteLayer::default());

    Udp::spawn(&mut builder, "0.0.0.0:5070").await?;

    // Build endpoint to start the SIP Stack
    let endpoint = builder.build();

    let local_uri = endpoint.parse_uri("sip:127.0.0.1").unwrap();
    let target = endpoint.parse_uri("sip:127.0.0.1").unwrap();

    let mut initiator = sip_ua::invite::initiator::InviteInitiator::new(
        endpoint,
        NameAddr::uri(local_uri.clone()),
        Contact::new(NameAddr::uri(local_uri)),
        target,
    );

    let mut credentials = DigestCredentials::new();
    credentials.set_default(DigestUser::new("6001", "6001"));

    let mut authenticator = DigestAuthenticator::new(credentials);

    loop {
        let mut invite = initiator.create_invite();

        authenticator.authorize_request(&mut invite.headers);

        initiator.send_invite(invite).await?;

        loop {
            match initiator.receive().await.unwrap() {
                sip_ua::invite::initiator::Response::Provisional(_) => todo!(),
                sip_ua::invite::initiator::Response::Failure(response) => {
                    if response.line.code.into_u16() != 401 {
                        return Ok(());
                    }

                    let tsx = initiator.transaction().unwrap();
                    let inv = tsx.request();

                    authenticator
                        .handle_rejection(
                            sip_auth::RequestParts {
                                line: &inv.msg.line,
                                headers: &inv.msg.headers,
                                body: b"",
                            },
                            sip_auth::ResponseParts {
                                line: &response.line,
                                headers: &response.headers,
                                body: &response.body,
                            },
                        )
                        .unwrap();

                    break;
                }
                sip_ua::invite::initiator::Response::Early(..) => {
                    unimplemented!()
                }
                sip_ua::invite::initiator::Response::Session(mut x, _response) => {
                    x.terminate().await.unwrap();
                }
                sip_ua::invite::initiator::Response::EarlyEvent => {}
                sip_ua::invite::initiator::Response::Finished => break,
            }
        }
    }
}
