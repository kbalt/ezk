use sip_core::transport::udp::Udp;
use sip_core::{Endpoint, Error, Result};
use sip_types::uri::sip::SipUri;
use sip_types::uri::NameAddr;
use sip_types::CodeKind;
use sip_ua::register::Registration;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    let mut builder = Endpoint::builder();

    Udp::spawn(&mut builder, "127.0.0.1:5060").await?;

    let endpoint = builder.build();

    let id: SipUri = "sip:alice@example.com".parse().unwrap();
    let registrar: SipUri = "sip:example.com".parse().unwrap();

    let mut registration = Registration::new(NameAddr::uri(id), registrar.into());

    loop {
        let request = registration.create_register(false);
        let transaction = endpoint.send_request(request, None, None).await?;
        let response = transaction.receive_final().await?;

        match response.line.code.kind() {
            CodeKind::Success => {}
            _ => return Err(Error::new(response.line.code)),
        }

        registration.receive_success_response(response);

        registration.wait_for_expiry().await;
    }
}
