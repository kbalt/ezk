use sip_core::transport::udp::Udp;
use sip_core::transport::TargetTransportInfo;
use sip_core::{Endpoint, Result};
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

    let mut target = TargetTransportInfo::default();
    let mut registration = Registration::new(NameAddr::uri(id), registrar.into());

    loop {
        let request = registration.create_register(false);
        let mut transaction = endpoint.send_request(request, &mut target).await?;
        let response = transaction.receive_final().await?;

        match response.line.code.kind() {
            CodeKind::Success => {}
            _ => panic!("registration failed!"),
        }

        registration.receive_success_response(response);

        registration.wait_for_expiry().await;
    }
}
