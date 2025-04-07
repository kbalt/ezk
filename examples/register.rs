use sip_core::transport::tcp::TcpConnector;
use sip_core::transport::udp::Udp;
use sip_core::transport::TargetTransportInfo;
use sip_core::{Endpoint, Result};
use sip_types::header::typed::Contact;
use sip_types::uri::NameAddr;
use sip_types::uri::SipUri;
use sip_types::CodeKind;
use sip_ua::register::Registration;
use std::sync::Arc;
use std::time::Duration;
use tokio_native_tls::{native_tls::TlsConnector as NativeTlsConnector, TlsConnector};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Create the endpoint
    let mut builder = Endpoint::builder();

    // Add a IPv4 UDP Socket
    Udp::spawn(&mut builder, "0.0.0.0:5060").await?;

    // Add a TCP connector
    builder.add_transport_factory(Arc::new(TcpConnector::default()));

    // Add a TLS connector using (tokio-)native-tls
    builder.add_transport_factory(Arc::new(TlsConnector::from(
        NativeTlsConnector::new().unwrap(),
    )));

    let endpoint = builder.build();

    let id: SipUri = "sip:alice@example.com".parse().unwrap();
    let contact: SipUri = "sip:alice@192.168.178.2:5060".parse().unwrap();
    let registrar: SipUri = "sip:example.com".parse().unwrap();

    let mut target = TargetTransportInfo::default();
    let mut registration = Registration::new(
        NameAddr::uri(id),
        Contact::new(NameAddr::uri(contact)),
        registrar,
        Duration::from_secs(600),
    );

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
