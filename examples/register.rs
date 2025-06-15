use sip_auth::{DigestAuthenticator, DigestCredentials, DigestUser};
use sip_core::{transport::udp::Udp, Endpoint};
use sip_ua::{dialog::DialogLayer, invite::InviteLayer, RegistrarConfig, Registration};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let mut builder = Endpoint::builder();

    // Make a UDP transport
    Udp::spawn(&mut builder, "0.0.0.0:5060").await.unwrap();

    // Add Dialog & INVITE capabilities
    builder.add_layer(DialogLayer::default());
    builder.add_layer(InviteLayer::default());

    let endpoint = builder.build();

    // Create credentials for bob
    let mut credentials = DigestCredentials::new();
    credentials.add_for_realm("example.org", DigestUser::new("bob", "hunter2"));

    // Register bob
    let registration = Registration::register(
        endpoint,
        RegistrarConfig::new("bob".into(), "sip:example.org".parse()?),
        DigestAuthenticator::new(credentials.clone()),
    )
    .await?;

    // unregister bob
    drop(registration);

    Ok(())
}
