use anyhow::Result;
use sip_auth::digest::DigestCredentials;
use sip_types::uri::sip::SipUri;
use sip_ua::account::AccountConfig;
use sip_ua::UserAgent;
use std::str::FromStr;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();

    // Build the user agent
    let user_agent = UserAgent::builder()
        .with_udp_transport("0.0.0.0:5060")
        .await?
        .build()
        .await;

    // Build account config and add some credentials
    let mut config = AccountConfig::new("alice".into(), SipUri::from_str("sip:example.org")?);
    config
        .credentials
        .add_for_realm("example.org", DigestCredentials::new("alice", "password2"));

    // Create account using the config
    let account_id = user_agent.create_account(config);

    // Try to register the account at the specified registrar
    user_agent.register(account_id).await?;

    // Wait for CTRL-C/SIGINT
    tokio::signal::ctrl_c().await?;

    // Unregister and quit
    user_agent.unregister(account_id).await?;

    Ok(())
}
