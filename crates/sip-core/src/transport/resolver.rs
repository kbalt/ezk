use crate::{Result, WithStatus};
use sip_types::Code;
use std::net::SocketAddr;
use tokio::net::lookup_host;

/// Resolver trait used by the `Endpoint` to resolve a hostname to `SocketAddr`
// TODO: to support NAPTR this must also be able to specify a transport
#[async_trait::async_trait]
pub trait Resolver: Send + Sync {
    /// Perform DNS resolution for the given `name`.
    ///
    /// Must return an error with the status code `502 BAD GATEWAY`
    /// if no DNS entries exist for the given Name.
    ///
    /// IO Errors when connecting to a DNS server must return the
    /// error with the status code `503 SERVICE UNAVAILABLE`.
    async fn resolve(&self, name: &str) -> Result<Vec<SocketAddr>>;
}

/// Resolves hostname using the systems DNS resolver
///
/// This resolver is the default one used by the endpoint. Covers most use cases.
pub struct SystemResolver;

#[async_trait::async_trait]
impl Resolver for SystemResolver {
    async fn resolve(&self, name: &str) -> Result<Vec<SocketAddr>> {
        Ok(lookup_host(name).await.status(Code::BAD_GATEWAY)?.collect())
    }
}
