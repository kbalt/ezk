use std::io;
use std::net::SocketAddr;
use tokio::net::lookup_host;

/// Resolver trait used by the `Endpoint` to resolve a hostname to `Vec<SocketAddr>`
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
    async fn resolve(&self, name: &str, port: u16) -> io::Result<Vec<SocketAddr>>;
}

/// Resolves hostname using the systems DNS resolver
///
/// This resolver is the default one used by the endpoint. Covers most use cases.
pub struct SystemResolver;

#[async_trait::async_trait]
impl Resolver for SystemResolver {
    async fn resolve(&self, name: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
        lookup_host((name, port)).await.map(|iter| iter.collect())
    }
}
