//! A high level SIP User Agent library
//!

use internal::dialog::DialogLayer;
use internal::invite::InviteLayer;
use layer::UserAgentLayer;
use sip_core::transport::streaming::generalized::StreamingTransport;
use sip_core::transport::streaming::tcp::Tcp;
use sip_core::transport::udp::Udp;
use sip_core::{Endpoint, LayerKey};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

pub mod account;
mod account2;
mod auth;
// mod call;
pub mod internal;
mod layer;

#[derive(Clone)]
pub struct UserAgent {
    endpoint: Endpoint,

    dialog_layer: LayerKey<DialogLayer>,
    invite_layer: LayerKey<InviteLayer>,
    ua_layer: LayerKey<UserAgentLayer>,
}

impl UserAgent {
    /// Construct a new [`UserAgentBuilder`]
    pub fn builder() -> UserAgentBuilder {
        UserAgentBuilder::new()
    }
}

pub struct UserAgentBuilder {
    transports: Vec<TransportConfig>,
}

impl UserAgentBuilder {
    pub fn new() -> Self {
        Self {
            transports: vec![
                #[cfg(target_os = "windows")]
                TransportConfig::Udp(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
                #[cfg(target_os = "windows")]
                TransportConfig::Tcp(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)),
                TransportConfig::Udp(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)),
                TransportConfig::Tcp(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)),
            ],
        }
    }

    pub async fn build(self) -> Result<UserAgent, io::Error> {
        let mut endpoint = Endpoint::builder();

        let dialog_layer = endpoint.add_layer(DialogLayer::default());
        let invite_layer = endpoint.add_layer(InviteLayer::default());
        let ua_layer = endpoint.add_layer(UserAgentLayer::default());

        for cfg in self.transports {
            match cfg {
                TransportConfig::Udp(addr) => {
                    Udp::spawn(&mut endpoint, addr).await?;
                }
                TransportConfig::Tcp(addr) => {
                    Tcp.spawn(&mut endpoint, addr).await?;
                }
            }
        }

        let endpoint = endpoint.build();

        Ok(UserAgent {
            endpoint,
            dialog_layer,
            invite_layer,
            ua_layer,
        })
    }
}

enum TransportConfig {
    Udp(SocketAddr),
    Tcp(SocketAddr),
}
