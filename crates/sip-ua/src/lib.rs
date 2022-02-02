//! A high level SIP User Agent library
//!

use internal::dialog::DialogLayer;
use internal::invite::InviteLayer;
use layer::UserAgentLayer;
use sip_core::transport::streaming::generalized::StreamingTransport;
use sip_core::transport::streaming::tcp::Tcp;
use sip_core::transport::udp::Udp;
use sip_core::{Endpoint, EndpointBuilder, LayerKey};
use std::io;
use tokio::net::ToSocketAddrs;

pub mod account;
mod auth;
mod call;
pub mod internal;
mod layer;
mod media;

#[derive(Clone)]
pub struct UserAgent {
    endpoint: Endpoint,

    runtime: tokio::runtime::Handle,

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

#[derive(Default)]
pub struct UserAgentBuilder {
    endpoint_builder: EndpointBuilder,

    dialog_layer: Option<LayerKey<DialogLayer>>,
    invite_layer: Option<LayerKey<InviteLayer>>,
    ua_layer: Option<LayerKey<UserAgentLayer>>,
}

impl UserAgentBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn endpoint_builder(&mut self) -> &mut EndpointBuilder {
        &mut self.endpoint_builder
    }

    pub async fn with_udp_transport<A>(mut self, addr: A) -> io::Result<Self>
    where
        A: ToSocketAddrs + Send,
    {
        self.bind_udp_transport(addr).await.map(|_| self)
    }

    pub async fn with_tcp_transport<A>(mut self, addr: A) -> io::Result<Self>
    where
        A: ToSocketAddrs + Send,
    {
        self.bind_tcp_transport(addr).await.map(|_| self)
    }

    pub async fn bind_udp_transport<A>(&mut self, addr: A) -> io::Result<()>
    where
        A: ToSocketAddrs,
    {
        Udp::spawn(&mut self.endpoint_builder, addr).await.map(drop)
    }

    pub async fn bind_tcp_transport<A>(&mut self, addr: A) -> io::Result<()>
    where
        A: ToSocketAddrs + Send,
    {
        Tcp.spawn(&mut self.endpoint_builder, addr).await
    }

    pub fn add_dialog_layer(&mut self) {
        self.dialog_layer = Some(self.endpoint_builder.add_layer(DialogLayer::default()));
    }

    pub fn add_invite_layer(&mut self) {
        assert!(self.dialog_layer.is_some());

        self.invite_layer = Some(self.endpoint_builder.add_layer(InviteLayer::default()));
    }

    pub fn add_ua_layer(&mut self) {
        assert!(self.dialog_layer.is_some());
        assert!(self.invite_layer.is_some());

        self.ua_layer = Some(self.endpoint_builder.add_layer(UserAgentLayer::default()));
    }

    pub async fn build(mut self) -> UserAgent {
        if self.dialog_layer.is_none() {
            self.add_dialog_layer();
        }

        if self.invite_layer.is_none() {
            self.add_invite_layer();
        }

        if self.ua_layer.is_none() {
            self.add_ua_layer();
        }

        let endpoint = self.endpoint_builder.build();

        UserAgent {
            endpoint,
            runtime: tokio::runtime::Handle::current(),
            dialog_layer: self.dialog_layer.unwrap(),
            invite_layer: self.invite_layer.unwrap(),
            ua_layer: self.ua_layer.unwrap(),
        }
    }
}
