use crate::{Client, ClientLayer};
use sip_core::transport::{
    streaming::StreamingListenerBuilder,
    tcp::{TcpConnector, TcpListener},
    udp::Udp,
};
use sip_ua::{dialog::DialogLayer, invite::InviteLayer};
use std::{io, mem::take, net::SocketAddr, sync::Arc};

pub struct ClientBuilder {
    endpoint: sip_core::EndpointBuilder,
    listen: Vec<Listen>,
}

enum Listen {
    Udp(SocketAddr),
    Tcp(SocketAddr),
    #[cfg(feature = "tls-native-tls")]
    NativeTls(SocketAddr, tokio_native_tls::TlsAcceptor),
    #[cfg(feature = "tls-rustls")]
    Rustls(SocketAddr, tokio_rustls::TlsAcceptor),
}

impl ClientBuilder {
    pub fn new() -> Self {
        Self {
            endpoint: sip_core::EndpointBuilder::new(),
            listen: Vec::new(),
        }
    }

    pub fn listen_udp(&mut self, addr: SocketAddr) -> &mut Self {
        self.listen.push(Listen::Udp(addr));
        self
    }

    pub fn listen_tcp(&mut self, addr: SocketAddr) -> &mut Self {
        self.listen.push(Listen::Tcp(addr));

        if addr.ip().is_unspecified() {
            self.endpoint
                .add_transport_factory(Arc::new(TcpConnector::new()));
        } else {
            self.endpoint
                .add_transport_factory(Arc::new(TcpConnector::new_with_bind(addr)));
        }

        self
    }

    #[cfg(feature = "tls-native-tls")]
    pub fn listen_native_tls(
        &mut self,
        addr: SocketAddr,
        acceptor: tokio_native_tls::TlsAcceptor,
    ) -> &mut Self {
        self.listen.push(Listen::NativeTls(addr, acceptor));
        self
    }

    #[cfg(feature = "tls-rustls")]
    pub fn listen_rustls(
        &mut self,
        addr: SocketAddr,
        acceptor: tokio_rustls::TlsAcceptor,
    ) -> &mut Self {
        self.listen.push(Listen::Rustls(addr, acceptor));
        self
    }

    #[cfg(feature = "tls-native-tls")]
    pub fn add_native_tls_connector(
        &mut self,
        connector: tokio_native_tls::TlsConnector,
    ) -> &mut Self {
        self.endpoint.add_transport_factory(Arc::new(connector));
        self
    }

    #[cfg(feature = "tls-rustls")]
    pub fn add_rustls_connector(&mut self, connector: tokio_rustls::TlsConnector) -> &mut Self {
        self.endpoint.add_transport_factory(Arc::new(connector));
        self
    }

    pub async fn build(&mut self) -> io::Result<Client> {
        let mut this = take(self);

        for listen in this.listen {
            match listen {
                Listen::Udp(addr) => {
                    Udp::spawn(&mut this.endpoint, addr).await?;
                }
                Listen::Tcp(addr) => {
                    TcpListener::new().spawn(&mut this.endpoint, addr).await?;
                }
                #[cfg(feature = "tls-native-tls")]
                Listen::NativeTls(addr, tls_acceptor) => {
                    tls_acceptor.spawn(&mut this.endpoint, addr).await?;
                }
                #[cfg(feature = "tls-rustls")]
                Listen::Rustls(addr, tls_acceptor) => {
                    tls_acceptor.spawn(&mut this.endpoint, addr).await?;
                }
            }
        }

        this.endpoint.add_layer(DialogLayer::default());
        this.endpoint.add_layer(InviteLayer::default());
        this.endpoint.add_layer(ClientLayer::default());

        Ok(Client {
            endpoint: this.endpoint.build(),
        })
    }
}

impl Default for ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}
