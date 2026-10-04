use quinn_udp::{RecvMeta, Transmit, UdpSockRef, UdpSocketState};
use socket2::{Domain, Protocol, Type};
use std::{
    collections::VecDeque,
    io::{self, ErrorKind, IoSliceMut},
    iter::once,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    task::{Context, Poll, ready},
};
use tokio::{io::Interest, net::UdpSocket};

const QUEUE_MAX_SIZE: usize = 200;
const BIND_ATTEMPTS: usize = 5;

pub(super) struct ComponentSockets {
    pub(super) v4: Socket,
    pub(super) v6: Option<Socket>,
}

impl ComponentSockets {
    pub(super) async fn bind(ipv6: bool) -> io::Result<ComponentSockets> {
        if ipv6 {
            ComponentSockets::bind_ipv6().await
        } else {
            Ok(ComponentSockets {
                v4: Socket::new(UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?)?,
                v6: None,
            })
        }
    }

    async fn bind_ipv6() -> io::Result<Self> {
        let mut attempts = 0;

        loop {
            attempts += 1;

            let v4 = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;

            let port = v4.local_addr()?.port();

            match bind_ipv6_only(port) {
                Ok(v6) => {
                    return Ok(Self {
                        v4: Socket::new(v4)?,
                        v6: Some(Socket::new(v6)?),
                    });
                }
                Err(e) if e.kind() == ErrorKind::AddrInUse && attempts < BIND_ATTEMPTS => {
                    // port is in use
                }
                Err(e) => {
                    log::warn!("Failed to bind IPv6 socket to port {port}, using IPv4 only: {e}");

                    return Ok(Self {
                        v4: Socket::new(v4)?,
                        v6: None,
                    });
                }
            }
        }
    }

    pub(super) fn port(&self) -> u16 {
        self.v4.local_addr().port()
    }

    pub(super) fn for_target(&mut self, target: SocketAddr) -> Option<&mut Socket> {
        if target.is_ipv4() {
            Some(&mut self.v4)
        } else {
            self.v6.as_mut()
        }
    }

    pub(super) fn iter(&self) -> impl Iterator<Item = &Socket> {
        once(&self.v4).chain(self.v6.as_ref())
    }

    pub(super) fn iter_mut(&mut self) -> impl Iterator<Item = &mut Socket> {
        once(&mut self.v4).chain(self.v6.as_mut())
    }
}

fn bind_ipv6_only(port: u16) -> io::Result<UdpSocket> {
    let socket = socket2::Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;

    // Not dual-stack, since IPv4 uses its own socket on the same port
    socket.set_only_v6(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;

    UdpSocket::from_std(socket.into())
}

pub(super) struct Socket {
    state: UdpSocketState,
    socket: UdpSocket,
    local_addr: SocketAddr,
    to_send: VecDeque<(Vec<u8>, Option<IpAddr>, SocketAddr)>,
}

impl Socket {
    pub(super) fn new(socket: UdpSocket) -> io::Result<Self> {
        let local_addr = socket.local_addr()?;

        Ok(Self {
            state: UdpSocketState::new((&socket).into())?,
            socket,
            local_addr,
            to_send: VecDeque::new(),
        })
    }

    pub(super) fn queue_is_full(&self) -> bool {
        self.to_send.len() >= QUEUE_MAX_SIZE
    }

    pub(super) fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub(super) fn enqueue(&mut self, data: Vec<u8>, source: Option<IpAddr>, target: SocketAddr) {
        self.to_send.push_back((data, source, target));
    }

    pub(super) fn send_pending(&mut self, cx: &mut Context<'_>) {
        'outer: while let Some((data, source, destination)) = self.to_send.front() {
            // Loop makes sure that the waker is registered with the runtime,
            // if poll_send_ready returns Ready but send returns WouldBlock
            loop {
                if self.socket.poll_send_ready(cx).is_pending() {
                    return;
                }

                let result = self.socket.try_io(Interest::WRITABLE, || {
                    let udp_ref = UdpSockRef::from(&self.socket);

                    self.state.try_send(
                        udp_ref,
                        &Transmit {
                            destination: *destination,
                            ecn: None,
                            contents: data,
                            segment_size: None,
                            src_ip: *source,
                        },
                    )
                });

                match result {
                    Err(err) if err.kind() == ErrorKind::WouldBlock => {}
                    Ok(_) => {
                        self.to_send.pop_front();
                        continue 'outer;
                    }
                    Err(err) => {
                        log::debug!("Failed to send UDP packet, {err}");
                        self.to_send.pop_front();
                        continue 'outer;
                    }
                }
            }
        }
    }

    pub(super) fn poll_recv_from(
        &mut self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>; super::BATCH_SIZE],
        addrs: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        // Loop makes sure that the waker is registered with the runtime,
        // if poll_recv_ready returns 'Ready', but then recv returns WouldBlock
        loop {
            ready!(self.socket.poll_recv_ready(cx))?;

            let res = self.socket.try_io(Interest::READABLE, || {
                let udp_ref = UdpSockRef::from(&self.socket);

                self.state.recv(udp_ref, bufs, addrs)
            });

            if let Ok(v) = res {
                return Poll::Ready(Ok(v));
            }
        }
    }
}
