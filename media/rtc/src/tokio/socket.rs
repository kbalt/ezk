use quinn_udp::{RecvMeta, Transmit, UdpSockRef, UdpSocketState};
use std::{
    collections::VecDeque,
    io::{self, IoSliceMut},
    net::{IpAddr, SocketAddr},
    task::{Context, Poll, ready},
};
use tokio::{io::Interest, net::UdpSocket};

const QUEUE_MAX_SIZE: usize = 200;

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

                    self.state.send(
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

                // Only return WouldBlock
                if result.is_ok() {
                    self.to_send.pop_front();
                    continue 'outer;
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
