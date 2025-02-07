use futures_util::ready;
use quinn_udp::{RecvMeta, Transmit, UdpSockRef, UdpSocketState};
use std::{
    collections::VecDeque,
    io::{self, IoSliceMut},
    net::{IpAddr, SocketAddr},
    task::{Context, Poll},
};
use tokio::{
    io::{Interest, ReadBuf},
    net::UdpSocket,
};

pub(crate) struct Socket {
    state: UdpSocketState,
    socket: UdpSocket,
    local_addr: SocketAddr,
    to_send: VecDeque<(Vec<u8>, Option<IpAddr>, SocketAddr)>,
}

impl Socket {
    pub(crate) fn new(socket: UdpSocket) -> Self {
        let local_addr = socket.local_addr().unwrap();
        Self {
            state: UdpSocketState::new((&socket).into()).unwrap(),
            socket,
            local_addr,
            to_send: VecDeque::new(),
        }
    }

    pub(crate) fn enqueue(&mut self, data: Vec<u8>, source: Option<IpAddr>, target: SocketAddr) {
        self.to_send.push_back((data, source, target));

        if self.to_send.len() > 100 {
            self.to_send.pop_front();

            log::warn!("to_send queue too large, dropping oldest packet");
        }
    }

    pub(crate) fn send_pending(&mut self, cx: &mut Context<'_>) {
        'outer: while let Some((data, source, target)) = self.to_send.front() {
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
                            destination: *target,
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

    pub(crate) fn poll_recv_from(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<(SocketAddr, SocketAddr)>> {
        // Loop makes sure that the waker is registered with the runtime,
        // if poll_recv_ready returns Ready but recv returns WouldBlock
        loop {
            ready!(self.socket.poll_recv_ready(cx))?;

            let res = self.socket.try_io(Interest::READABLE, || {
                let udp_ref = UdpSockRef::from(&self.socket);
                let mut bufs = [IoSliceMut::new(buf.initialize_unfilled())];
                let mut meta = [RecvMeta::default()];

                self.state.recv(udp_ref, &mut bufs, &mut meta)?;

                buf.set_filled(meta[0].len);

                Ok((
                    meta[0]
                        .dst_ip
                        .map(|ip| SocketAddr::new(ip, self.local_addr.port()))
                        .unwrap_or(self.local_addr),
                    meta[0].addr,
                ))
            });

            if let Ok(v) = res {
                return Poll::Ready(Ok(v));
            }
        }
    }
}
