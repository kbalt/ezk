use ezk_ice::{Component, IceAgent, IceConnectionState, IceCredentials, IceEvent, ReceivedPkt};
use std::{cmp::min, mem::take, net::SocketAddr, time::Instant};

fn create_pair() -> (IceAgent, IceAgent) {
    let a = IceCredentials::random();
    let b = IceCredentials::random();

    let a_agent = IceAgent::new_from_answer(a.clone(), b.clone(), true, true);
    let b_agent = IceAgent::new_from_answer(b, a, true, true);

    (a_agent, b_agent)
}

struct Packet {
    data: Vec<u8>,
    source: SocketAddr,
    destination: SocketAddr,
}

// Very simple test to verify that the ice agent at least works with itself
#[test]
fn same_network() {
    env_logger::init();
    let (mut a, mut b) = create_pair();

    for addr in [
        "127.0.0.1",
        "192.168.178.10",
        "10.10.10.10",
        "10.127.10.10",
        "172.17.0.1",
    ] {
        a.add_host_addr(Component::Rtp, format!("{addr}:5555").parse().unwrap());
        b.add_host_addr(Component::Rtp, format!("{addr}:4444").parse().unwrap());
    }

    for c in a.ice_candidates() {
        b.add_remote_candidate(&c);
    }

    for c in b.ice_candidates() {
        a.add_remote_candidate(&c);
    }

    let mut now = Instant::now();

    while a.connection_state() != IceConnectionState::Connected
        && b.connection_state() != IceConnectionState::Connected
    {
        a.poll(now);
        b.poll(now);

        let mut to_a = Vec::new();
        let mut to_b = Vec::new();

        while {
            poll_agent(now, &mut a, 5555, &mut to_b, &mut to_a);
            poll_agent(now, &mut b, 4444, &mut to_a, &mut to_b);

            !to_a.is_empty() || !to_b.is_empty()
        } {}

        now += opt_min(a.timeout(now), b.timeout(now)).unwrap();
    }
}

fn poll_agent(
    now: Instant,
    agent: &mut IceAgent,
    agent_port: u16,
    to_peer: &mut Vec<Packet>,
    from_peer: &mut Vec<Packet>,
) {
    for packet in take(from_peer) {
        agent.receive(
            now,
            ReceivedPkt {
                data: packet.data,
                source: packet.source,
                destination: packet.destination,
                component: Component::Rtp,
            },
        );
    }

    while let Some(event) = agent.pop_event() {
        if let IceEvent::SendData {
            component: _,
            data,
            source,
            target,
        } = event
        {
            to_peer.push(Packet {
                data,
                source: SocketAddr::new(source.unwrap(), agent_port),
                destination: target,
            });
        }
    }
}

fn opt_min<T: Ord>(a: Option<T>, b: Option<T>) -> Option<T> {
    match (a, b) {
        (None, None) => None,
        (None, Some(b)) => Some(b),
        (Some(a), None) => Some(a),
        (Some(a), Some(b)) => Some(min(a, b)),
    }
}
