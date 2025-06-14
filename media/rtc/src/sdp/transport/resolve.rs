use sdp_types::{Connection, MediaDescription, SessionDescription, TaggedAddress};
use std::net::SocketAddr;

/// Errors encountered when trying to extract the remote's IP address from SDP
#[derive(Debug, thiserror::Error)]
pub enum ResolveError {
    #[error("Missing connection attribute")]
    MissingConnectionAttribute,
    #[error("FQDN in connection attribute which is unsupported")]
    FqdnInConnectionAttribute,
}

pub(crate) fn resolve_rtp_and_rtcp_address(
    remote_session_desc: &SessionDescription,
    remote_media_desc: &MediaDescription,
) -> Result<(SocketAddr, SocketAddr), ResolveError> {
    let connection = remote_media_desc
        .connection
        .as_ref()
        .or(remote_session_desc.connection.as_ref())
        .ok_or(ResolveError::MissingConnectionAttribute)?;

    let remote_rtp_address = connection.address.clone();
    let remote_rtp_port = remote_media_desc.media.port;

    let (remote_rtcp_address, remote_rtcp_port) =
        rtcp_address_and_port(remote_media_desc, connection);

    let remote_rtp_address = resolve_tagged_address(&remote_rtp_address, remote_rtp_port)?;
    let remote_rtcp_address = resolve_tagged_address(&remote_rtcp_address, remote_rtcp_port)?;

    Ok((remote_rtp_address, remote_rtcp_address))
}

fn rtcp_address_and_port(
    remote_media_desc: &MediaDescription,
    connection: &Connection,
) -> (TaggedAddress, u16) {
    if remote_media_desc.rtcp_mux {
        return (connection.address.clone(), remote_media_desc.media.port);
    }

    if let Some(rtcp_addr) = &remote_media_desc.rtcp {
        let address = rtcp_addr
            .address
            .clone()
            .unwrap_or_else(|| connection.address.clone());

        return (address, rtcp_addr.port);
    }

    (
        connection.address.clone(),
        remote_media_desc.media.port.saturating_add(1),
    )
}

fn resolve_tagged_address(address: &TaggedAddress, port: u16) -> Result<SocketAddr, ResolveError> {
    match address {
        TaggedAddress::IP4(ipv4_addr) => Ok(SocketAddr::from((*ipv4_addr, port))),
        TaggedAddress::IP4FQDN(..) => Err(ResolveError::FqdnInConnectionAttribute),
        TaggedAddress::IP6(ipv6_addr) => Ok(SocketAddr::from((*ipv6_addr, port))),
        TaggedAddress::IP6FQDN(..) => Err(ResolveError::FqdnInConnectionAttribute),
    }
}
