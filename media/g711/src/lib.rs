pub mod alaw;
pub mod mulaw;

/// Split the encoded G.711 into RTP payloads
pub fn packetize(g711_data: &[u8], mtu: usize) -> impl Iterator<Item = &[u8]> {
    g711_data.chunks(mtu)
}
