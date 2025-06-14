use hickory_resolver::ResolveError;
use hickory_resolver::proto::rr::rdata::{NAPTR, SRV};
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::{Name, TokioResolver};
use multimap::MultiMap;
use std::io;
use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Copy)]
pub(super) struct ServerEntry {
    pub(super) address: SocketAddr,
    pub(super) transport: Option<Transport>,
}

impl<S> From<S> for ServerEntry
where
    SocketAddr: From<S>,
{
    fn from(address: S) -> Self {
        Self {
            address: SocketAddr::from(address),
            transport: None,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub(super) enum Transport {
    /// SIP+D2U
    Udp,
    /// SIP+D2T
    Tcp,
    /// SIPS+D2T
    TlsOverTcp,
    /// SIP+D2S
    Sctp,
}

impl Transport {
    pub(super) fn as_str(&self) -> &'static str {
        match self {
            Transport::Udp => "UDP",
            Transport::Tcp => "TCP",
            Transport::TlsOverTcp => "TLS",
            Transport::Sctp => "SCTP",
        }
    }

    fn from_services(services: &[u8]) -> Option<Self> {
        match services {
            b"SIP+D2U" => Some(Self::Udp),
            b"SIP+D2T" => Some(Self::Tcp),
            b"SIPS+D2T" => Some(Self::TlsOverTcp),
            b"SIP+D2S" => Some(Self::Sctp),
            _ => None,
        }
    }

    fn default_port(&self) -> u16 {
        match self {
            Transport::Udp => 5060,
            Transport::Tcp => 5060,
            Transport::TlsOverTcp => 5061,
            Transport::Sctp => 5060,
        }
    }
}

#[tracing::instrument(err, skip(dns_resolver, uri_port))]
pub(super) async fn resolve_host(
    dns_resolver: &TokioResolver,
    name: &str,
    uri_port: u16,
) -> io::Result<Vec<ServerEntry>> {
    log::debug!("Resolving hostname {:?}", name);

    let name = Name::from_utf8(name)?;

    let mut entries: Vec<ServerEntry> = vec![];

    // First find NAPTR DNS records
    resolve_naptr_records(dns_resolver, name.clone(), &mut entries).await?;

    // If there are none, look for SRV entries directly
    if entries.is_empty() {
        use Transport::*;

        // Try all transports this library should support
        let records = [
            (Name::from_utf8(format!("_sips._tcp.{name}"))?, TlsOverTcp),
            (Name::from_utf8(format!("_sip._udp.{name}"))?, Udp),
            (Name::from_utf8(format!("_sip._tcp.{name}"))?, Tcp),
        ];

        for (name, transport) in records {
            resolve_srv_records(dns_resolver, name, Some(transport), &mut entries).await?;
        }
    }

    // Neither NAPTR nor SRV entries exist - just resolve A/AAAA records
    if entries.is_empty() {
        resolve_a_records(dns_resolver, name.clone(), None, uri_port, &mut entries).await?;
    }

    if entries.is_empty() {
        return Err(io::Error::other(format!(
            "No DNS records for host '{name}' found"
        )));
    }

    Ok(entries)
}

async fn resolve_naptr_records(
    dns_resolver: &TokioResolver,
    name: Name,
    entries: &mut Vec<ServerEntry>,
) -> Result<(), ResolveError> {
    log::debug!("Resolving NAPTR records for \"{name}\"");

    // Fetch records
    let Some(lookup) =
        filter_no_records(dns_resolver.lookup(name.clone(), RecordType::NAPTR).await)?
    else {
        log::debug!("No NAPTR records exist for \"{name}\"");
        return Ok(());
    };

    // Order records by 'order' field
    let mut naptr_records: Vec<&NAPTR> = lookup
        .record_iter()
        .filter_map(|record| match record.data() {
            RData::NAPTR(naptr) => Some(naptr),
            record_data => {
                log::warn!("Got unexpected DNS record from NAPTR request, {record_data:?}");
                None
            }
        })
        .collect();
    naptr_records.sort_unstable_by_key(|naptr| naptr.order());

    log::debug!("Got {} NAPTR records for \"{name}\"", naptr_records.len());

    // Go through all NAPTR records and resolve them recursivly into `ServerEntry`s
    for record in naptr_records {
        let Some(transport) = Transport::from_services(record.services()) else {
            log::warn!(
                "Got unknown services field '{}' in NAPTR record",
                String::from_utf8_lossy(record.services())
            );

            continue;
        };

        match record.flags() {
            b"s" => {
                resolve_srv_records(
                    dns_resolver,
                    record.replacement().clone(),
                    Some(transport),
                    entries,
                )
                .await?
            }
            b"a" => {
                resolve_a_records(
                    dns_resolver,
                    record.replacement().clone(),
                    Some(transport),
                    transport.default_port(),
                    entries,
                )
                .await?;
            }
            b"u" => {
                log::warn!("Got NAPTR record with unimplemented flag \"u\", skipping...");
                continue;
            }
            b"p" => {
                log::warn!("Got NAPTR record with unimplemented flag \"p\", skipping...");
                continue;
            }
            flags => {
                log::warn!("Got NAPTR record with unknown flag \"{flags:X?}\", skipping...");
                continue;
            }
        }
    }

    Ok(())
}

async fn resolve_srv_records(
    dns_resolver: &TokioResolver,
    name: Name,
    transport: Option<Transport>,
    entries: &mut Vec<ServerEntry>,
) -> Result<(), ResolveError> {
    log::debug!("Resolving SRV records for \"{name}\"");

    let Some(lookup) = filter_no_records(dns_resolver.lookup(name.clone(), RecordType::SRV).await)?
    else {
        log::debug!("No SRV records exist for \"{name}\"");
        return Ok(());
    };

    // Order SRV records by priority
    let mut srv_records: Vec<&SRV> = lookup
        .record_iter()
        .filter_map(|record| match record.data() {
            RData::SRV(srv) => Some(srv),
            _ => None,
        })
        .collect();
    srv_records.sort_unstable_by_key(|srv| srv.priority());

    log::debug!("Got {} SRV records for \"{name}\"", srv_records.len());

    // Often we also get some A/AAAA records for the highest priority, so map them
    let ip_records: MultiMap<&Name, IpAddr> = lookup
        .record_iter()
        .filter_map(|record| match record.data() {
            RData::A(a) => Some((record.name(), IpAddr::from(a.0))),
            RData::AAAA(aaaa) => Some((record.name(), IpAddr::from(aaaa.0))),
            _ => None,
        })
        .collect();

    for record in srv_records {
        let target = record.target();
        let port = record.port();

        if let Some(ips) = ip_records.get_vec(target) {
            entries.extend(ips.iter().map(|ip| ServerEntry {
                address: SocketAddr::new(*ip, port),
                transport,
            }));
        } else {
            resolve_a_records(dns_resolver, target.clone(), transport, port, entries).await?;
        };
    }

    Ok(())
}

async fn resolve_a_records(
    dns_resolver: &TokioResolver,
    name: Name,
    transport: Option<Transport>,
    port: u16,
    entries: &mut Vec<ServerEntry>,
) -> Result<(), ResolveError> {
    log::debug!("Resolving A/AAAA records for \"{name}\"");

    let Some(lookup) = filter_no_records(dns_resolver.lookup_ip(name.clone()).await)? else {
        log::debug!("No A/AAAA records exist for \"{name}\"");
        return Ok(());
    };

    log::debug!(
        "Got {} A/AAAA records for \"{name}\"",
        lookup.as_lookup().records().len()
    );

    entries.extend(lookup.iter().map(|ip| ServerEntry {
        address: SocketAddr::new(ip, port),
        transport,
    }));

    Ok(())
}

/// Filter out errors where no records for a given name weren't found and instead return an Ok(None)
fn filter_no_records<T>(e: Result<T, ResolveError>) -> Result<Option<T>, ResolveError> {
    match e {
        Ok(t) => Ok(Some(t)),
        Err(e) if e.proto().is_some_and(|p| p.is_no_records_found()) => Ok(None),
        Err(e) => Err(e),
    }
}
