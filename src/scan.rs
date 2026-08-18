//! The core scanning engine: host discovery, port probing, and enrichment.

use crate::arp::{ArpEntry, arp_table};
use crate::net::cidr_hosts;
use crate::services::{DEFAULT_PORTS, service_for_port};
use crate::vendor::vendor_for_mac;

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpStream};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

/// An open TCP port and its best-guess service name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Port {
    /// The open TCP port number.
    pub port: u16,
    /// The well-known service name for this port, if recognized.
    pub service: Option<String>,
}

/// A single host discovered on the network.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Host {
    /// The host's IPv4 address.
    pub ip: Ipv4Addr,
    /// The hardware address from the ARP cache, if known.
    pub mac: Option<String>,
    /// The resolved hostname, if the system resolver returned one.
    pub hostname: Option<String>,
    /// The hardware vendor inferred from the MAC OUI, if recognized.
    pub vendor: Option<String>,
    /// The open ports found on this host, sorted ascending.
    pub open_ports: Vec<Port>,
}

impl Host {
    /// Case-insensitive substring match across every displayed field: IP, MAC,
    /// hostname, vendor, and each open port's number and service name. An empty
    /// needle matches everything. Used by the CLI `--filter` flag and the TUI
    /// live filter so both search identically.
    #[must_use]
    pub fn matches(&self, needle: &str) -> bool {
        let needle = needle.trim().to_lowercase();
        if needle.is_empty() {
            return true;
        }
        let mut hay = self.ip.to_string();
        for value in [&self.mac, &self.hostname, &self.vendor]
            .into_iter()
            .flatten()
        {
            hay.push(' ');
            hay.push_str(value);
        }
        for port in &self.open_ports {
            hay.push(' ');
            hay.push_str(&port.port.to_string());
            if let Some(service) = &port.service {
                hay.push(' ');
                hay.push_str(service);
            }
        }
        hay.to_lowercase().contains(&needle)
    }
}

/// Parameters controlling a scan.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// The network to scan, in CIDR form (e.g. `192.168.1.0/24`).
    pub cidr: String,
    /// The TCP ports to probe on each address.
    pub ports: Vec<u16>,
    /// Per-connection timeout.
    pub timeout: Duration,
    /// Maximum number of concurrent probes.
    pub concurrency: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            cidr: "192.168.1.0/24".to_string(),
            ports: DEFAULT_PORTS.to_vec(),
            timeout: Duration::from_millis(400),
            concurrency: 256,
        }
    }
}

impl ScanConfig {
    /// Build a config for the given CIDR, keeping all other defaults.
    #[must_use]
    pub fn from_cidr(cidr: impl Into<String>) -> Self {
        Self {
            cidr: cidr.into(),
            ..Self::default()
        }
    }
}

/// Scan the configured network and return the live hosts found.
///
/// A host is considered live if it answers on any probed port **or** is present
/// in the local ARP cache within the scanned range. Every returned host is
/// enriched with ARP data (MAC, hostname) and a vendor guess. Results are
/// sorted by IP address.
///
/// An invalid CIDR yields an empty result rather than panicking; callers that
/// need to surface the error should validate with
/// [`crate::net::cidr_hosts`] first.
#[must_use]
pub fn scan(cfg: &ScanConfig) -> Vec<Host> {
    let addrs = cidr_hosts(&cfg.cidr).unwrap_or_default();
    if addrs.is_empty() {
        return Vec::new();
    }

    let open = probe_all(&addrs, cfg);
    let arp = arp_table();
    let in_range: BTreeSet<Ipv4Addr> = addrs.iter().copied().collect();

    // Union of hosts that answered a probe and hosts with a *resolved* ARP
    // entry in range. Incomplete ARP entries (no MAC) mean the host never
    // replied to an ARP request, so they are not counted as live.
    let mut live: BTreeSet<Ipv4Addr> = open.keys().copied().collect();
    for entry in arp.values() {
        if entry.mac.is_some() && in_range.contains(&entry.ip) {
            live.insert(entry.ip);
        }
    }
    let live: Vec<Ipv4Addr> = live.into_iter().collect();

    // Reverse-DNS the live hosts the ARP cache did not already name. Many home
    // routers publish no PTR records, in which case this simply finds nothing.
    let unnamed: Vec<Ipv4Addr> = live
        .iter()
        .copied()
        .filter(|ip| arp.get(ip).and_then(|e| e.hostname.as_ref()).is_none())
        .collect();
    let resolved = resolve_hostnames(&unnamed, cfg.concurrency);

    live.into_iter()
        .map(|ip| {
            assemble_host(
                ip,
                open.get(&ip).cloned(),
                arp.get(&ip),
                resolved.get(&ip).cloned(),
            )
        })
        .collect()
}

fn assemble_host(
    ip: Ipv4Addr,
    open_ports: Option<Vec<Port>>,
    arp: Option<&ArpEntry>,
    resolved: Option<String>,
) -> Host {
    let mac = arp.and_then(|entry| entry.mac.clone());
    let vendor = mac.as_deref().and_then(vendor_for_mac).map(str::to_string);
    Host {
        ip,
        vendor,
        mac,
        // Prefer the ARP-provided name; fall back to reverse DNS.
        hostname: arp.and_then(|entry| entry.hostname.clone()).or(resolved),
        open_ports: open_ports.unwrap_or_default(),
    }
}

/// Reverse-resolve hostnames for the given IPs concurrently, reusing the same
/// bounded worker model as the port scan so a slow resolver never serializes
/// the whole batch. Addresses with no usable PTR record are omitted.
fn resolve_hostnames(ips: &[Ipv4Addr], concurrency: usize) -> HashMap<Ipv4Addr, String> {
    if ips.is_empty() {
        return HashMap::new();
    }
    let next = AtomicUsize::new(0);
    let found: Mutex<HashMap<Ipv4Addr, String>> = Mutex::new(HashMap::new());
    let workers = concurrency.clamp(1, ips.len());

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&ip) = ips.get(index) else {
                        break;
                    };
                    if let Some(name) = reverse_dns(ip) {
                        found.lock().expect("dns mutex poisoned").insert(ip, name);
                    }
                }
            });
        }
    });

    found.into_inner().expect("dns mutex poisoned")
}

/// Best-effort reverse DNS for one address. `lookup_addr` returns the numeric
/// IP string when there is no PTR record, so that (and the raw arpa form) is
/// filtered out to keep results honest.
fn reverse_dns(ip: Ipv4Addr) -> Option<String> {
    let name = dns_lookup::lookup_addr(&IpAddr::V4(ip)).ok()?;
    if name.is_empty() || name == ip.to_string() || name.ends_with(".in-addr.arpa") {
        None
    } else {
        Some(name)
    }
}

/// Probe every (address, port) pair concurrently, returning the open ports per
/// host. A bounded pool of worker threads pulls from a shared task index, which
/// keeps latency dominated by the slowest single probe rather than the sum.
fn probe_all(addrs: &[Ipv4Addr], cfg: &ScanConfig) -> HashMap<Ipv4Addr, Vec<Port>> {
    let tasks: Vec<(Ipv4Addr, u16)> = addrs
        .iter()
        .flat_map(|&ip| cfg.ports.iter().map(move |&port| (ip, port)))
        .collect();

    if tasks.is_empty() {
        return HashMap::new();
    }

    let next = AtomicUsize::new(0);
    let found: Mutex<HashMap<Ipv4Addr, Vec<u16>>> = Mutex::new(HashMap::new());
    let workers = cfg.concurrency.clamp(1, tasks.len());

    std::thread::scope(|scope| {
        for _ in 0..workers {
            scope.spawn(|| {
                loop {
                    let index = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&(ip, port)) = tasks.get(index) else {
                        break;
                    };
                    if tcp_open(ip, port, cfg.timeout) {
                        found
                            .lock()
                            .expect("probe mutex poisoned")
                            .entry(ip)
                            .or_default()
                            .push(port);
                    }
                }
            });
        }
    });

    found
        .into_inner()
        .expect("probe mutex poisoned")
        .into_iter()
        .map(|(ip, mut ports)| {
            ports.sort_unstable();
            let ports = ports
                .into_iter()
                .map(|port| Port {
                    port,
                    service: service_for_port(port).map(str::to_string),
                })
                .collect();
            (ip, ports)
        })
        .collect()
}

/// Return `true` when a TCP connection to `ip:port` completes within `timeout`.
fn tcp_open(ip: Ipv4Addr, port: u16, timeout: Duration) -> bool {
    let addr = SocketAddr::new(IpAddr::V4(ip), port);
    TcpStream::connect_timeout(&addr, timeout).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;

    #[test]
    fn default_config_is_sane() {
        let cfg = ScanConfig::default();
        assert!(!cfg.ports.is_empty());
        assert!(cfg.concurrency >= 1);
    }

    #[test]
    fn from_cidr_overrides_only_the_network() {
        let cfg = ScanConfig::from_cidr("10.0.0.0/24");
        assert_eq!(cfg.cidr, "10.0.0.0/24");
        assert_eq!(cfg.ports, DEFAULT_PORTS.to_vec());
    }

    #[test]
    fn invalid_cidr_yields_no_hosts() {
        let cfg = ScanConfig::from_cidr("nonsense");
        assert!(scan(&cfg).is_empty());
    }

    #[test]
    fn detects_a_real_open_port_on_loopback() {
        // Bind an ephemeral listener; the kernel completes the handshake from
        // the listen backlog, so the probe succeeds without an accept loop.
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().unwrap().port();
        assert!(tcp_open(
            Ipv4Addr::LOCALHOST,
            port,
            Duration::from_millis(500)
        ));
    }

    #[test]
    fn closed_port_is_not_open() {
        // Port 1 on loopback is essentially never listening in CI/dev.
        assert!(!tcp_open(
            Ipv4Addr::LOCALHOST,
            1,
            Duration::from_millis(100)
        ));
    }

    #[test]
    fn assembles_vendor_from_mac() {
        let arp = ArpEntry {
            ip: Ipv4Addr::new(192, 168, 1, 5),
            mac: Some("B8:27:EB:11:22:33".to_string()),
            hostname: Some("pi.home".to_string()),
        };
        let host = assemble_host(Ipv4Addr::new(192, 168, 1, 5), None, Some(&arp), None);
        assert_eq!(host.vendor.as_deref(), Some("Raspberry Pi"));
        assert_eq!(host.hostname.as_deref(), Some("pi.home"));
        assert!(host.open_ports.is_empty());
    }

    #[test]
    fn reverse_dns_falls_back_when_arp_has_no_name() {
        // No ARP hostname, but reverse DNS resolved one: it should be used.
        let host = assemble_host(
            Ipv4Addr::new(192, 168, 1, 9),
            None,
            None,
            Some("printer.local".to_string()),
        );
        assert_eq!(host.hostname.as_deref(), Some("printer.local"));
    }

    #[test]
    fn filter_matches_across_all_fields() {
        let host = Host {
            ip: Ipv4Addr::new(10, 0, 0, 22),
            mac: Some("DC:E9:94:96:48:DB".to_string()),
            hostname: Some("printer.local".to_string()),
            vendor: Some("Foxconn".to_string()),
            open_ports: vec![Port {
                port: 9100,
                service: Some("printer-raw".to_string()),
            }],
        };
        assert!(host.matches("")); // empty matches everything
        assert!(host.matches("10.0.0.22")); // IP
        assert!(host.matches("dc:e9")); // MAC, case-insensitive
        assert!(host.matches("PRINTER")); // hostname/service, case-insensitive
        assert!(host.matches("foxconn")); // vendor
        assert!(host.matches("9100")); // port number
        assert!(!host.matches("apple")); // no match
    }
}
