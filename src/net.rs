//! Local address discovery and CIDR expansion.

use std::net::{Ipv4Addr, UdpSocket};

/// Discover this machine's primary IPv4 address on the LAN.
///
/// Uses the classic "connect a UDP socket to a public address" trick: no
/// packet is actually sent, but the OS picks the outbound interface and its
/// local address becomes visible via [`UdpSocket::local_addr`]. Returns
/// `None` when there is no usable route (for example, no network).
pub fn local_ipv4() -> Option<Ipv4Addr> {
    let socket = UdpSocket::bind("0.0.0.0:0").ok()?;
    // 203.0.113.0/24 is the RFC 5737 documentation range: never routed, safe.
    socket.connect("203.0.113.1:80").ok()?;
    match socket.local_addr().ok()? {
        std::net::SocketAddr::V4(addr) => Some(*addr.ip()),
        std::net::SocketAddr::V6(_) => None,
    }
}

/// Guess the local /24 network in CIDR form, e.g. `192.168.1.0/24`.
///
/// Returns `None` when the local address cannot be determined.
pub fn default_cidr() -> Option<String> {
    let ip = local_ipv4()?;
    let o = ip.octets();
    Some(format!("{}.{}.{}.0/24", o[0], o[1], o[2]))
}

/// Expand a CIDR block such as `192.168.1.0/24` into its usable host addresses.
///
/// Network and broadcast addresses are excluded for prefixes shorter than
/// `/31`. To keep scans bounded, prefixes shorter than `/16` (more than
/// 65 536 addresses) are rejected.
///
/// # Errors
///
/// Returns a human-readable message when the input is not a valid CIDR or is
/// too large to scan.
pub fn cidr_hosts(cidr: &str) -> Result<Vec<Ipv4Addr>, String> {
    let (addr_part, prefix_part) = cidr
        .split_once('/')
        .ok_or_else(|| format!("missing '/prefix' in CIDR: {cidr}"))?;

    let base: Ipv4Addr = addr_part
        .parse()
        .map_err(|_| format!("invalid IPv4 address: {addr_part}"))?;
    let prefix: u32 = prefix_part
        .parse()
        .map_err(|_| format!("invalid prefix: {prefix_part}"))?;

    if prefix > 32 {
        return Err(format!("prefix out of range (0-32): {prefix}"));
    }
    if prefix < 16 {
        return Err(format!(
            "prefix /{prefix} is too large to scan (max 65536 hosts, use /16 or longer)"
        ));
    }

    let base_u32 = u32::from(base);
    let host_bits = 32 - prefix;
    let size: u32 = if host_bits == 32 {
        u32::MAX
    } else {
        1u32 << host_bits
    };
    let network = base_u32 & !(size.wrapping_sub(1));

    let mut hosts = Vec::new();
    match prefix {
        32 => hosts.push(Ipv4Addr::from(network)),
        31 => {
            hosts.push(Ipv4Addr::from(network));
            hosts.push(Ipv4Addr::from(network + 1));
        }
        _ => {
            // Skip the network (first) and broadcast (last) addresses.
            for offset in 1..(size - 1) {
                hosts.push(Ipv4Addr::from(network + offset));
            }
        }
    }
    Ok(hosts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_a_slash_24() {
        let hosts = cidr_hosts("192.168.1.0/24").unwrap();
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(hosts[253], Ipv4Addr::new(192, 168, 1, 254));
    }

    #[test]
    fn normalizes_a_non_network_base() {
        // Base is a host inside the block; expansion should still align.
        let hosts = cidr_hosts("192.168.1.77/24").unwrap();
        assert_eq!(hosts.first().copied(), Some(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(hosts.len(), 254);
    }

    #[test]
    fn expands_a_slash_30() {
        let hosts = cidr_hosts("10.0.0.0/30").unwrap();
        assert_eq!(
            hosts,
            vec![Ipv4Addr::new(10, 0, 0, 1), Ipv4Addr::new(10, 0, 0, 2)]
        );
    }

    #[test]
    fn handles_slash_31_and_32() {
        assert_eq!(cidr_hosts("10.0.0.0/31").unwrap().len(), 2);
        assert_eq!(
            cidr_hosts("10.0.0.5/32").unwrap(),
            vec![Ipv4Addr::new(10, 0, 0, 5)]
        );
    }

    #[test]
    fn rejects_bad_input() {
        assert!(cidr_hosts("not-a-cidr").is_err());
        assert!(cidr_hosts("192.168.1.0/40").is_err());
        assert!(cidr_hosts("192.168.1.0/8").is_err());
        assert!(cidr_hosts("999.1.1.1/24").is_err());
    }
}
