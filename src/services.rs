//! Well-known TCP port to service-name mapping and the default scan set.

/// The default set of TCP ports probed during host discovery.
///
/// Chosen to cover the services most likely to be running on home-network
/// devices (routers, NAS boxes, printers, media servers, laptops) so that a
/// live host answers on at least one of them.
pub const DEFAULT_PORTS: &[u16] = &[
    22,    // SSH
    53,    // DNS
    80,    // HTTP
    139,   // NetBIOS
    443,   // HTTPS
    445,   // SMB
    515,   // Printer (LPD)
    548,   // AFP
    631,   // IPP (printing)
    3000,  // Dev servers
    3389,  // RDP
    5000,  // UPnP / dev servers
    5353,  // mDNS
    8000,  // HTTP-alt
    8080,  // HTTP-alt
    8443,  // HTTPS-alt
    9100,  // Printer (raw)
    32400, // Plex
];

/// Return the common service name for a well-known port, if known.
#[must_use]
pub fn service_for_port(port: u16) -> Option<&'static str> {
    let name = match port {
        20 | 21 => "ftp",
        22 => "ssh",
        23 => "telnet",
        25 => "smtp",
        53 => "dns",
        67 | 68 => "dhcp",
        80 => "http",
        110 => "pop3",
        111 => "rpcbind",
        123 => "ntp",
        139 => "netbios",
        143 => "imap",
        161 => "snmp",
        389 => "ldap",
        443 => "https",
        445 => "smb",
        515 => "printer",
        548 => "afp",
        631 => "ipp",
        993 => "imaps",
        995 => "pop3s",
        1883 => "mqtt",
        3000 => "http-dev",
        3306 => "mysql",
        3389 => "rdp",
        5000 => "upnp",
        5353 => "mdns",
        5432 => "postgres",
        5900 => "vnc",
        6379 => "redis",
        8000 | 8080 => "http-alt",
        8443 => "https-alt",
        9100 => "printer-raw",
        27017 => "mongodb",
        32400 => "plex",
        _ => return None,
    };
    Some(name)
}

/// Parse a comma-separated list of ports (e.g. `"22,80,443"`) into a vector.
///
/// # Errors
///
/// Returns a message identifying the first token that is not a valid port.
pub fn parse_ports(spec: &str) -> Result<Vec<u16>, String> {
    spec.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u16>().map_err(|_| format!("invalid port: {s}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ports_resolve() {
        assert_eq!(service_for_port(22), Some("ssh"));
        assert_eq!(service_for_port(443), Some("https"));
        assert_eq!(service_for_port(32400), Some("plex"));
    }

    #[test]
    fn unknown_port_is_none() {
        assert_eq!(service_for_port(12345), None);
    }

    #[test]
    fn parses_a_port_list() {
        assert_eq!(parse_ports("22, 80,443").unwrap(), vec![22, 80, 443]);
    }

    #[test]
    fn rejects_a_bad_port() {
        assert!(parse_ports("22,notaport").is_err());
        assert!(parse_ports("99999").is_err());
    }

    #[test]
    fn default_ports_are_sorted_and_unique() {
        let mut sorted = DEFAULT_PORTS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            sorted,
            DEFAULT_PORTS.to_vec(),
            "DEFAULT_PORTS must stay sorted and unique"
        );
    }
}
