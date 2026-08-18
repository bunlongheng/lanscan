//! Reading and parsing the system ARP cache for MAC/hostname enrichment.
//!
//! The scanner discovers *whether* a host is up by probing TCP ports. The ARP
//! cache adds the *identity*: hardware address, and often a resolved hostname.
//! Parsing is split from the command invocation so it can be unit-tested
//! against captured fixtures on any platform.

use crate::vendor::normalize_mac;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;

/// One entry from the ARP cache.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArpEntry {
    /// The cached IPv4 address.
    pub ip: Ipv4Addr,
    /// The hardware (MAC) address, normalized, when the entry is complete.
    pub mac: Option<String>,
    /// The resolved hostname, when the resolver returned one.
    pub hostname: Option<String>,
}

/// Read the local ARP cache by invoking the system `arp -a` command.
///
/// Returns an empty map when the command is unavailable or fails; the scanner
/// treats ARP data as optional enrichment, never a hard dependency.
#[must_use]
pub fn arp_table() -> HashMap<Ipv4Addr, ArpEntry> {
    let output = Command::new("arp").arg("-a").output();
    let text = match output {
        Ok(out) if out.status.success() => String::from_utf8_lossy(&out.stdout).into_owned(),
        _ => return HashMap::new(),
    };
    parse_arp(&text)
        .into_iter()
        .map(|entry| (entry.ip, entry))
        .collect()
}

/// Parse the textual output of `arp -a` into structured entries.
///
/// Handles the BSD/macOS and Linux shapes, both of which follow the pattern
/// `hostname (1.2.3.4) at aa:bb:cc:dd:ee:ff ...`. Incomplete entries (no MAC)
/// are still returned, with `mac == None`.
#[must_use]
pub fn parse_arp(text: &str) -> Vec<ArpEntry> {
    let mut entries = Vec::new();
    for line in text.lines() {
        let Some(entry) = parse_line(line) else {
            continue;
        };
        entries.push(entry);
    }
    entries
}

fn parse_line(line: &str) -> Option<ArpEntry> {
    // IP address lives inside the first "(...)" group.
    let open = line.find('(')?;
    let close = line[open..].find(')')? + open;
    let ip: Ipv4Addr = line[open + 1..close].parse().ok()?;

    // Hostname is the token before " (", unless it is the "?" placeholder.
    let hostname = {
        let head = line[..open].trim();
        if head.is_empty() || head == "?" {
            None
        } else {
            Some(head.to_string())
        }
    };

    // MAC follows the literal " at ".
    let mac = line.find(" at ").and_then(|at| {
        let rest = line[at + 4..].trim_start();
        let token = rest.split_whitespace().next()?;
        // BSD prints "(incomplete)" for unresolved entries.
        if token.starts_with('(') {
            None
        } else {
            normalize_mac(token)
        }
    });

    Some(ArpEntry { ip, mac, hostname })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_macos_output() {
        let text = "\
router.home (192.168.1.1) at ac:bc:32:11:22:33 on en0 ifscope [ethernet]
? (192.168.1.42) at b8:27:eb:aa:bb:cc on en0 ifscope [ethernet]
? (192.168.1.99) at (incomplete) on en0 ifscope [ethernet]";
        let entries = parse_arp(text);
        assert_eq!(entries.len(), 3);

        assert_eq!(entries[0].ip, Ipv4Addr::new(192, 168, 1, 1));
        assert_eq!(entries[0].hostname.as_deref(), Some("router.home"));
        assert_eq!(entries[0].mac.as_deref(), Some("AC:BC:32:11:22:33"));

        assert_eq!(entries[1].hostname, None);
        assert_eq!(entries[1].mac.as_deref(), Some("B8:27:EB:AA:BB:CC"));

        // Incomplete entries keep the IP but drop the MAC.
        assert_eq!(entries[2].ip, Ipv4Addr::new(192, 168, 1, 99));
        assert_eq!(entries[2].mac, None);
    }

    #[test]
    fn parses_linux_output() {
        let text = "nas (10.0.0.5) at dc:a6:32:00:11:22 [ether] on eth0";
        let entries = parse_arp(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].ip, Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(entries[0].hostname.as_deref(), Some("nas"));
        assert_eq!(entries[0].mac.as_deref(), Some("DC:A6:32:00:11:22"));
    }

    #[test]
    fn ignores_junk_lines() {
        assert!(parse_arp("this is not an arp line\n\n").is_empty());
    }
}
