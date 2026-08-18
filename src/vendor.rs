//! Best-effort MAC-address OUI to vendor lookup.
//!
//! The full IEEE OUI registry has tens of thousands of entries; shipping all of
//! them would bloat the binary. Instead this embeds a curated set of prefixes
//! for the vendors that dominate a typical home network. Unknown prefixes
//! simply resolve to `None`, which is honest rather than wrong.

/// Curated OUI prefixes (first three MAC octets, uppercase, colon-separated).
const OUI: &[(&str, &str)] = &[
    ("00:1A:11", "Google"),
    ("3C:5A:B4", "Google"),
    ("F4:F5:E8", "Google"),
    ("D8:6C:63", "Google"),
    ("A4:77:33", "Google"),
    ("00:03:93", "Apple"),
    ("00:1C:B3", "Apple"),
    ("00:1E:C2", "Apple"),
    ("3C:07:54", "Apple"),
    ("A4:83:E7", "Apple"),
    ("F0:18:98", "Apple"),
    ("AC:BC:32", "Apple"),
    ("DC:A6:32", "Raspberry Pi"),
    ("B8:27:EB", "Raspberry Pi"),
    ("E4:5F:01", "Raspberry Pi"),
    ("D8:3A:DD", "Raspberry Pi"),
    ("00:50:56", "VMware"),
    ("00:0C:29", "VMware"),
    ("08:00:27", "VirtualBox"),
    ("52:54:00", "QEMU/KVM"),
    ("00:1D:0F", "TP-Link"),
    ("50:C7:BF", "TP-Link"),
    ("EC:08:6B", "TP-Link"),
    ("00:18:E7", "Netgear"),
    ("A0:40:A0", "Netgear"),
    ("2C:30:33", "Netgear"),
    ("00:24:B2", "Netgear"),
    ("00:1F:33", "Netgear"),
    ("00:14:BF", "Cisco/Linksys"),
    ("00:25:9C", "Cisco/Linksys"),
    ("58:6D:8F", "Cisco/Linksys"),
    ("00:90:A9", "Western Digital"),
    ("00:11:32", "Synology"),
    ("00:08:9B", "Synology"),
    ("24:5E:BE", "QNAP"),
    ("00:04:F2", "Polycom"),
    ("B0:4E:26", "TP-Link"),
    ("FC:EC:DA", "Ubiquiti"),
    ("74:83:C2", "Ubiquiti"),
    ("00:15:6D", "Ubiquiti"),
    ("18:E8:29", "Ubiquiti"),
    ("00:17:88", "Philips Hue"),
    ("EC:B5:FA", "Philips Hue"),
    ("00:BB:3A", "Amazon"),
    ("FC:65:DE", "Amazon"),
    ("68:37:E9", "Amazon"),
    ("00:71:47", "Amazon"),
    ("50:DC:E7", "Amazon"),
    ("40:B4:CD", "Amazon"),
    ("18:B4:30", "Nest"),
    ("64:16:66", "Nest"),
    ("D8:0D:17", "TP-Link"),
    ("00:1D:D8", "Microsoft"),
    ("00:15:5D", "Microsoft (Hyper-V)"),
    ("7C:1E:52", "Microsoft"),
    ("00:50:F2", "Microsoft"),
    ("00:E0:4C", "Realtek"),
    ("52:54:AB", "Realtek"),
    ("00:1B:44", "SanDisk"),
    ("00:24:E4", "Withings"),
    ("00:04:20", "Sony"),
    ("00:13:A9", "Sony"),
    ("FC:F1:52", "Sony"),
    ("00:26:AB", "Seiko Epson"),
    ("00:00:48", "Seiko Epson"),
    ("38:D5:47", "ASUSTek"),
    ("00:1F:C6", "ASUSTek"),
    ("2C:56:DC", "ASUSTek"),
    ("00:26:B9", "Dell"),
    ("18:03:73", "Dell"),
    ("F8:BC:12", "Dell"),
    ("00:21:9B", "Dell"),
];

/// Normalize a MAC address to `AA:BB:CC:DD:EE:FF` (uppercase, colon-separated).
///
/// Accepts colon- or hyphen-separated input and pads single-digit octets, which
/// some platforms (notably the BSD/macOS `arp` command) emit. Returns `None`
/// when the value does not look like a 6-octet MAC.
#[must_use]
pub fn normalize_mac(mac: &str) -> Option<String> {
    let parts: Vec<&str> = mac.split([':', '-']).collect();
    if parts.len() != 6 {
        return None;
    }
    let mut octets = Vec::with_capacity(6);
    for part in parts {
        let byte = u8::from_str_radix(part, 16).ok()?;
        octets.push(format!("{byte:02X}"));
    }
    Some(octets.join(":"))
}

/// Look up the vendor for a MAC address by its OUI prefix.
#[must_use]
pub fn vendor_for_mac(mac: &str) -> Option<&'static str> {
    let normalized = normalize_mac(mac)?;
    let prefix: String = normalized.chars().take(8).collect(); // "AA:BB:CC"
    OUI.iter()
        .find(|(oui, _)| *oui == prefix)
        .map(|(_, vendor)| *vendor)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_short_octets() {
        // macOS arp emits "b:27:eb:..." without leading zeros.
        assert_eq!(
            normalize_mac("b:27:eb:1:2:3").as_deref(),
            Some("0B:27:EB:01:02:03")
        );
    }

    #[test]
    fn normalizes_hyphen_form() {
        assert_eq!(
            normalize_mac("DC-A6-32-11-22-33").as_deref(),
            Some("DC:A6:32:11:22:33")
        );
    }

    #[test]
    fn rejects_non_mac() {
        assert_eq!(normalize_mac("not:a:mac"), None);
        assert_eq!(normalize_mac("11:22:33"), None);
    }

    #[test]
    fn resolves_known_vendor() {
        assert_eq!(vendor_for_mac("b8:27:eb:aa:bb:cc"), Some("Raspberry Pi"));
        assert_eq!(vendor_for_mac("DC-A6-32-00-00-00"), Some("Raspberry Pi"));
    }

    #[test]
    fn unknown_vendor_is_none() {
        assert_eq!(vendor_for_mac("aa:aa:aa:aa:aa:aa"), None);
    }
}
