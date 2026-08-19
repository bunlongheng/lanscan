//! A small on-disk device inventory: every host ever seen, so the scanner can
//! show what is online now and what has gone offline, with a last-seen time.
//!
//! A live scan only reports reachable hosts. Persisting each scan lets the tool
//! remember devices across runs and flag the ones missing from the latest scan
//! as offline. Storage is a single JSON file - no database dependency - keyed
//! by MAC address where known, falling back to the IP when a host has no MAC.

use crate::scan::{Host, Port};

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// One remembered device and when it was last seen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    /// Stable key: the MAC address if known, otherwise the IP string.
    pub key: String,
    /// Most recent IPv4 address (may change across DHCP leases).
    pub ip: String,
    /// Hardware address, once it has ever been resolved.
    pub mac: Option<String>,
    /// Most recent resolved hostname.
    pub hostname: Option<String>,
    /// Most recent vendor guess.
    pub vendor: Option<String>,
    /// Open ports from the most recent sighting.
    pub open_ports: Vec<Port>,
    /// Unix time (seconds) the device was first seen.
    pub first_seen: u64,
    /// Unix time (seconds) the device was last seen.
    pub last_seen: u64,
    /// Number of scans this device has appeared in.
    pub times_seen: u64,
}

/// The persisted inventory: known devices plus the time of the last scan.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Inventory {
    /// Unix time (seconds) of the most recent recorded scan. Zero means none.
    #[serde(default)]
    pub last_scan: u64,
    /// Known devices, keyed by [`Device::key`].
    #[serde(default)]
    pub devices: BTreeMap<String, Device>,
}

impl Inventory {
    /// Fold one scan's hosts into the inventory, stamping `now` as the scan
    /// time. New devices are inserted; seen devices have their fields refreshed
    /// and `last_seen`/`times_seen` bumped.
    pub fn record(&mut self, hosts: &[Host], now: u64) {
        self.last_scan = now;
        for host in hosts {
            let key = device_key(host);
            let device = self.devices.entry(key.clone()).or_insert_with(|| Device {
                key,
                ip: host.ip.to_string(),
                mac: host.mac.clone(),
                hostname: host.hostname.clone(),
                vendor: host.vendor.clone(),
                open_ports: host.open_ports.clone(),
                first_seen: now,
                last_seen: now,
                times_seen: 0,
            });
            device.ip = host.ip.to_string();
            // Only overwrite identity fields when this scan actually resolved
            // them, so a transient miss never erases a known name or vendor.
            if host.mac.is_some() {
                device.mac = host.mac.clone();
            }
            if host.hostname.is_some() {
                device.hostname = host.hostname.clone();
            }
            if host.vendor.is_some() {
                device.vendor = host.vendor.clone();
            }
            device.open_ports = host.open_ports.clone();
            device.last_seen = now;
            device.times_seen += 1;
        }
    }

    /// Whether a device was present in the most recent scan (i.e. online now).
    #[must_use]
    pub fn is_online(&self, device: &Device) -> bool {
        self.last_scan != 0 && device.last_seen >= self.last_scan
    }

    /// Devices for display: online first, then by most-recently-seen.
    #[must_use]
    pub fn sorted(&self) -> Vec<&Device> {
        let mut devices: Vec<&Device> = self.devices.values().collect();
        devices.sort_by(|a, b| {
            self.is_online(b)
                .cmp(&self.is_online(a))
                .then(b.last_seen.cmp(&a.last_seen))
                .then(a.ip.cmp(&b.ip))
        });
        devices
    }

    /// Read the inventory at `path`, returning an empty one if it is missing or
    /// unreadable (a corrupt file should never crash a scan).
    #[must_use]
    pub fn load(path: &Path) -> Inventory {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|text| serde_json::from_str(&text).ok())
            .unwrap_or_default()
    }

    /// Write the inventory to `path`, creating parent directories as needed.
    ///
    /// # Errors
    ///
    /// Returns any I/O or serialization error encountered while writing.
    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let json = serde_json::to_string_pretty(self)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        std::fs::write(path, json)
    }
}

/// The stable per-device key: MAC when known, else the IP.
fn device_key(host: &Host) -> String {
    host.mac.clone().unwrap_or_else(|| host.ip.to_string())
}

/// Current Unix time in seconds (zero if the clock is before the epoch).
#[must_use]
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// The inventory file path: `$LANSCAN_INVENTORY` if set, otherwise
/// `$HOME/.lanscan/inventory.json`. `None` when no home directory is known.
#[must_use]
pub fn default_path() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os("LANSCAN_INVENTORY") {
        return Some(PathBuf::from(explicit));
    }
    let home = std::env::var_os("HOME")?;
    Some(PathBuf::from(home).join(".lanscan").join("inventory.json"))
}

/// Best-effort: fold this scan into the on-disk inventory. Any missing path or
/// I/O error is ignored so persistence never fails a scan.
pub fn persist_scan(hosts: &[Host]) {
    let Some(path) = default_path() else { return };
    let mut inventory = Inventory::load(&path);
    inventory.record(hosts, now_secs());
    let _ = inventory.save(&path);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn host(ip: [u8; 4], mac: Option<&str>, name: Option<&str>) -> Host {
        Host {
            ip: Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]),
            mac: mac.map(String::from),
            hostname: name.map(String::from),
            vendor: Some("Acme".to_string()),
            open_ports: vec![Port { port: 80, service: Some("http".to_string()) }],
        }
    }

    #[test]
    fn records_and_flags_online() {
        let mut inv = Inventory::default();
        inv.record(&[host([10, 0, 0, 5], Some("AA:BB:CC:00:11:22"), Some("nas"))], 1000);
        assert_eq!(inv.devices.len(), 1);
        let device = inv.devices.values().next().unwrap();
        assert_eq!(device.key, "AA:BB:CC:00:11:22");
        assert_eq!(device.times_seen, 1);
        assert!(inv.is_online(device));
    }

    #[test]
    fn missing_device_goes_offline_on_next_scan() {
        let mut inv = Inventory::default();
        inv.record(&[host([10, 0, 0, 5], Some("AA:BB:CC:00:11:22"), None)], 1000);
        // A later scan without that device: it stays known but is now offline.
        inv.record(&[host([10, 0, 0, 6], Some("DD:EE:FF:00:11:22"), None)], 2000);
        let gone = &inv.devices["AA:BB:CC:00:11:22"];
        let present = &inv.devices["DD:EE:FF:00:11:22"];
        assert!(!inv.is_online(gone));
        assert!(inv.is_online(present));
        assert_eq!(gone.last_seen, 1000);
    }

    #[test]
    fn re_sighting_bumps_count_and_keeps_first_seen() {
        let mut inv = Inventory::default();
        inv.record(&[host([10, 0, 0, 5], Some("AA:BB:CC:00:11:22"), None)], 1000);
        inv.record(&[host([10, 0, 0, 9], Some("AA:BB:CC:00:11:22"), Some("nas"))], 2000);
        let device = &inv.devices["AA:BB:CC:00:11:22"];
        assert_eq!(device.times_seen, 2);
        assert_eq!(device.first_seen, 1000);
        assert_eq!(device.last_seen, 2000);
        assert_eq!(device.ip, "10.0.0.9"); // refreshed to the latest lease
        assert_eq!(device.hostname.as_deref(), Some("nas"));
    }

    #[test]
    fn keys_by_ip_when_mac_is_missing() {
        let mut inv = Inventory::default();
        inv.record(&[host([10, 0, 0, 7], None, None)], 1000);
        assert!(inv.devices.contains_key("10.0.0.7"));
    }

    #[test]
    fn load_missing_file_is_empty() {
        let inv = Inventory::load(Path::new("/no/such/lanscan-inventory.json"));
        assert!(inv.devices.is_empty());
        assert_eq!(inv.last_scan, 0);
    }

    #[test]
    fn round_trips_through_json() {
        let mut inv = Inventory::default();
        inv.record(&[host([10, 0, 0, 5], Some("AA:BB:CC:00:11:22"), Some("nas"))], 1234);
        let json = serde_json::to_string(&inv).unwrap();
        let back: Inventory = serde_json::from_str(&json).unwrap();
        assert_eq!(inv, back);
    }
}
