//! Rendering scan results as a human table or as JSON.

use crate::scan::Host;

/// Render hosts as a JSON array of objects.
///
/// # Errors
///
/// Propagates any [`serde_json`] serialization error (in practice, never for
/// these plain data types).
pub fn to_json(hosts: &[Host]) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(hosts)
}

/// Render hosts as an aligned, human-readable text table.
#[must_use]
pub fn to_table(hosts: &[Host]) -> String {
    if hosts.is_empty() {
        return "No live hosts found.".to_string();
    }

    let rows: Vec<[String; 5]> = hosts.iter().map(row_for).collect();
    let headers = ["IP", "MAC", "HOSTNAME", "VENDOR", "OPEN PORTS"];

    // Compute each column width from the header and every cell.
    let mut widths = headers.map(str::len);
    for row in &rows {
        for (i, cell) in row.iter().enumerate() {
            widths[i] = widths[i].max(cell.chars().count());
        }
    }

    let mut out = String::new();
    push_row(&mut out, &headers.map(String::from), &widths);
    let divider: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    push_row(
        &mut out,
        &divider.try_into().expect("five columns"),
        &widths,
    );
    for row in &rows {
        push_row(&mut out, row, &widths);
    }

    out.push_str(&format!("\n{} host(s) up.", hosts.len()));
    out
}

fn row_for(host: &Host) -> [String; 5] {
    let ports = if host.open_ports.is_empty() {
        "-".to_string()
    } else {
        host.open_ports
            .iter()
            .map(|p| match &p.service {
                Some(service) => format!("{}/{service}", p.port),
                None => p.port.to_string(),
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    [
        host.ip.to_string(),
        host.mac.clone().unwrap_or_else(|| "-".to_string()),
        host.hostname.clone().unwrap_or_else(|| "-".to_string()),
        host.vendor.clone().unwrap_or_else(|| "-".to_string()),
        ports,
    ]
}

fn push_row(out: &mut String, cells: &[String; 5], widths: &[usize; 5]) {
    for (i, cell) in cells.iter().enumerate() {
        let pad = widths[i].saturating_sub(cell.chars().count());
        out.push_str(cell);
        if i < cells.len() - 1 {
            out.push_str(&" ".repeat(pad + 2));
        }
    }
    out.push('\n');
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scan::Port;
    use std::net::Ipv4Addr;

    fn sample() -> Vec<Host> {
        vec![Host {
            ip: Ipv4Addr::new(192, 168, 1, 1),
            mac: Some("AC:BC:32:00:00:00".to_string()),
            hostname: Some("router.home".to_string()),
            vendor: Some("Apple".to_string()),
            open_ports: vec![
                Port {
                    port: 80,
                    service: Some("http".to_string()),
                },
                Port {
                    port: 443,
                    service: Some("https".to_string()),
                },
            ],
        }]
    }

    #[test]
    fn table_contains_key_fields() {
        let table = to_table(&sample());
        assert!(table.contains("192.168.1.1"));
        assert!(table.contains("AC:BC:32:00:00:00"));
        assert!(table.contains("router.home"));
        assert!(table.contains("80/http"));
        assert!(table.contains("1 host(s) up."));
    }

    #[test]
    fn empty_table_is_explicit() {
        assert_eq!(to_table(&[]), "No live hosts found.");
    }

    #[test]
    fn json_round_trips() {
        let json = to_json(&sample()).unwrap();
        let back: Vec<Host> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, sample());
    }
}
