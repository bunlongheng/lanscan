//! A tiny HTTP server exposing the scanner over a local JSON API plus a
//! self-contained web UI, so a browser on this machine can drive a scan.
//!
//! Like the MCP module, this hand-rolls the protocol rather than pulling in a
//! web framework: a threaded [`TcpListener`] accept loop speaking minimal
//! HTTP/1.1. The scan itself still runs locally - the only place with a route
//! to the LAN - and results come back as JSON the bundled UI (or any client)
//! can consume, which is also the seam for mirroring data elsewhere later.
//!
//! Routes:
//! * `GET /` - the embedded single-page UI.
//! * `GET /api/scan?cidr=&ports=&timeout_ms=` - run a scan, return JSON.
//! * `GET /api/arp` - the local ARP cache with vendor enrichment.
//! * `GET /api/config` - the auto-detected CIDR and default ports (UI prefill).
//! * `GET /health` - liveness plus the server version.

use crate::VERSION;
use crate::arp;
use crate::net::{cidr_hosts, default_cidr};
use crate::scan::{ScanConfig, scan};
use crate::services::{DEFAULT_PORTS, parse_ports};

use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};

/// The `Content-Type` used for every JSON response.
const JSON: &str = "application/json";

/// Serve the web UI and JSON API on `host:port`, scanning with `base` as the
/// default configuration (individual requests may override CIDR/ports/timeout).
///
/// Binds to `host` (default `127.0.0.1`, i.e. this machine only) and blocks,
/// handling each connection on its own thread. Ctrl-C stops it.
///
/// # Errors
///
/// Returns an error if the listener cannot bind (for example, the port is in
/// use or the host is not a local address).
pub fn run(base: ScanConfig, host: &str, port: u16) -> std::io::Result<()> {
    let listener = TcpListener::bind((host, port))?;
    eprintln!("lanscan serve: http://{host}:{port}  (Ctrl-C to stop)");
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        let base = base.clone();
        std::thread::spawn(move || {
            let _ = handle(stream, &base);
        });
    }
    Ok(())
}

/// Read one request, route it, and write the response. Best-effort: any I/O
/// error just drops the connection.
fn handle(stream: TcpStream, base: &ScanConfig) -> std::io::Result<()> {
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);

    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    // Drain the remaining request headers; GET requests carry no body we need.
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or("/");
    if method != "GET" {
        return respond(&mut writer, 405, "text/plain; charset=utf-8", b"method not allowed");
    }

    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let params = parse_query(query);

    match path {
        "/" => respond(&mut writer, 200, "text/html; charset=utf-8", INDEX_HTML.as_bytes()),
        "/icon.png" | "/favicon.ico" | "/apple-touch-icon.png" | "/apple-touch-icon-precomposed.png" => {
            respond_cached(&mut writer, "image/png", ICON_PNG)
        }
        "/manifest.webmanifest" => respond(&mut writer, 200, "application/manifest+json", MANIFEST.as_bytes()),
        "/health" => {
            let body = json!({ "status": "ok", "version": VERSION }).to_string();
            respond(&mut writer, 200, JSON, body.as_bytes())
        }
        "/api/config" => {
            let body = json!({
                "cidr": default_cidr(),
                "default_ports": DEFAULT_PORTS,
            })
            .to_string();
            respond(&mut writer, 200, JSON, body.as_bytes())
        }
        "/api/arp" => respond(&mut writer, 200, JSON, arp_json().as_bytes()),
        "/api/inventory" => respond(&mut writer, 200, JSON, inventory_json().as_bytes()),
        "/api/scan" => match build_config(base, &params) {
            Ok(cfg) => {
                let started = Instant::now();
                let hosts = scan(&cfg);
                // Remember this scan so the UI can show online vs offline history.
                crate::inventory::persist_scan(&hosts);
                let body = json!({
                    "cidr": cfg.cidr,
                    "count": hosts.len(),
                    "elapsed_ms": started.elapsed().as_millis() as u64,
                    "hosts": hosts,
                })
                .to_string();
                respond(&mut writer, 200, JSON, body.as_bytes())
            }
            Err(message) => {
                let body = json!({ "error": message }).to_string();
                respond(&mut writer, 400, JSON, body.as_bytes())
            }
        },
        _ => respond(&mut writer, 404, "text/plain; charset=utf-8", b"not found"),
    }
}

/// Build a [`ScanConfig`] from the base config plus query overrides, validating
/// each field the same way the CLI and MCP paths do.
fn build_config(base: &ScanConfig, params: &HashMap<String, String>) -> Result<ScanConfig, String> {
    let cidr = match nonempty(params, "cidr") {
        Some(cidr) => cidr,
        None => default_cidr().ok_or("could not determine local network; pass cidr")?,
    };
    cidr_hosts(&cidr)?; // validate early for a clear error

    let ports = match nonempty(params, "ports") {
        Some(spec) => parse_ports(&spec)?,
        None => base.ports.clone(),
    };
    if ports.is_empty() {
        return Err("no ports to scan".to_string());
    }

    let timeout = params
        .get("timeout_ms")
        .and_then(|value| value.parse::<u64>().ok())
        .map_or(base.timeout, Duration::from_millis);

    Ok(ScanConfig {
        cidr,
        ports,
        timeout,
        concurrency: base.concurrency,
    })
}

/// A trimmed, non-empty query parameter, or `None`.
fn nonempty(params: &HashMap<String, String>, key: &str) -> Option<String> {
    params
        .get(key)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Serialize the local ARP cache to a JSON array, sorted by IP, with vendor
/// enrichment - the same shape the MCP `arp_table` tool returns.
fn arp_json() -> String {
    let mut entries: Vec<_> = arp::arp_table().into_values().collect();
    entries.sort_by_key(|entry| entry.ip);
    let value: Vec<Value> = entries
        .into_iter()
        .map(|entry| {
            let vendor = entry.mac.as_deref().and_then(crate::vendor::vendor_for_mac);
            json!({
                "ip": entry.ip.to_string(),
                "mac": entry.mac,
                "hostname": entry.hostname,
                "vendor": vendor,
            })
        })
        .collect();
    json!(value).to_string()
}

/// Serialize the persisted device inventory to JSON: every device ever seen,
/// each flagged `online` (present in the most recent scan) with a `last_seen`
/// timestamp, so the UI can show what has gone offline.
fn inventory_json() -> String {
    let Some(path) = crate::inventory::default_path() else {
        return json!({ "last_scan": 0, "now": crate::inventory::now_secs(), "devices": [] }).to_string();
    };
    let inventory = crate::inventory::Inventory::load(&path);
    let devices: Vec<Value> = inventory
        .sorted()
        .into_iter()
        .map(|device| {
            json!({
                "key": device.key,
                "ip": device.ip,
                "mac": device.mac,
                "hostname": device.hostname,
                "vendor": device.vendor,
                "open_ports": device.open_ports,
                "online": inventory.is_online(device),
                "first_seen": device.first_seen,
                "last_seen": device.last_seen,
                "times_seen": device.times_seen,
            })
        })
        .collect();
    json!({
        "last_scan": inventory.last_scan,
        "now": crate::inventory::now_secs(),
        "devices": devices,
    })
    .to_string()
}

/// Parse `a=1&b=2` into a map, percent- and `+`-decoding keys and values.
fn parse_query(query: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        map.insert(percent_decode(key), percent_decode(value));
    }
    map
}

/// Decode `%XX` escapes and `+` (space) in a query token. Invalid escapes are
/// left as literal bytes rather than dropped.
fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match u8::from_str_radix(&text[i + 1..i + 3], 16) {
                Ok(decoded) => {
                    out.push(decoded);
                    i += 3;
                }
                Err(_) => {
                    out.push(bytes[i]);
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            other => {
                out.push(other);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Serve a static asset with a long cache lifetime (icons never change per build).
fn respond_cached(stream: &mut TcpStream, content_type: &str, body: &[u8]) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: public, max-age=86400\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// Write a complete HTTP/1.1 response and close the connection.
fn respond(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        _ => "OK",
    };
    let header = format!(
        "HTTP/1.1 {status} {reason}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         Cache-Control: no-store\r\n\
         Connection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

/// The self-contained web UI, served at `/`. Inline CSS and JS only, so it
/// needs no external assets and works offline.
const INDEX_HTML: &str = include_str!("serve_ui.html");

/// The app icon (512x512 PNG), served for the favicon, the iOS/Android
/// add-to-home-screen tile, and the web-app manifest.
const ICON_PNG: &[u8] = include_bytes!("icon.png");

/// The web-app manifest enabling "add to home screen" as a standalone app.
const MANIFEST: &str = r##"{
  "name": "LAN Scan",
  "short_name": "LAN Scan",
  "description": "Local network scanner",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#0b1020",
  "theme_color": "#0b1020",
  "icons": [
    { "src": "/icon.png", "sizes": "512x512", "type": "image/png", "purpose": "any maskable" },
    { "src": "/icon.png", "sizes": "192x192", "type": "image/png", "purpose": "any maskable" }
  ]
}"##;

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> ScanConfig {
        ScanConfig::default()
    }

    #[test]
    fn parses_and_decodes_query() {
        let params = parse_query("cidr=10.0.0.0%2F24&ports=22%2C80&x=");
        assert_eq!(params.get("cidr").unwrap(), "10.0.0.0/24");
        assert_eq!(params.get("ports").unwrap(), "22,80");
        assert_eq!(params.get("x").unwrap(), "");
    }

    #[test]
    fn nonempty_trims_and_filters() {
        let params = parse_query("a=%20%20&b=%20hi%20");
        assert_eq!(nonempty(&params, "a"), None);
        assert_eq!(nonempty(&params, "b").as_deref(), Some("hi"));
        assert_eq!(nonempty(&params, "missing"), None);
    }

    #[test]
    fn config_defaults_ports_from_base() {
        let params = parse_query("cidr=192.168.5.0/24");
        let cfg = build_config(&base(), &params).unwrap();
        assert_eq!(cfg.cidr, "192.168.5.0/24");
        assert_eq!(cfg.ports, base().ports);
    }

    #[test]
    fn config_overrides_ports_and_timeout() {
        let params = parse_query("cidr=192.168.5.0/24&ports=22,443&timeout_ms=250");
        let cfg = build_config(&base(), &params).unwrap();
        assert_eq!(cfg.ports, vec![22, 443]);
        assert_eq!(cfg.timeout, Duration::from_millis(250));
    }

    #[test]
    fn config_rejects_bad_cidr() {
        let params = parse_query("cidr=10.0.0.0/8");
        assert!(build_config(&base(), &params).unwrap_err().contains("too large"));
    }

    #[test]
    fn ui_references_the_api() {
        assert!(INDEX_HTML.contains("/api/scan"));
        assert!(INDEX_HTML.contains("/api/config"));
    }
}
