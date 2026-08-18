//! A minimal Model Context Protocol server over stdio.
//!
//! Rather than pull in a full SDK, this speaks the MCP JSON-RPC dialect
//! directly: newline-delimited JSON messages on stdin/stdout. Only the handful
//! of methods a tool server needs are implemented (`initialize`, `tools/list`,
//! `tools/call`, `ping`), which keeps the surface small and unit-testable.
//!
//! Exposed tools:
//! * `scan_network` - discover live hosts, their open ports, MAC and vendor.
//! * `arp_table` - dump the local ARP cache.

use crate::scan::{ScanConfig, scan};
use crate::services::{DEFAULT_PORTS, parse_ports};
use crate::{VERSION, arp};

use serde_json::{Value, json};
use std::io::{BufRead, Write};
use std::time::Duration;

/// The MCP protocol revision this server implements.
const PROTOCOL_VERSION: &str = "2024-11-05";

/// Run the MCP server loop, reading requests from `input` and writing responses
/// to `output`. Blocks until end-of-input.
///
/// # Errors
///
/// Propagates I/O errors from the underlying reader or writer.
pub fn serve<R: BufRead, W: Write>(mut input: R, mut output: W) -> std::io::Result<()> {
    let mut line = String::new();
    loop {
        line.clear();
        let read = input.read_line(&mut line)?;
        if read == 0 {
            break; // EOF
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<Value>(trimmed) {
            Ok(request) => handle_request(&request),
            Err(err) => Some(error_response(
                &Value::Null,
                -32700,
                &format!("parse error: {err}"),
            )),
        };

        if let Some(response) = response {
            serde_json::to_writer(&mut output, &response)?;
            output.write_all(b"\n")?;
            output.flush()?;
        }
    }
    Ok(())
}

/// Run the server against real stdio. Convenience wrapper over [`serve`].
///
/// # Errors
///
/// Propagates any I/O error from stdio.
pub fn serve_stdio() -> std::io::Result<()> {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    serve(stdin.lock(), stdout.lock())
}

/// Handle a single JSON-RPC request, returning the response to send.
///
/// Returns `None` for notifications (requests without an `id`), which by the
/// JSON-RPC spec receive no reply.
#[must_use]
pub fn handle_request(request: &Value) -> Option<Value> {
    let id = request.get("id").cloned();
    let method = request
        .get("method")
        .and_then(Value::as_str)
        .unwrap_or_default();

    // Notifications carry no id and expect no response.
    let is_notification = id.is_none();

    match method {
        "initialize" => id.map(|id| success(&id, initialize_result())),
        "tools/list" => id.map(|id| success(&id, tools_list_result())),
        "ping" => id.map(|id| success(&id, json!({}))),
        "notifications/initialized" | "notifications/cancelled" => None,
        "tools/call" => {
            let id = id?;
            Some(handle_tools_call(&id, request.get("params")))
        }
        _ if is_notification => None,
        _ => id.map(|id| error_response(&id, -32601, &format!("method not found: {method}"))),
    }
}

fn initialize_result() -> Value {
    json!({
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": { "tools": {} },
        "serverInfo": { "name": "lanscan", "version": VERSION }
    })
}

fn tools_list_result() -> Value {
    json!({
        "tools": [
            {
                "name": "scan_network",
                "description": "Scan a LAN and return live hosts with their open ports, MAC address, hostname, and hardware vendor.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "cidr": {
                            "type": "string",
                            "description": "Network to scan in CIDR form, e.g. 192.168.1.0/24. Defaults to the local /24."
                        },
                        "ports": {
                            "type": "string",
                            "description": "Comma-separated TCP ports to probe, e.g. \"22,80,443\". Defaults to a common-service set."
                        },
                        "timeout_ms": {
                            "type": "integer",
                            "description": "Per-connection timeout in milliseconds (default 400).",
                            "minimum": 10
                        }
                    }
                }
            },
            {
                "name": "arp_table",
                "description": "Return the local ARP cache: IP, MAC, hostname, and inferred vendor for recently-seen hosts.",
                "inputSchema": { "type": "object", "properties": {} }
            }
        ]
    })
}

fn handle_tools_call(id: &Value, params: Option<&Value>) -> Value {
    let name = params
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let args = params
        .and_then(|p| p.get("arguments"))
        .cloned()
        .unwrap_or_else(|| json!({}));

    let result = match name {
        "scan_network" => run_scan_tool(&args),
        "arp_table" => run_arp_tool(),
        other => Err(format!("unknown tool: {other}")),
    };

    match result {
        Ok(text) => success(id, tool_text(&text, false)),
        Err(message) => success(id, tool_text(&message, true)),
    }
}

fn run_scan_tool(args: &Value) -> Result<String, String> {
    let cfg = build_scan_config(args)?;
    let hosts = scan(&cfg);
    serde_json::to_string_pretty(&hosts).map_err(|e| e.to_string())
}

fn run_arp_tool() -> Result<String, String> {
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
    serde_json::to_string_pretty(&value).map_err(|e| e.to_string())
}

/// Build a [`ScanConfig`] from MCP tool arguments, validating each field.
///
/// # Errors
///
/// Returns a message when `cidr` or `ports` are malformed.
pub fn build_scan_config(args: &Value) -> Result<ScanConfig, String> {
    let cidr = match args.get("cidr").and_then(Value::as_str) {
        Some(cidr) => cidr.to_string(),
        None => crate::net::default_cidr().ok_or("could not determine local network; pass cidr")?,
    };
    // Validate the CIDR eagerly so the caller gets a clear error.
    crate::net::cidr_hosts(&cidr)?;

    let ports = match args.get("ports").and_then(Value::as_str) {
        Some(spec) => parse_ports(spec)?,
        None => DEFAULT_PORTS.to_vec(),
    };
    if ports.is_empty() {
        return Err("no ports to scan".to_string());
    }

    let timeout = args
        .get("timeout_ms")
        .and_then(Value::as_u64)
        .map_or(Duration::from_millis(400), Duration::from_millis);

    Ok(ScanConfig {
        cidr,
        ports,
        timeout,
        concurrency: 256,
    })
}

fn tool_text(text: &str, is_error: bool) -> Value {
    json!({
        "content": [{ "type": "text", "text": text }],
        "isError": is_error
    })
}

fn success(id: &Value, result: Value) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "result": result })
}

fn error_response(id: &Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn initialize_reports_server_info() {
        let req = json!({ "jsonrpc": "2.0", "id": 1, "method": "initialize" });
        let resp = handle_request(&req).expect("initialize has a response");
        assert_eq!(resp["result"]["serverInfo"]["name"], "lanscan");
        assert_eq!(resp["result"]["protocolVersion"], PROTOCOL_VERSION);
    }

    #[test]
    fn tools_list_exposes_both_tools() {
        let req = json!({ "jsonrpc": "2.0", "id": 2, "method": "tools/list" });
        let resp = handle_request(&req).unwrap();
        let names: Vec<&str> = resp["result"]["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["name"].as_str().unwrap())
            .collect();
        assert!(names.contains(&"scan_network"));
        assert!(names.contains(&"arp_table"));
    }

    #[test]
    fn notifications_get_no_response() {
        let req = json!({ "jsonrpc": "2.0", "method": "notifications/initialized" });
        assert!(handle_request(&req).is_none());
    }

    #[test]
    fn unknown_method_is_an_error() {
        let req = json!({ "jsonrpc": "2.0", "id": 3, "method": "does/not/exist" });
        let resp = handle_request(&req).unwrap();
        assert_eq!(resp["error"]["code"], -32601);
    }

    #[test]
    fn build_config_rejects_bad_cidr() {
        let err = build_scan_config(&json!({ "cidr": "10.0.0.0/8" })).unwrap_err();
        assert!(err.contains("too large"));
    }

    #[test]
    fn build_config_parses_ports_and_timeout() {
        let cfg = build_scan_config(&json!({
            "cidr": "192.168.5.0/24",
            "ports": "22,443",
            "timeout_ms": 250
        }))
        .unwrap();
        assert_eq!(cfg.cidr, "192.168.5.0/24");
        assert_eq!(cfg.ports, vec![22, 443]);
        assert_eq!(cfg.timeout, Duration::from_millis(250));
    }

    #[test]
    fn scan_tool_reports_unknown_tool() {
        let id = json!(9);
        let resp = handle_tools_call(&id, Some(&json!({ "name": "bogus" })));
        assert_eq!(resp["result"]["isError"], true);
    }

    #[test]
    fn serve_handles_a_full_exchange() {
        let input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n\
                     {\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n\
                     {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n";
        let mut output = Vec::new();
        serve(input.as_bytes(), &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        // initialize + tools/list produce two responses; the notification none.
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("serverInfo"));
        assert!(lines[1].contains("scan_network"));
    }
}
