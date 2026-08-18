//! End-to-end tests that drive the compiled `lanscan` binary.

use std::io::Write;
use std::process::{Command, Stdio};

/// Path to the binary Cargo built for this test run.
fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_lanscan")
}

#[test]
fn prints_version() {
    let out = Command::new(bin())
        .arg("--version")
        .output()
        .expect("run --version");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    assert!(text.contains("lanscan"), "version output was: {text}");
}

#[test]
fn scan_rejects_bad_cidr() {
    let out = Command::new(bin())
        .args(["scan", "--cidr", "10.0.0.0/8"])
        .output()
        .expect("run scan");
    assert!(!out.status.success(), "over-large CIDR should fail");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("too large"), "stderr was: {err}");
}

#[test]
fn scan_emits_valid_json_for_empty_range() {
    // 192.0.2.0/30 is RFC 5737 documentation space: nothing answers, so the
    // scan returns quickly and the output must be a valid (empty) JSON array.
    let out = Command::new(bin())
        .args([
            "scan",
            "--cidr",
            "192.0.2.0/30",
            "--timeout-ms",
            "150",
            "--json",
        ])
        .output()
        .expect("run scan --json");
    assert!(out.status.success());
    let text = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(text.trim()).expect("valid JSON");
    assert!(parsed.is_array(), "expected a JSON array, got: {text}");
}

#[test]
fn mcp_initialize_and_list_tools() {
    let mut child = Command::new(bin())
        .arg("mcp")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn mcp");

    let requests = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\"}\n\
                    {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n";
    child
        .stdin
        .take()
        .unwrap()
        .write_all(requests.as_bytes())
        .unwrap();

    let out = child.wait_with_output().expect("mcp output");
    let text = String::from_utf8_lossy(&out.stdout);
    let lines: Vec<&str> = text.lines().collect();
    assert_eq!(lines.len(), 2, "expected 2 responses, got: {text}");

    let init: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(init["result"]["serverInfo"]["name"], "lanscan");

    let list: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
    let tools = list["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 2);
}
