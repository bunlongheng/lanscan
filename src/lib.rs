//! LAN Scan: a pure-Rust home network scanner.
//!
//! The crate is organized as a small core library that three front-ends share:
//!
//! * a **CLI** (`lanscan scan`) that prints a table or JSON,
//! * a **TUI** (`lanscan tui`) built on [`ratatui`], and
//! * an **MCP** server (`lanscan mcp`) that speaks JSON-RPC over stdio so agents
//!   and other tools can call the scanner programmatically, and
//! * a **web** server (`lanscan serve`) that exposes a local JSON API and a
//!   self-contained UI so a browser on this machine can drive a scan.
//!
//! Discovery needs no root: hosts are found by probing a handful of common TCP
//! ports and by reading the system ARP cache for MAC and vendor enrichment.
//!
//! # Example
//!
//! ```no_run
//! use lanscan::scan::{scan, ScanConfig};
//!
//! let cfg = ScanConfig::from_cidr("192.168.1.0/24");
//! let hosts = scan(&cfg);
//! for host in hosts {
//!     println!("{} has {} open port(s)", host.ip, host.open_ports.len());
//! }
//! ```

#![doc(html_root_url = "https://docs.rs/lanscan")]

pub mod arp;
pub mod inventory;
pub mod net;
pub mod output;
pub mod scan;
pub mod services;
pub mod vendor;

pub mod mcp;
pub mod serve;
pub mod tui;

/// The crate version, taken from `Cargo.toml` at build time.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
