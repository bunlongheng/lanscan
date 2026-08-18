# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-08-18

### Added

- Core scanning engine: concurrent TCP-connect host discovery over a bounded
  thread pool, no root required.
- ARP-cache enrichment for MAC address, hostname, and OUI-based vendor guess.
- CLI (`lanscan scan`) with table and `--json` output, configurable CIDR,
  ports, timeout, and concurrency.
- Interactive TUI (`lanscan tui`) built on ratatui, with background scanning
  and rescan.
- MCP server (`lanscan mcp`) speaking JSON-RPC over stdio, exposing
  `scan_network` and `arp_table` tools.
- Unit and end-to-end test suites.
