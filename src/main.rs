//! `lanscan` command-line entry point: `scan`, `tui`, and `mcp` subcommands.

use clap::{Parser, Subcommand};
use lanscan::net::{cidr_hosts, default_cidr};
use lanscan::output::{to_json, to_table};
use lanscan::scan::{ScanConfig, scan};
use lanscan::services::{DEFAULT_PORTS, parse_ports};
use std::io::IsTerminal;
use std::process::ExitCode;
use std::time::Duration;

/// A pure-Rust home LAN scanner: CLI, TUI, and MCP server.
#[derive(Parser)]
#[command(name = "lanscan", version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Scan the network and print a table (or JSON with --json).
    Scan(ScanArgs),
    /// Launch the interactive terminal UI.
    Tui(NetArgs),
    /// Run the Model Context Protocol server over stdio.
    Mcp,
    /// Serve a local web UI and JSON API for scanning from a browser.
    Serve(ServeArgs),
    /// List every device ever seen, marking which are online now.
    Inventory(InventoryArgs),
}

/// Arguments for the `inventory` subcommand.
#[derive(clap::Args)]
struct InventoryArgs {
    /// Only show devices that are currently offline (missing from the last scan).
    #[arg(long)]
    offline: bool,

    /// Emit the inventory as JSON instead of a table.
    #[arg(long)]
    json: bool,
}

/// Arguments for the `serve` subcommand.
#[derive(clap::Args)]
struct ServeArgs {
    #[command(flatten)]
    net: NetArgs,

    /// Address to bind (default: localhost only).
    #[arg(long, default_value = "127.0.0.1")]
    host: String,

    /// TCP port to listen on.
    #[arg(long, default_value_t = 8787)]
    port: u16,
}

/// Network-selection arguments shared by `scan` and `tui`.
#[derive(clap::Args)]
struct NetArgs {
    /// Network to scan in CIDR form (default: the local /24).
    #[arg(short, long)]
    cidr: Option<String>,

    /// Comma-separated TCP ports to probe (default: common services).
    #[arg(short, long)]
    ports: Option<String>,

    /// Per-connection timeout in milliseconds.
    #[arg(short, long, default_value_t = 400)]
    timeout_ms: u64,

    /// Maximum concurrent probes.
    #[arg(long, default_value_t = 256)]
    concurrency: usize,
}

/// Arguments for the `scan` subcommand.
#[derive(clap::Args)]
struct ScanArgs {
    #[command(flatten)]
    net: NetArgs,

    /// Only show hosts matching this text (case-insensitive) in any field:
    /// IP, MAC, hostname, vendor, or port/service.
    #[arg(short, long)]
    filter: Option<String>,

    /// Emit results as JSON instead of a table.
    #[arg(long)]
    json: bool,

    /// Do not record this scan into the device inventory.
    #[arg(long)]
    no_save: bool,
}

impl Default for NetArgs {
    fn default() -> Self {
        NetArgs {
            cidr: None,
            ports: None,
            timeout_ms: 400,
            concurrency: 256,
        }
    }
}

impl NetArgs {
    /// Resolve these arguments into a validated [`ScanConfig`].
    fn into_config(self) -> Result<ScanConfig, String> {
        let cidr = match self.cidr {
            Some(cidr) => cidr,
            None => default_cidr().ok_or("could not determine the local network; pass --cidr")?,
        };
        cidr_hosts(&cidr)?; // validate early for a clear error

        let ports = match self.ports {
            Some(spec) => parse_ports(&spec)?,
            None => DEFAULT_PORTS.to_vec(),
        };
        if ports.is_empty() {
            return Err("no ports to scan".to_string());
        }

        Ok(ScanConfig {
            cidr,
            ports,
            timeout: Duration::from_millis(self.timeout_ms),
            concurrency: self.concurrency.max(1),
        })
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command.unwrap_or_else(default_command) {
        Command::Scan(args) => run_scan(args),
        Command::Tui(net) => run_tui(net),
        Command::Mcp => lanscan::mcp::serve_stdio().map_err(|e| e.to_string()),
        Command::Serve(args) => run_serve(args),
        Command::Inventory(args) => run_inventory(args),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("lanscan: {message}");
            ExitCode::FAILURE
        }
    }
}

/// The action for a bare `lanscan` with no subcommand: the interactive TUI when
/// attached to a real terminal, otherwise a plain table scan so pipes, redirects,
/// scripts, and non-interactive SSH still get useful output instead of a crash.
fn default_command() -> Command {
    if std::io::stdout().is_terminal() {
        Command::Tui(NetArgs::default())
    } else {
        Command::Scan(ScanArgs {
            net: NetArgs::default(),
            filter: None,
            json: false,
            no_save: false,
        })
    }
}

fn run_scan(args: ScanArgs) -> Result<(), String> {
    let json = args.json;
    let filter = args.filter;
    let no_save = args.no_save;
    let cfg = args.net.into_config()?;
    if !json {
        eprintln!("Scanning {} ...", cfg.cidr);
    }
    let mut hosts = scan(&cfg);
    // Record the full result set (pre-filter) so the inventory reflects the
    // whole network, then narrow the display to the filter.
    if !no_save {
        lanscan::inventory::persist_scan(&hosts);
    }
    if let Some(needle) = &filter {
        hosts.retain(|host| host.matches(needle));
    }
    if json {
        println!("{}", to_json(&hosts).map_err(|e| e.to_string())?);
    } else {
        println!("{}", to_table(&hosts));
    }
    Ok(())
}

fn run_tui(net: NetArgs) -> Result<(), String> {
    let cfg = net.into_config()?;
    lanscan::tui::run(cfg).map_err(|e| e.to_string())
}

fn run_serve(args: ServeArgs) -> Result<(), String> {
    let host = args.host.clone();
    let port = args.port;
    let cfg = args.net.into_config()?;
    lanscan::serve::run(cfg, &host, port).map_err(|e| e.to_string())
}

fn run_inventory(args: InventoryArgs) -> Result<(), String> {
    use lanscan::inventory::{Inventory, default_path};

    let Some(path) = default_path() else {
        return Err("no home directory; set LANSCAN_INVENTORY to a file path".to_string());
    };
    let inventory = Inventory::load(&path);
    let now = lanscan::inventory::now_secs();

    let mut devices = inventory.sorted();
    if args.offline {
        devices.retain(|device| !inventory.is_online(device));
    }

    if args.json {
        let rows: Vec<_> = devices
            .iter()
            .map(|device| {
                serde_json::json!({
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
        println!(
            "{}",
            serde_json::to_string_pretty(&rows).map_err(|e| e.to_string())?
        );
        return Ok(());
    }

    if devices.is_empty() {
        println!("No devices recorded yet. Run `lanscan scan` first.");
        return Ok(());
    }

    println!(
        "{:<8}  {:<15}  {:<17}  {:<18}  {:<18}  LAST SEEN",
        "STATUS", "IP", "MAC", "HOSTNAME", "VENDOR"
    );
    for device in &devices {
        let status = if inventory.is_online(device) {
            "online".to_string()
        } else {
            "offline".to_string()
        };
        let seen = if inventory.is_online(device) {
            "now".to_string()
        } else {
            ago(now.saturating_sub(device.last_seen))
        };
        println!(
            "{:<8}  {:<15}  {:<17}  {:<18}  {:<18}  {}",
            status,
            device.ip,
            device.mac.as_deref().unwrap_or("-"),
            trunc(device.hostname.as_deref().unwrap_or("-"), 18),
            trunc(device.vendor.as_deref().unwrap_or("-"), 18),
            seen,
        );
    }
    let online = devices.iter().filter(|d| inventory.is_online(d)).count();
    println!(
        "\n{} device(s): {online} online, {} offline.",
        devices.len(),
        devices.len() - online
    );
    Ok(())
}

/// Render a seconds duration as a compact "N unit ago" string.
fn ago(secs: u64) -> String {
    match secs {
        s if s < 60 => format!("{s}s ago"),
        s if s < 3_600 => format!("{}m ago", s / 60),
        s if s < 86_400 => format!("{}h ago", s / 3_600),
        s => format!("{}d ago", s / 86_400),
    }
}

/// Truncate a string to `width` characters, adding an ellipsis when clipped.
fn trunc(text: &str, width: usize) -> String {
    if text.chars().count() <= width {
        text.to_string()
    } else {
        let keep: String = text.chars().take(width.saturating_sub(1)).collect();
        format!("{keep}…")
    }
}
