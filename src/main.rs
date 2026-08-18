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

    /// Emit results as JSON instead of a table.
    #[arg(long)]
    json: bool,
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
            json: false,
        })
    }
}

fn run_scan(args: ScanArgs) -> Result<(), String> {
    let json = args.json;
    let cfg = args.net.into_config()?;
    if !json {
        eprintln!("Scanning {} ...", cfg.cidr);
    }
    let hosts = scan(&cfg);
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
