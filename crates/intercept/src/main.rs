//! `proxyx-intercept`: the session proxy as its own binary.
//!
//! It is not a `proxyx` subcommand because its upstream TLS stack (BoringSSL,
//! for browser-grade fingerprints) exports the same C symbols as the OpenSSL
//! that the control plane's Kafka consumer links; one process cannot hold both.

use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Parser)]
#[command(
    name = "proxyx-intercept",
    version,
    about = "ProxyX session proxy: per-session routing, TLS interception and capture"
)]
struct Args {
    /// Configuration file; overrides the environment (`PROXYX_INTERCEPT_*`).
    #[arg(short, long, global = true)]
    config: Option<String>,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Check the configuration and what the proxy needs (Redis, broker, CA, ports)
    /// without starting it. Exit code 0: all clear, 1: a failure, 2: only warnings.
    Doctor(proxyx_intercept::doctor::DoctorArgs),
}

#[tokio::main]
async fn main() -> anyhow::Result<ExitCode> {
    let args = Args::parse();
    match args.command {
        None => {
            proxyx_intercept::run(args.config.as_deref()).await?;
            Ok(ExitCode::SUCCESS)
        }
        Some(Command::Doctor(doctor)) => {
            let code = proxyx_intercept::doctor::run(args.config.as_deref(), doctor).await;
            Ok(ExitCode::from(u8::try_from(code).unwrap_or(1)))
        }
    }
}
