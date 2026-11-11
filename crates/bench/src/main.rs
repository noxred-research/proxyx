//! `proxyx-bench`: load tool for the pool gateway and the session proxy.
//!
//! Exit status: 0 when every request succeeded, 1 when a run had errors, 2 on
//! a startup or usage failure.

use std::process::ExitCode;

use clap::Parser as _;
use proxyx_bench::cli::{Cli, Command};
use proxyx_bench::report::Report;
use proxyx_bench::{gateway, session};

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("proxyx-bench: cannot start the async runtime: {e}");
            return ExitCode::from(2);
        }
    };
    let (json, outcome) = match &cli.command {
        Command::Gateway(args) => (args.common.json, runtime.block_on(gateway::run(args))),
        Command::Session(args) => (args.common.json, runtime.block_on(session::run(args))),
    };
    match outcome {
        Ok(report) => finish(&report, json),
        Err(e) => {
            eprintln!("proxyx-bench: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn finish(report: &Report, json: bool) -> ExitCode {
    let text = if json {
        match report.to_json() {
            Ok(t) => t,
            Err(e) => {
                eprintln!("proxyx-bench: cannot render the report: {e:#}");
                return ExitCode::from(2);
            }
        }
    } else {
        report.to_table()
    };
    println!("{text}");
    if report.total_errors() > 0 || report.total_requests() == 0 {
        eprintln!(
            "proxyx-bench: {} errors, {} successful requests",
            report.total_errors(),
            report.total_requests()
        );
        return ExitCode::from(1);
    }
    ExitCode::SUCCESS
}
