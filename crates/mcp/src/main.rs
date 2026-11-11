//! `proxyx-mcp`: the MCP server as a standalone binary. The same code runs as `proxyx mcp`.

use clap::Parser;
use proxyx_mcp::McpArgs;

#[derive(Parser)]
#[command(
    name = "proxyx-mcp",
    version,
    about = "Model Context Protocol server for ProxyX: monitor, manage and configure the proxy from AI agents"
)]
struct Cli {
    #[command(flatten)]
    args: McpArgs,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // stdout is the protocol channel of the stdio transport: logs go to stderr only.
    proxyx_mcp::init_logging();
    proxyx_mcp::run(Cli::parse().args).await
}
