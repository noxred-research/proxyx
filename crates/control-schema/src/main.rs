use anyhow::{Context as _, Result, bail};

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("manifest") => write_manifest(args),
        Some(command) => bail!("unknown command `{command}`"),
        None => bail!("expected command: manifest"),
    }
}

fn write_manifest(mut args: impl Iterator<Item = String>) -> Result<()> {
    let mut out = None;
    let mut version = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" | "-o" => out = args.next(),
            "--version" => version = args.next(),
            other => bail!("unknown manifest argument `{other}`"),
        }
    }

    let out = out.context("--out is required")?;
    let version = version
        .or_else(|| std::env::var("PROVENANCE_ID").ok())
        .filter(|v| !v.trim().is_empty())
        .context("--version is required (or set PROVENANCE_ID)")?;
    let routing_url = std::env::var("PROXYX_SCHEMA_ROUTING_URL")
        .unwrap_or_else(|_| "http://localhost:9000/graphql".to_string());

    let manifest = serde_json::json!({
        "subgraph": "proxyx",
        "routing_url": routing_url,
        "schema": proxyx_control_graphql::federation_sdl(),
        "version": version.trim(),
    });

    std::fs::create_dir_all(&out)?;
    let path = std::path::Path::new(&out).join("proxyx.json");
    std::fs::write(&path, serde_json::to_vec(&manifest)?)?;
    eprintln!("Wrote proxyx manifest to {}", path.display());
    Ok(())
}
