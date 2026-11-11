//! Open a capture session, fetch a URL through it, close it and read the capture back.
//!
//! ```text
//! PROXYX_API=http://127.0.0.1:9000 PROXYX_SERVICE_KEY=pxk_... PROXYX_ORG=acme \
//!   cargo run -p proxyx-client --example capture_session -- https://example.com/
//! ```
//!
//! `PROXYX_HOSTS` (comma-separated patterns, default `*`) selects the captured hosts. The proxy
//! URL carries the session credential, so the example never prints it.

use std::time::Duration;

use proxyx_client::sessions::{CreateSessionRequest, SessionsClient};
use proxyx_client::traffic::{QueryBranch, TrafficQuery};

fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    std::env::var(name).map_err(|_| format!("set {name}").into())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args()
        .nth(1)
        .ok_or("usage: capture_session <url>")?;
    let org = required("PROXYX_ORG")?;
    let hosts = std::env::var("PROXYX_HOSTS").unwrap_or_else(|_| "*".to_owned());
    let source_id = format!("example-{}", std::process::id());

    let client = SessionsClient::new(&required("PROXYX_API")?, required("PROXYX_SERVICE_KEY")?)?;
    let request = CreateSessionRequest::new(org, "example", source_id.clone())
        .captured_hosts(hosts.split(',').map(str::trim).filter(|h| !h.is_empty()));
    let session = client.open_session(request).await?;
    println!("session expires at {} ms", session.expires_at_ms());

    let fetched = async {
        let response = session.http_client()?.get(&url).send().await?;
        let status = response.status();
        Ok::<_, proxyx_client::Error>((status, response.bytes().await?.len()))
    }
    .await;
    // Release the hold even if constructing the HTTP client or fetching the URL failed.
    session.end().await?;
    let (status, bytes) = fetched?;
    println!("{status} {url} ({bytes} bytes)");
    session
        .wait_all_processed(Duration::from_secs(60), Duration::from_millis(500))
        .await?;

    let query = TrafficQuery::new(vec![QueryBranch::for_source(source_id)]).limit(100);
    let page = client.search_requests(&query).await?;
    for item in &page.items {
        println!(
            "captured {} {}{} -> {}",
            item.method, item.host, item.path, item.status_code
        );
    }
    Ok(())
}
