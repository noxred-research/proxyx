//! A traffic view export against a real ClickHouse and a real S3-API store:
//! the Parquet object ClickHouse writes holds every captured row, with the
//! capture id as text.
//!
//! ClickHouse 25.8 (the version the `backends` job pins) cannot write a `UUID`
//! column to Parquet; the export selects `toString(id)`.
//!
//! Needs `PROXYX_TEST_S3_ENDPOINT`, `PROXYX_TEST_S3_ACCESS_KEY`,
//! `PROXYX_TEST_S3_SECRET_KEY`, `PROXYX_TEST_CLICKHOUSE_URL` (a ClickHouse that
//! can reach the endpoint) and `PROXYX_CONTROL_CLICKHOUSE__LOCAL_SINGLE_NODE`;
//! skips without them.

use std::sync::Arc;
use std::time::Duration;

use aws_sdk_s3::config::{Credentials, Region};
use common::wire;
use figment::Figment;
use figment::providers::{Format as _, Toml};
use proxyx_control::capture_store::{CaptureStore, ClickHouseStore};
use proxyx_control::config::ControlConfig;
use proxyx_control::pipeline::ClickHouseSink;
use proxyx_control::pipeline::clickhouse::ClickHouseConfig;
use proxyx_control::view_store::ViewStore;
use proxyx_control::views::ExportOutcome;
use serde_json::json;
use uuid::Uuid;

mod support;
use support::*;

#[tokio::test]
async fn the_parquet_export_of_a_view_holds_every_row_with_text_ids() {
    let get = |name: &str| std::env::var(name).ok();
    let (Some(endpoint), Some(access), Some(secret), Some(url)) = (
        get("PROXYX_TEST_S3_ENDPOINT"),
        get("PROXYX_TEST_S3_ACCESS_KEY"),
        get("PROXYX_TEST_S3_SECRET_KEY"),
        get("PROXYX_TEST_CLICKHOUSE_URL"),
    ) else {
        eprintln!("SKIP: PROXYX_TEST_S3_* and PROXYX_TEST_CLICKHOUSE_URL are not set");
        return;
    };
    if std::env::var_os("PROXYX_CONTROL_CLICKHOUSE__LOCAL_SINGLE_NODE").is_none() {
        eprintln!("SKIP: PROXYX_CONTROL_CLICKHOUSE__LOCAL_SINGLE_NODE is not set");
        return;
    }
    let user = get("PROXYX_TEST_CLICKHOUSE_USER");
    let password = get("PROXYX_TEST_CLICKHOUSE_PASSWORD");

    // The tables expire rows older than 12 months: capture "now".
    let now = time::OffsetDateTime::now_utc().unix_timestamp_nanos() as i64;
    set_base_nanos(now - now % 1_000_000_000 - 3_600 * 1_000_000_000);

    let database = format!("pxt_{}", &Uuid::new_v4().simple().to_string()[..12]);
    let mut admin = clickhouse::Client::default().with_url(&url);
    if let Some(user) = &user {
        admin = admin.with_user(user);
    }
    if let Some(password) = &password {
        admin = admin.with_password(password);
    }
    admin
        .query(&format!("CREATE DATABASE {database}"))
        .execute()
        .await
        .unwrap();

    let config = ClickHouseConfig {
        url,
        database: Some(database.clone()),
        user,
        password,
        table: None,
        bulk_size: 500,
        flush_interval_secs: 1,
        max_buffer_bytes: 256 * 1024 * 1024,
        circuit_breaker_threshold: 5,
        circuit_breaker_reset_secs: 60,
    };
    let client = proxyx_control::runtime::clickhouse_client(&config);
    proxyx_control::migrations::run_clickhouse(&client)
        .await
        .unwrap();
    let store = ClickHouseStore::new(client);

    // Rows with every column kind of the table: header maps, bodies, a
    // nullable correlation id.
    let mut rich = capture(7);
    rich.request_headers = vec![
        wire::Header {
            name: "X-Trace".into(),
            value: "abc".into(),
        },
        wire::Header {
            name: "X-ProxyX-Agent".into(),
            value: "agent-7".into(),
        },
    ];
    rich.request_body = br#"{"query":"Hello World"}"#.to_vec().into();
    rich.request_body_size = 23;
    rich.response_body = br#"{"ok":true}"#.to_vec().into();
    rich.response_body_size = 11;
    let mut messages = series(6);
    messages.push(Message::Http(rich));
    let sent = messages.len();
    let sink = Arc::new(
        ClickHouseSink::new(
            config.clone(),
            Some("X-ProxyX-Agent".into()),
            None,
            None,
            None,
        )
        .unwrap(),
    );
    assert_eq!(deliver_via(sink, messages).await, sent);
    let expected: Vec<String> = {
        let mut ids: Vec<String> = (1..=6).chain([7]).map(|n| uuid_n(n).to_string()).collect();
        ids.sort();
        ids
    };

    // The object store: one bucket, the way the shared-instance setup uses it.
    let bucket = format!("pxt-{}", &Uuid::new_v4().simple().to_string()[..12]);
    let sdk = aws_sdk_s3::Client::from_conf(
        aws_sdk_s3::Config::builder()
            .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
            .region(Region::new("us-east-1"))
            .endpoint_url(&endpoint)
            .force_path_style(true)
            .credentials_provider(Credentials::new(&access, &secret, None, None, "test"))
            .build(),
    );
    sdk.create_bucket().bucket(&bucket).send().await.unwrap();
    let dir = std::env::temp_dir().join(format!("proxyx-export-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let credentials = dir.join("credentials");
    std::fs::write(
        &credentials,
        format!("access_key_id = {access}\nsecret_access_key = {secret}\n"),
    )
    .unwrap();
    let control: ControlConfig = Figment::new()
        .merge(Toml::string(&format!(
            "traffic_views_bucket = \"{bucket}\"\n\
             traffic_views_prefix = \"proxyx/\"\n\
             traffic_views_s3_profile = \"self-hosted\"\n\
             traffic_views_s3_endpoint = \"{endpoint}\"\n\
             traffic_views_s3_credentials_file = \"{}\"\n",
            credentials.display()
        )))
        .extract()
        .unwrap();
    control.validate_traffic_views().unwrap();
    let views = ViewStore::from_config(&control).await.unwrap();

    let dynamic: &dyn CaptureStore = &store;
    let exporter = dynamic.require_view_exporter().unwrap();
    for (name, query, want) in [
        ("all", tq(json!({})), expected.clone()),
        (
            "one run",
            branch(json!({ "source_id": "run-1" })),
            expected.clone(),
        ),
    ] {
        let key = format!("proxyx/traffic-views/acme/{}.parquet", Uuid::new_v4());
        let qid = format!("pxt-export-{}", Uuid::new_v4());
        exporter
            .submit(&control, &views, &query, &qid, &key)
            .await
            .unwrap_or_else(|error| panic!("{name}: submit: {error:#}"));

        let mut outcome = None;
        for _ in 0..120 {
            admin.query("SYSTEM FLUSH LOGS").execute().await.unwrap();
            if let Some(found) = exporter.outcome(&qid).await.unwrap() {
                outcome = Some(found);
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        match outcome.unwrap_or_else(|| panic!("{name}: the export did not finish")) {
            ExportOutcome::Finished => {}
            ExportOutcome::Failed(error) => panic!("{name}: the export failed: {error}"),
        }

        let object = format!("{endpoint}/{bucket}/{key}");
        let ids: Vec<String> = admin
            .query(&format!(
                "SELECT ifNull(id, '') AS id FROM s3('{object}', '{access}', '{secret}', 'Parquet') ORDER BY id"
            ))
            .fetch_all()
            .await
            .unwrap_or_else(|error| panic!("{name}: read back {key}: {error}"));
        assert_eq!(ids, want, "{name}");
    }

    admin
        .query(&format!("DROP DATABASE {database}"))
        .execute()
        .await
        .unwrap();
}
