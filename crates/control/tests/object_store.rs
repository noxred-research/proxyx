//! Traffic view exports against a real S3-API store and a real ClickHouse.
//!
//! Needs `PROXYX_TEST_S3_ENDPOINT`, `PROXYX_TEST_S3_ACCESS_KEY`,
//! `PROXYX_TEST_S3_SECRET_KEY` and `PROXYX_TEST_CLICKHOUSE_URL` (a ClickHouse
//! that can reach the endpoint); the tests skip without them.

use aws_sdk_s3::config::{Credentials, Region};
use figment::Figment;
use figment::providers::{Format as _, Toml};
use proxyx_control::config::{ControlConfig, S3Profile};
use proxyx_control::view_store::ViewStore;
use uuid::Uuid;

struct Env {
    endpoint: String,
    access: String,
    secret: String,
    clickhouse: String,
}

fn env() -> Option<Env> {
    let get = |name: &str| std::env::var(name).ok();
    let found = (|| {
        Some(Env {
            endpoint: get("PROXYX_TEST_S3_ENDPOINT")?,
            access: get("PROXYX_TEST_S3_ACCESS_KEY")?,
            secret: get("PROXYX_TEST_S3_SECRET_KEY")?,
            clickhouse: get("PROXYX_TEST_CLICKHOUSE_URL")?,
        })
    })();
    if found.is_none() {
        eprintln!("SKIP: PROXYX_TEST_S3_* and PROXYX_TEST_CLICKHOUSE_URL are not set");
    }
    found
}

fn config(toml: &str) -> anyhow::Result<ControlConfig> {
    let config: ControlConfig = Figment::new().merge(Toml::string(toml)).extract()?;
    config.validate_traffic_views()?;
    Ok(config)
}

fn sdk(env: &Env) -> aws_sdk_s3::Client {
    let config = aws_sdk_s3::Config::builder()
        .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
        .region(Region::new("us-east-1"))
        .endpoint_url(&env.endpoint)
        .force_path_style(true)
        .credentials_provider(Credentials::new(
            &env.access,
            &env.secret,
            None,
            None,
            "test",
        ))
        .build();
    aws_sdk_s3::Client::from_conf(config)
}

async fn keys(client: &aws_sdk_s3::Client, bucket: &str, prefix: &str) -> Vec<String> {
    client
        .list_objects_v2()
        .bucket(bucket)
        .prefix(prefix)
        .send()
        .await
        .expect("list")
        .contents()
        .iter()
        .filter_map(|object| object.key().map(str::to_owned))
        .collect()
}

async fn export(env: &Env, store: &ViewStore, key: &str) {
    let target = store.export_target_sql(key).await.expect("target");
    clickhouse::Client::default()
        .with_url(&env.clickhouse)
        .query(&format!(
            "INSERT INTO FUNCTION {target} SELECT number AS n FROM numbers(25) \
             SETTINGS s3_truncate_on_insert = 1"
        ))
        .execute()
        .await
        .expect("ClickHouse writes the Parquet export to the object store");
}

fn store_config(env: &Env, bucket: &str, prefix: &str, credentials_file: &str) -> String {
    format!(
        "traffic_views_bucket = \"{bucket}\"\n\
         traffic_views_prefix = \"{prefix}\"\n\
         traffic_views_s3_profile = \"self-hosted\"\n\
         traffic_views_s3_endpoint = \"{}\"\n\
         traffic_views_s3_credentials_file = \"{credentials_file}\"\n",
        env.endpoint
    )
}

#[tokio::test]
async fn two_products_share_one_bucket_without_seeing_each_other() {
    let Some(env) = env() else { return };
    let bucket = format!("pxt-{}", &Uuid::new_v4().simple().to_string()[..12]);
    let client = sdk(&env);
    client
        .create_bucket()
        .bucket(&bucket)
        .send()
        .await
        .expect("bucket");
    let dir = std::env::temp_dir().join(format!("proxyx-os-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("dir");
    let file = dir.join("credentials");
    std::fs::write(
        &file,
        format!(
            "# test\naccess_key_id = {}\nsecret_access_key = {}\n",
            env.access, env.secret
        ),
    )
    .expect("credentials file");
    let file = file.display().to_string();

    let mine = ViewStore::from_config(
        &config(&store_config(&env, &bucket, "proxyx/", &file)).expect("config"),
    )
    .await
    .expect("store");
    let other = ViewStore::from_config(
        &config(&store_config(&env, &bucket, "crawlx/", &file)).expect("config"),
    )
    .await
    .expect("store");
    assert_eq!((mine.prefix(), other.prefix()), ("proxyx/", "crawlx/"));

    let view = Uuid::new_v4();
    let my_key = format!("{}traffic-views/acme/{view}.parquet", mine.prefix());
    let other_key = format!("{}traffic-views/acme/{view}.parquet", other.prefix());
    export(&env, &mine, &my_key).await;
    export(&env, &other, &other_key).await;

    // each product sees its own object through the SDK path ProxyX uses
    assert!(mine.exists(&my_key).await);
    assert!(other.exists(&other_key).await);
    assert_eq!(
        keys(&client, &bucket, "proxyx/").await,
        vec![my_key.clone()]
    );
    assert_eq!(
        keys(&client, &bucket, "crawlx/").await,
        vec![other_key.clone()]
    );

    // deleting is idempotent and stays inside the product's own key
    mine.delete(&my_key).await.expect("delete");
    mine.delete(&my_key)
        .await
        .expect("deleting a missing object succeeds");
    assert!(!mine.exists(&my_key).await);
    assert!(
        other.exists(&other_key).await,
        "the other product's export is untouched"
    );

    // the exported object is the Parquet file ClickHouse wrote
    let body = client
        .get_object()
        .bucket(&bucket)
        .key(&other_key)
        .send()
        .await
        .expect("get")
        .body
        .collect()
        .await
        .expect("body")
        .into_bytes();
    assert_eq!(&body[..4], b"PAR1");
    other.delete(&other_key).await.expect("delete");
    client
        .delete_bucket()
        .bucket(&bucket)
        .send()
        .await
        .expect("remove bucket");
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn a_wrong_credentials_file_fails_at_use_not_silently() {
    let Some(env) = env() else { return };
    let bucket = format!("pxt-{}", &Uuid::new_v4().simple().to_string()[..12]);
    sdk(&env)
        .create_bucket()
        .bucket(&bucket)
        .send()
        .await
        .expect("bucket");
    let dir = std::env::temp_dir().join(format!("proxyx-os-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("dir");
    let file = dir.join("credentials");
    std::fs::write(
        &file,
        format!(
            "access_key_id = nobody\nsecret_access_key = {}\n",
            Uuid::new_v4().simple()
        ),
    )
    .expect("file");
    let store = ViewStore::from_config(
        &config(&store_config(
            &env,
            &bucket,
            "proxyx/",
            &file.display().to_string(),
        ))
        .expect("config"),
    )
    .await
    .expect("store");
    // the SDK is refused by the store, so nothing is reported as present
    assert!(!store.exists("proxyx/traffic-views/acme/x.parquet").await);
    assert!(
        store
            .delete("proxyx/traffic-views/acme/x.parquet")
            .await
            .is_err()
    );
    sdk(&env)
        .delete_bucket()
        .bucket(&bucket)
        .send()
        .await
        .expect("remove bucket");
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn profile_and_prefix_combinations_are_validated_at_load_time() {
    let ok = |toml: &str| {
        config(toml).map(|c| (c.traffic_views_s3_profile(), c.traffic_views_path_style()))
    };
    assert_eq!(ok("").expect("defaults"), (S3Profile::Standard, false));
    assert_eq!(
        ok("traffic_views_s3_endpoint = \"http://minio:9000\"").expect("endpoint"),
        (S3Profile::Compatible, true)
    );
    assert_eq!(
        ok("traffic_views_s3_profile = \"edge\"\ntraffic_views_s3_endpoint = \"https://acct.example.test\"\ntraffic_views_s3_path_style = false")
            .expect("edge"),
        (S3Profile::Edge, false)
    );
    for (toml, why) in [
        (
            "traffic_views_s3_profile = \"standard\"\ntraffic_views_s3_endpoint = \"http://x:9000\"",
            "takes no",
        ),
        (
            "traffic_views_s3_profile = \"standard\"\ntraffic_views_s3_path_style = true",
            "path_style",
        ),
        (
            "traffic_views_s3_profile = \"edge\"",
            "needs traffic_views_s3_endpoint",
        ),
        (
            "traffic_views_s3_profile = \"self-hosted\"",
            "needs traffic_views_s3_endpoint",
        ),
        ("traffic_views_s3_profile = \"aws\"", "unknown variant"),
        ("traffic_views_prefix = \"/abs/\"", "traffic_views_prefix"),
        (
            "traffic_views_prefix = \"no-slash\"",
            "traffic_views_prefix",
        ),
        ("traffic_views_prefix = \"a/../b/\"", "traffic_views_prefix"),
        ("traffic_views_prefix = \"a*/\"", "traffic_views_prefix"),
        (
            "traffic_views_backend = \"azure\"\ntraffic_views_s3_endpoint = \"http://x\"",
            "s3\" only",
        ),
    ] {
        let error = ok(toml).expect_err(toml);
        assert!(format!("{error:#}").contains(why), "{toml}: {error:#}");
    }
    assert_eq!(
        ok("traffic_views_prefix = \"\"").expect("empty prefix").0,
        S3Profile::Standard
    );
    assert_eq!(
        ok("traffic_views_prefix = \"team/proxyx/\"")
            .expect("nested")
            .0,
        S3Profile::Standard
    );
}

#[test]
fn a_credentials_file_must_name_both_keys() {
    let dir = std::env::temp_dir().join(format!("proxyx-os-{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).expect("dir");
    for (text, why) in [
        ("access_key_id = a\n", "required"),
        ("secret_access_key = b\n", "required"),
        (
            "access_key_id = a\nsecret_access_key = b\nregion = x\n",
            "unknown name",
        ),
        ("access_key_id a\n", "name = value"),
    ] {
        let file = dir.join("c");
        std::fs::write(&file, text).expect("file");
        let error = proxyx_control::view_store::read_credentials_file(&file).expect_err(text);
        assert!(format!("{error:#}").contains(why), "{text}: {error:#}");
    }
    let _ = std::fs::remove_dir_all(dir);
}
