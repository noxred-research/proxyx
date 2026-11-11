//! Object store behind traffic view Parquet exports.
//!
//! ClickHouse writes the export itself through a table function; this
//! module only builds that function call and performs the small number of
//! direct object operations ProxyX needs: existence check, delete, and a
//! short-lived download URL.
//!
//! - **S3**: `s3()` with credentials from ProxyX's AWS chain (they appear in
//!   ClickHouse's query log — treat it as sensitive). Downloads are
//!   CloudFront-signed URLs.
//! - **Azure**: `azureBlobStorage()` with *no* credentials; ClickHouse
//!   authenticates with its own workload identity. ProxyX uses its own
//!   workload identity for HEAD/DELETE and user-delegation SAS URLs.

use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use aws_credential_types::provider::ProvideCredentials;
use azure_core::http::{RequestContent, StatusCode, Url, XmlFormat};
use azure_storage_blob::BlobServiceClient;
use azure_storage_blob::models::KeyInfo;
use azure_storage_sas::SasBuilder;
use time::{Duration, OffsetDateTime};

use crate::config::{ControlConfig, TrafficViewsBackend};

/// Lifetime of a download URL handed to callers.
const DOWNLOAD_URL_TTL_SECS: i64 = 3600;

pub enum ViewStore {
    // Boxed: `SdkConfig` makes the S3 variant ~3x the Azure one.
    S3(Box<S3Store>),
    Azure(AzureStore),
}

pub struct S3Store {
    aws_cfg: aws_config::SdkConfig,
    client: aws_sdk_s3::Client,
    bucket: String,
    region: String,
    endpoint: Option<reqwest::Url>,
    cloudfront_domain: String,
    cloudfront_key_pair_id: String,
    cloudfront_private_key: String,
}

pub struct AzureStore {
    account: String,
    container: String,
    service: BlobServiceClient,
}

impl ViewStore {
    pub async fn from_config(config: &ControlConfig) -> Result<Self> {
        match config.traffic_views_backend {
            TrafficViewsBackend::S3 => {
                let endpoint = config
                    .traffic_views_s3_endpoint
                    .as_deref()
                    .map(parse_s3_endpoint)
                    .transpose()?;
                let aws_cfg = aws_config::defaults(aws_config::BehaviorVersion::latest())
                    .region(aws_sdk_s3::config::Region::new(
                        config.traffic_views_s3_region.clone(),
                    ))
                    .load()
                    .await;
                let client_config = s3_client_config(&aws_cfg, endpoint.as_ref());
                Ok(Self::S3(Box::new(S3Store {
                    client: aws_sdk_s3::Client::from_conf(client_config),
                    aws_cfg,
                    bucket: config.traffic_views_bucket.clone(),
                    region: config.traffic_views_s3_region.clone(),
                    endpoint,
                    cloudfront_domain: config.cloudfront_domain.trim().to_owned(),
                    cloudfront_key_pair_id: config.cloudfront_key_pair_id.trim().to_owned(),
                    cloudfront_private_key: config.cloudfront_private_key.trim().to_owned(),
                })))
            }
            TrafficViewsBackend::Azure => {
                let account = config.traffic_views_azure_account.trim();
                anyhow::ensure!(
                    !account.is_empty(),
                    "traffic_views_backend=azure requires traffic_views_azure_account"
                );
                let credential = azure_identity::WorkloadIdentityCredential::new(None)
                    .context("creating Azure workload identity credential")?;
                let service = BlobServiceClient::new(
                    Url::parse(&azure_account_url(account))?,
                    Some(credential),
                    None,
                )
                .context("creating Azure blob service client")?;
                Ok(Self::Azure(AzureStore {
                    account: account.to_owned(),
                    container: config.traffic_views_bucket.clone(),
                    service,
                }))
            }
        }
    }

    /// Table-function expression ClickHouse inserts the Parquet export into.
    pub async fn export_target_sql(&self, key: &str) -> Result<String> {
        match self {
            Self::S3(s3) => {
                let url = s3_object_url(s3.endpoint.as_ref(), &s3.bucket, &s3.region, key)?;
                let creds = s3
                    .aws_cfg
                    .credentials_provider()
                    .context("no AWS credentials provider configured")?
                    .provide_credentials()
                    .await
                    .context("failed to resolve AWS credentials")?;
                Ok(s3_function_sql(
                    &url,
                    creds.access_key_id(),
                    creds.secret_access_key(),
                    creds.session_token().unwrap_or(""),
                ))
            }
            Self::Azure(az) => Ok(azure_function_sql(&az.account, &az.container, key)),
        }
    }

    /// Whether the export object exists. Any error other than "not found" is
    /// logged and reported as missing, so callers re-export instead of
    /// handing out a URL to a file that cannot be confirmed.
    pub async fn exists(&self, key: &str) -> bool {
        match self {
            Self::S3(s3) => s3
                .client
                .head_object()
                .bucket(&s3.bucket)
                .key(key)
                .send()
                .await
                .is_ok(),
            Self::Azure(az) => match az.service.blob_client(&az.container, key).exists().await {
                Ok(exists) => exists,
                Err(e) => {
                    tracing::warn!(key, error = %e, "azure blob existence check failed");
                    false
                }
            },
        }
    }

    /// Delete the export object. Deleting an object that is already gone
    /// succeeds, so concurrent reapers on several API replicas are safe.
    pub async fn delete(&self, key: &str) -> Result<()> {
        match self {
            Self::S3(s3) => {
                // S3 DeleteObject is already idempotent for missing keys.
                s3.client
                    .delete_object()
                    .bucket(&s3.bucket)
                    .key(key)
                    .send()
                    .await
                    .context("S3 DeleteObject failed")?;
            }
            Self::Azure(az) => {
                match az
                    .service
                    .blob_client(&az.container, key)
                    .delete(None)
                    .await
                {
                    Ok(_) => {}
                    Err(e) if e.http_status() == Some(StatusCode::NotFound) => {}
                    Err(e) => return Err(e).context("Azure blob delete failed"),
                }
            }
        }
        Ok(())
    }

    /// Short-lived read URL for a completed export. `None` when the backend
    /// cannot sign (S3 without CloudFront config, or an Azure signing error).
    pub async fn download_url(&self, key: &str) -> Option<String> {
        match self {
            Self::S3(s3) => cloudfront_signed_url(
                &s3.cloudfront_domain,
                &s3.cloudfront_key_pair_id,
                &s3.cloudfront_private_key,
                key,
            ),
            Self::Azure(az) => match azure_sas_url(az, key).await {
                Ok(url) => Some(url),
                Err(e) => {
                    tracing::warn!(key, error = %e, "azure SAS URL generation failed");
                    None
                }
            },
        }
    }
}

fn parse_s3_endpoint(endpoint: &str) -> Result<reqwest::Url> {
    let mut url = reqwest::Url::parse(endpoint).context("invalid traffic_views_s3_endpoint URL")?;
    let authority = endpoint
        .split_once("://")
        .and_then(|(_, rest)| rest.split('/').next())
        .context("traffic_views_s3_endpoint must include an HTTP(S) authority")?;
    anyhow::ensure!(
        !endpoint.is_empty()
            && !endpoint.chars().any(char::is_control)
            && endpoint.trim() == endpoint
            && matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && !authority.is_empty()
            && !authority.contains('@')
            && url.query().is_none()
            && url.fragment().is_none(),
        "traffic_views_s3_endpoint must be an HTTP(S) URL without userinfo, query, or fragment"
    );
    // The SDK concatenates the bucket with this prefix; keep its separator.
    if !url.path().ends_with('/') {
        url.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("traffic_views_s3_endpoint cannot hold path segments"))?
            .push("");
    }
    Ok(url)
}

fn s3_client_config(
    aws_cfg: &aws_config::SdkConfig,
    endpoint: Option<&reqwest::Url>,
) -> aws_sdk_s3::Config {
    let mut builder = aws_sdk_s3::config::Builder::from(aws_cfg);
    if let Some(endpoint) = endpoint {
        builder = builder
            .endpoint_url(endpoint.as_str())
            .force_path_style(true);
    }
    builder.build()
}

fn s3_object_url(
    endpoint: Option<&reqwest::Url>,
    bucket: &str,
    region: &str,
    key: &str,
) -> Result<String> {
    let Some(endpoint) = endpoint else {
        let mut url = reqwest::Url::parse(&format!("https://{bucket}.s3.{region}.amazonaws.com/"))?;
        url.path_segments_mut()
            .map_err(|_| anyhow::anyhow!("S3 URL cannot hold path segments"))?
            .extend(key.split('/'));
        return Ok(url.into());
    };
    let mut url = endpoint.clone();
    url.path_segments_mut()
        .map_err(|_| anyhow::anyhow!("traffic_views_s3_endpoint cannot hold path segments"))?
        .pop_if_empty()
        .push(bucket)
        .extend(key.split('/'));
    Ok(url.into())
}

fn sql_string_literal(value: &str) -> String {
    let mut literal = String::with_capacity(value.len() + 2);
    literal.push('\'');
    for character in value.chars() {
        if matches!(character, '\\' | '\'') {
            literal.push('\\');
        }
        literal.push(character);
    }
    literal.push('\'');
    literal
}

fn azure_account_url(account: &str) -> String {
    format!("https://{account}.blob.core.windows.net")
}

fn s3_function_sql(url: &str, access_key: &str, secret_key: &str, token: &str) -> String {
    let url = sql_string_literal(url);
    let access_key = sql_string_literal(access_key);
    let secret_key = sql_string_literal(secret_key);
    if token.is_empty() {
        format!("s3({url}, {access_key}, {secret_key}, 'Parquet')")
    } else {
        let token = sql_string_literal(token);
        format!("s3({url}, {access_key}, {secret_key}, {token}, 'Parquet')")
    }
}

/// No account key: ClickHouse falls back to its own (workload) identity.
fn azure_function_sql(account: &str, container: &str, key: &str) -> String {
    format!(
        "azureBlobStorage({}, {}, {}, 'Parquet')",
        sql_string_literal(&azure_account_url(account)),
        sql_string_literal(container),
        sql_string_literal(key),
    )
}

async fn azure_sas_url(az: &AzureStore, key: &str) -> Result<String> {
    let now = OffsetDateTime::now_utc();
    let expiry = now + Duration::seconds(DOWNLOAD_URL_TTL_SECS);
    let key_info: RequestContent<KeyInfo, XmlFormat> = KeyInfo {
        start: Some(now),
        expiry: Some(expiry),
        ..Default::default()
    }
    .try_into()?;
    let udk = az
        .service
        .get_user_delegation_key(key_info, None)
        .await
        .context("fetching user delegation key")?
        .into_model()?;
    let token = SasBuilder::new(az.account.as_str(), &udk, expiry)?
        .blob(az.container.as_str(), key)
        .read()
        .build();
    let mut url = az.service.blob_client(&az.container, key).url().clone();
    url.set_query(Some(&token));
    Ok(url.to_string())
}

/// CloudFront signed URL (canned policy, SHA1-RSA). `None` when CloudFront
/// is not configured (local/dev) or the key cannot be parsed.
fn cloudfront_signed_url(domain: &str, key_pair_id: &str, pem: &str, key: &str) -> Option<String> {
    if domain.is_empty() || key_pair_id.is_empty() || pem.is_empty() {
        return None;
    }

    let mut url = reqwest::Url::parse(&format!("https://{domain}/")).ok()?;
    url.path_segments_mut().ok()?.extend(key.split('/'));
    if url.path().contains('*') {
        url.set_path(&url.path().replace('*', "%2A"));
    }
    let expires =
        SystemTime::now().duration_since(UNIX_EPOCH).ok()?.as_secs() + DOWNLOAD_URL_TTL_SECS as u64;

    let policy = format!(
        r#"{{"Statement":[{{"Resource":"{url}","Condition":{{"DateLessThan":{{"AWS:EpochTime":{expires}}}}}}}]}}"#
    );

    use rsa::pkcs1::DecodeRsaPrivateKey as _;
    use rsa::pkcs8::DecodePrivateKey as _;
    let private_key = rsa::PrivateKey::from_pkcs1_pem(pem)
        .or_else(|_| rsa::PrivateKey::from_pkcs8_pem(pem))
        .ok()?;

    const SHA1_DI: &[u8] = &[
        0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
    ];
    use sha1::Digest as _;
    let hash = sha1::Sha1::digest(policy.as_bytes());
    let mut digest_input = SHA1_DI.to_vec();
    digest_input.extend_from_slice(&hash);

    let sig = private_key
        .sign(rsa::pkcs1v15::Pkcs1v15Sign::new_unprefixed(), &digest_input)
        .ok()?;
    let sig_b64 = cf_base64(&sig);

    Some(format!(
        "{url}?Expires={expires}&Signature={sig_b64}&Key-Pair-Id={key_pair_id}"
    ))
}

fn cf_base64(bytes: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    STANDARD
        .encode(bytes)
        .replace('+', "-")
        .replace('/', "~")
        .replace('=', "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_default_url_keeps_aws_virtual_host() {
        assert_eq!(
            s3_object_url(None, "traffic-views", "eu-west-1", "org/view.parquet").unwrap(),
            "https://traffic-views.s3.eu-west-1.amazonaws.com/org/view.parquet"
        );
        assert_eq!(
            s3_function_sql("https://bucket/key", "access", "secret", ""),
            "s3('https://bucket/key', 'access', 'secret', 'Parquet')"
        );
    }

    #[test]
    fn s3_default_url_encodes_key_segments() {
        assert_eq!(
            s3_object_url(
                None,
                "traffic-views",
                "eu-west-1",
                "org/a b?#%\\\"é.parquet",
            )
            .unwrap(),
            "https://traffic-views.s3.eu-west-1.amazonaws.com/org/a%20b%3F%23%25%5C%22%C3%A9.parquet"
        );
    }

    #[test]
    fn s3_custom_url_preserves_prefix_and_encodes_segments() {
        for endpoint in [
            "http://minio:9000",
            "http://minio:9000/",
            "https://minio:9000/storage",
            "https://minio:9000/storage/",
        ] {
            let endpoint = parse_s3_endpoint(endpoint).unwrap();
            let url = s3_object_url(
                Some(&endpoint),
                "bucket/name",
                "us-east-1",
                "org/a b?#%\\é.parquet",
            )
            .unwrap();
            let prefix = if endpoint.scheme() == "https" {
                "https://minio:9000/storage"
            } else {
                "http://minio:9000"
            };
            assert_eq!(
                url,
                format!("{prefix}/bucket%2Fname/org/a%20b%3F%23%25%5C%C3%A9.parquet")
            );
        }
    }

    #[test]
    fn s3_endpoint_rejects_malformed_or_ambiguous_urls() {
        for endpoint in [
            "",
            "minio:9000",
            "not a url",
            "ftp://minio/storage",
            "http://",
            "http://minio:invalid",
            "http://user@minio",
            "http://user:password@minio",
            "http://@minio",
            "http://minio?query",
            "http://minio?",
            "http://minio#fragment",
            "http://minio#",
            " http://minio",
            "http://minio ",
        ] {
            assert!(parse_s3_endpoint(endpoint).is_err(), "{endpoint:?}");
        }
    }

    #[tokio::test]
    async fn s3_sdk_uses_custom_endpoint_path_style_and_configured_region() {
        let aws_cfg = aws_config::SdkConfig::builder()
            .region(aws_sdk_s3::config::Region::new("ap-southeast-2"))
            .credentials_provider(
                aws_credential_types::provider::SharedCredentialsProvider::new(
                    aws_credential_types::Credentials::new("access", "secret", None, None, "test"),
                ),
            )
            .behavior_version(aws_config::BehaviorVersion::latest())
            .build();
        for endpoint in ["http://minio:9000/storage", "http://minio:9000/storage/"] {
            let endpoint = parse_s3_endpoint(endpoint).unwrap();
            let client_config = s3_client_config(&aws_cfg, Some(&endpoint));
            assert_eq!(client_config.region().unwrap().as_ref(), "ap-southeast-2");
            let client = aws_sdk_s3::Client::from_conf(client_config);
            let signed = client
                .head_object()
                .bucket("traffic-views")
                .key("org/view.parquet")
                .presigned(
                    aws_sdk_s3::presigning::PresigningConfig::expires_in(
                        std::time::Duration::from_secs(60),
                    )
                    .unwrap(),
                )
                .await
                .unwrap();
            let url = reqwest::Url::parse(signed.uri()).unwrap();
            assert_eq!(url.host_str(), Some("minio"));
            assert_eq!(url.port(), Some(9000));
            assert_eq!(url.path(), "/storage/traffic-views/org/view.parquet");
            assert!(url.query_pairs().any(|(name, value)| {
                name == "X-Amz-Credential" && value.ends_with("/ap-southeast-2/s3/aws4_request")
            }));
            assert_eq!(
                s3_object_url(
                    Some(&endpoint),
                    "traffic-views",
                    "ap-southeast-2",
                    "org/view.parquet",
                )
                .unwrap(),
                format!("http://minio:9000{}", url.path()),
            );
        }
    }

    #[test]
    fn export_sql_escapes_all_string_literals() {
        assert_eq!(sql_string_literal("a\\'b"), r"'a\\\'b'");
        assert_eq!(
            s3_function_sql("url\\'", "access\\'", "secret\\'", "token\\'"),
            r"s3('url\\\'', 'access\\\'', 'secret\\\'', 'token\\\'', 'Parquet')"
        );
        assert_eq!(
            s3_function_sql("url\\'", "access\\'", "secret\\'", ""),
            r"s3('url\\\'', 'access\\\'', 'secret\\\'', 'Parquet')"
        );
        assert_eq!(
            azure_function_sql("account\\'", "container\\'", "key\\'"),
            r"azureBlobStorage('https://account\\\'.blob.core.windows.net', 'container\\\'', 'key\\\'', 'Parquet')"
        );
        let key = "org/x'); SELECT 1 --\\";
        let url = s3_object_url(None, "bucket", "us-east-1", key).unwrap();
        assert_eq!(
            s3_function_sql(&url, "access", "secret", ""),
            r"s3('https://bucket.s3.us-east-1.amazonaws.com/org/x\');%20SELECT%201%20--%5C', 'access', 'secret', 'Parquet')"
        );
    }

    #[test]
    fn azure_export_target_carries_no_credentials() {
        let sql = azure_function_sql(
            "exampleaccount",
            "traffic-views",
            "traffic-views/org-1/view.parquet",
        );
        assert_eq!(
            sql,
            "azureBlobStorage('https://exampleaccount.blob.core.windows.net', \
             'traffic-views', 'traffic-views/org-1/view.parquet', 'Parquet')"
        );
    }

    #[test]
    fn cloudfront_base64_matches_aws_alphabet() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};

        assert_eq!(STANDARD.encode(b"\xfb\xff"), "+/8=");
        assert_eq!(cf_base64(b"\xfb\xff"), "-~8_");
    }

    /// The signed URL verifies with the key pair's public key over CloudFront's canned
    /// policy, PKCS#1 v1.5 with a SHA-1 digest, in CloudFront's URL-safe base64.
    #[test]
    fn cloudfront_signature_verifies_with_the_public_key() {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use rsa::Generate as _;
        use rsa::pkcs8::{EncodePrivateKey as _, LineEnding};
        use sha1::Digest as _;

        let key = rsa::PrivateKey::generate();
        let pem = key.to_pkcs8_pem(LineEnding::LF).expect("pem");
        for (object_key, resource) in [
            (
                "views/a.parquet",
                "https://cdn.example.test/views/a.parquet",
            ),
            (
                "views/a b?#%\\\"*é.parquet",
                "https://cdn.example.test/views/a%20b%3F%23%25%5C%22%2A%C3%A9.parquet",
            ),
        ] {
            let url = cloudfront_signed_url("cdn.example.test", "K2ABCDEF", &pem, object_key)
                .expect("a configured key signs");
            let (signed_resource, query) = url.split_once('?').expect("query");
            assert_eq!(signed_resource, resource);
            let parsed = reqwest::Url::parse(&url).expect("URL");
            assert!(parsed.fragment().is_none());
            assert_eq!(parsed.query_pairs().count(), 3);
            let param = |name: &str| {
                query
                    .split('&')
                    .find_map(|kv| kv.strip_prefix(name)?.strip_prefix('='))
                    .expect(name)
                    .to_owned()
            };
            assert_eq!(param("Key-Pair-Id"), "K2ABCDEF");
            let expires = param("Expires");
            let signature = STANDARD
                .decode(
                    param("Signature")
                        .replace('-', "+")
                        .replace('_', "=")
                        .replace('~', "/"),
                )
                .expect("base64");
            let policy = format!(
                r#"{{"Statement":[{{"Resource":"{resource}","Condition":{{"DateLessThan":{{"AWS:EpochTime":{expires}}}}}}}]}}"#
            );
            let parsed_policy: serde_json::Value =
                serde_json::from_str(&policy).expect("policy JSON");
            assert_eq!(parsed_policy["Statement"][0]["Resource"], resource);
            let mut digest_info = vec![
                0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04,
                0x14,
            ];
            digest_info.extend_from_slice(&sha1::Sha1::digest(policy.as_bytes()));
            key.to_public_key()
                .verify(
                    rsa::pkcs1v15::Pkcs1v15Sign::new_unprefixed(),
                    &digest_info,
                    &signature,
                )
                .expect("signature verifies");
            // A different policy (another expiry) does not verify.
            let mut tampered = digest_info.clone();
            if let Some(last) = tampered.last_mut() {
                *last ^= 1;
            }
            assert!(
                key.to_public_key()
                    .verify(
                        rsa::pkcs1v15::Pkcs1v15Sign::new_unprefixed(),
                        &tampered,
                        &signature
                    )
                    .is_err()
            );
        }
    }
}
