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
                let aws_cfg =
                    aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
                Ok(Self::S3(Box::new(S3Store {
                    client: aws_sdk_s3::Client::new(&aws_cfg),
                    aws_cfg,
                    bucket: config.traffic_views_bucket.clone(),
                    region: config.traffic_views_s3_region.clone(),
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
                let url = format!("https://{}.s3.{}.amazonaws.com/{key}", s3.bucket, s3.region);
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

fn azure_account_url(account: &str) -> String {
    format!("https://{account}.blob.core.windows.net")
}

fn s3_function_sql(url: &str, access_key: &str, secret_key: &str, token: &str) -> String {
    if token.is_empty() {
        format!("s3('{url}', '{access_key}', '{secret_key}', 'Parquet')")
    } else {
        format!("s3('{url}', '{access_key}', '{secret_key}', '{token}', 'Parquet')")
    }
}

/// No account key: ClickHouse falls back to its own (workload) identity.
fn azure_function_sql(account: &str, container: &str, key: &str) -> String {
    format!(
        "azureBlobStorage('{}', '{container}', '{key}', 'Parquet')",
        azure_account_url(account)
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

    let url = format!("https://{domain}/{key}");
    let expires = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before UNIX_EPOCH")
        .as_secs()
        + DOWNLOAD_URL_TTL_SECS as u64;

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
        .replace('/', "_")
        .replace('=', "~")
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let url = cloudfront_signed_url("cdn.example.test", "K2ABCDEF", &pem, "views/a.parquet")
            .expect("a configured key signs");
        let query = url.split_once('?').expect("query").1;
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
                    .replace('_', "/")
                    .replace('~', "="),
            )
            .expect("base64");
        let policy = format!(
            r#"{{"Statement":[{{"Resource":"https://cdn.example.test/views/a.parquet","Condition":{{"DateLessThan":{{"AWS:EpochTime":{expires}}}}}}}]}}"#
        );
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
