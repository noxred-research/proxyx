//! OpenSearch and Elasticsearch behind one configuration: engine detection,
//! the `kind` check, and two index prefixes sharing one cluster.
//!
//! Needs `PROXYX_TEST_OPENSEARCH_URL` and/or `PROXYX_TEST_ELASTICSEARCH_URL`
//! (security off); an engine without a URL is skipped.

use proxyx_control::capture_store::opensearch::{install_templates, verify_templates};
use proxyx_control::capture_store::{OpenSearchConfig, SearchKind};
use uuid::Uuid;

fn engines() -> Vec<(SearchKind, String)> {
    let mut found = Vec::new();
    for (kind, var) in [
        (SearchKind::OpenSearch, "PROXYX_TEST_OPENSEARCH_URL"),
        (SearchKind::Elasticsearch, "PROXYX_TEST_ELASTICSEARCH_URL"),
    ] {
        match std::env::var(var) {
            Ok(url) => found.push((kind, url)),
            Err(_) => eprintln!("SKIP: {var} is not set"),
        }
    }
    found
}

fn config(url: &str, prefix: &str, kind: Option<SearchKind>) -> OpenSearchConfig {
    let mut config = OpenSearchConfig::new(url);
    config.index_prefix = prefix.to_owned();
    config.kind = kind;
    config.number_of_replicas = 0;
    config.request_timeout_secs = 120;
    config
}

async fn template_names(url: &str, pattern: &str) -> Vec<String> {
    let body: serde_json::Value = reqwest::get(format!("{url}/_index_template/{pattern}"))
        .await
        .expect("templates")
        .json()
        .await
        .expect("json");
    let mut names: Vec<String> = body["index_templates"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|t| t["name"].as_str().map(str::to_owned))
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn the_engine_is_detected_and_the_kind_setting_is_enforced() {
    for (kind, url) in engines() {
        let prefix = format!("pxk-{}", &Uuid::new_v4().simple().to_string()[..10]);
        // right kind, and no kind at all: both work
        install_templates(&config(&url, &prefix, Some(kind)))
            .await
            .expect("right kind");
        install_templates(&config(&url, &prefix, None))
            .await
            .expect("either kind");
        verify_templates(&config(&url, &prefix, Some(kind)))
            .await
            .expect("verify");
        // the other engine's name is refused, and nothing is installed under the new prefix
        let other = match kind {
            SearchKind::OpenSearch => SearchKind::Elasticsearch,
            SearchKind::Elasticsearch => SearchKind::OpenSearch,
        };
        let wrong = format!("pxk-{}", &Uuid::new_v4().simple().to_string()[..10]);
        let error = install_templates(&config(&url, &wrong, Some(other)))
            .await
            .expect_err("wrong kind");
        let text = format!("{error:#}");
        assert!(
            text.contains(other.as_str()) && text.contains(kind.as_str()),
            "{text}"
        );
        assert!(template_names(&url, &format!("{wrong}-*")).await.is_empty());
        assert!(
            verify_templates(&config(&url, &wrong, Some(other)))
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn two_prefixes_on_one_cluster_own_separate_templates() {
    for (kind, url) in engines() {
        let one = format!("pxk-{}", &Uuid::new_v4().simple().to_string()[..10]);
        let two = format!("pxk-{}", &Uuid::new_v4().simple().to_string()[..10]);
        install_templates(&config(&url, &one, Some(kind)))
            .await
            .expect("first");
        assert!(
            verify_templates(&config(&url, &two, Some(kind)))
                .await
                .is_err(),
            "the second namespace is not installed yet"
        );
        install_templates(&config(&url, &two, Some(kind)))
            .await
            .expect("second");
        verify_templates(&config(&url, &two, Some(kind)))
            .await
            .expect("second verifies");
        assert_eq!(
            template_names(&url, &format!("{one}-*")).await,
            vec![format!("{one}-http"), format!("{one}-ws")]
        );
        assert_eq!(
            template_names(&url, &format!("{two}-*")).await,
            vec![format!("{two}-http"), format!("{two}-ws")]
        );
        // installing the second left the first as it was
        verify_templates(&config(&url, &one, Some(kind)))
            .await
            .expect("first still verifies");
    }
}
