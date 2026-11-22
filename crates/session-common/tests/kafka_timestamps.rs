//! The vendored Kafka client (`vendor/rskafka`) takes `std::time::SystemTime` where the upstream
//! release took a `chrono::DateTime<Utc>`. A record's creation time must reach a real broker and
//! come back to the millisecond, and `OffsetAt::Timestamp` must find a record by it.
//!
//! Skipped with a message unless `PROXYX_TEST_KAFKA_BROKERS` is set (see
//! `crates/control/tests/broker_kafka.rs` for a broker to start).

use std::time::{Duration, UNIX_EPOCH};

use rskafka::client::ClientBuilder;
use rskafka::client::partition::{Compression, OffsetAt, UnknownTopicHandling};
use rskafka::record::{Record, from_unix_millis, unix_millis};
use uuid::Uuid;

#[tokio::test]
async fn record_timestamps_round_trip_through_the_vendored_client() {
    let Ok(brokers) = std::env::var("PROXYX_TEST_KAFKA_BROKERS") else {
        eprintln!("SKIP: PROXYX_TEST_KAFKA_BROKERS is not set");
        return;
    };
    let client = ClientBuilder::new(brokers.split(',').map(str::to_owned).collect())
        .build()
        .await
        .expect("connect to the broker");
    let topic = format!("pxts-{}", Uuid::new_v4().simple());
    client
        .controller_client()
        .expect("controller client")
        .create_topic(&topic, 1, 1, 10_000)
        .await
        .expect("create the topic");
    let partition = client
        .partition_client(&topic, 0, UnknownTopicHandling::Retry)
        .await
        .expect("partition client");

    let first = UNIX_EPOCH + Duration::from_millis(1_700_000_000_123);
    let second = UNIX_EPOCH + Duration::from_millis(1_700_000_060_456);
    let record = |value: &[u8], timestamp| Record {
        key: None,
        value: Some(value.to_vec()),
        headers: Default::default(),
        timestamp,
    };
    partition
        .produce(
            vec![
                // Sub-millisecond parts are not sent: Kafka keeps milliseconds.
                record(b"first", first + Duration::from_micros(789)),
                record(b"second", second),
            ],
            Compression::NoCompression,
        )
        .await
        .expect("produce");

    let (records, _) = partition
        .fetch_records(0, 1..1_000_000, 1_000)
        .await
        .expect("fetch");
    let stamps: Vec<_> = records.iter().map(|r| r.record.timestamp).collect();
    assert_eq!(stamps, vec![first, second]);
    let found = partition
        .get_offset(OffsetAt::Timestamp(second))
        .await
        .expect("offset by timestamp");
    assert_eq!(
        found, 1,
        "the offset of the first record at or after the time"
    );
    for (at, offset) in [(first, 0), (first + Duration::from_millis(1), 1)] {
        assert_eq!(
            partition
                .get_offset(OffsetAt::Timestamp(at))
                .await
                .expect("offset by timestamp"),
            offset,
            "the offset of the first record at or after {at:?}"
        );
    }
}

/// The conversions behind the vendored client: Kafka's epoch milliseconds (not seconds or
/// microseconds), truncating sub-millisecond parts, rounding toward negative infinity before the
/// epoch. Runs without a broker.
#[test]
fn conversions_are_epoch_milliseconds_and_round_toward_negative_infinity() {
    let at = |millis: u64| UNIX_EPOCH + Duration::from_millis(millis);
    assert_eq!(
        unix_millis(UNIX_EPOCH + Duration::from_secs(1_700_000_000)),
        1_700_000_000_000
    );
    assert_eq!(unix_millis(at(1_700_000_000_123)), 1_700_000_000_123);
    assert_eq!(
        from_unix_millis(1_700_000_000_123),
        Some(UNIX_EPOCH + Duration::from_micros(1_700_000_000_123_000))
    );
    assert_eq!(unix_millis(UNIX_EPOCH + Duration::from_micros(1_999)), 1);
    assert_eq!(unix_millis(UNIX_EPOCH - Duration::from_micros(1)), -1);
    assert_eq!(unix_millis(UNIX_EPOCH - Duration::from_micros(1_000)), -1);
    assert_eq!(unix_millis(UNIX_EPOCH - Duration::from_micros(1_001)), -2);
    assert_eq!(
        unix_millis(UNIX_EPOCH - Duration::from_secs(86_400)),
        -86_400_000
    );
    for millis in [
        0,
        1,
        999,
        1_000,
        1_337,
        -1,
        -999,
        -1_000,
        -1_337,
        -86_400_000,
        1_700_000_000_123,
    ] {
        let time = from_unix_millis(millis).expect("representable");
        assert_eq!(unix_millis(time), millis, "round trip of {millis}");
    }
}
