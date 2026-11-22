use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// High-level record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub key: Option<Vec<u8>>,
    pub value: Option<Vec<u8>>,
    pub headers: BTreeMap<String, Vec<u8>>,
    /// Record creation time. Kafka keeps millisecond precision; finer parts are dropped on write.
    pub timestamp: SystemTime,
}

/// Milliseconds since the Unix epoch, rounded toward negative infinity, saturating at the `i64`
/// range.
pub fn unix_millis(time: SystemTime) -> i64 {
    match time.duration_since(UNIX_EPOCH) {
        Ok(after) => i64::try_from(after.as_millis()).unwrap_or(i64::MAX),
        Err(err) => {
            let before = err.duration();
            let millis = i64::try_from(before.as_millis()).unwrap_or(i64::MAX);
            let rounded_up = if before.subsec_nanos() % 1_000_000 == 0 {
                millis
            } else {
                millis.saturating_add(1)
            };
            rounded_up.saturating_neg()
        }
    }
}

/// The instant `millis` milliseconds after the Unix epoch, or `None` if the platform cannot
/// represent it.
pub fn from_unix_millis(millis: i64) -> Option<SystemTime> {
    let magnitude = Duration::from_millis(millis.unsigned_abs());
    if millis >= 0 {
        UNIX_EPOCH.checked_add(magnitude)
    } else {
        UNIX_EPOCH.checked_sub(magnitude)
    }
}

impl Record {
    /// Returns the approximate uncompressed size of this [`Record`]
    pub fn approximate_size(&self) -> usize {
        self.key.as_ref().map(|k| k.len()).unwrap_or_default()
            + self.value.as_ref().map(|v| v.len()).unwrap_or_default()
            + self
                .headers
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>()
    }
}

/// Record that has offset information attached.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordAndOffset {
    pub record: Record,
    pub offset: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approximate_size() {
        let record = Record {
            key: Some(vec![0; 23]),
            value: Some(vec![0; 45]),
            headers: vec![("a".to_string(), vec![0; 5]), ("b".to_string(), vec![0; 7])]
                .into_iter()
                .collect(),
            timestamp: from_unix_millis(1337).unwrap(),
        };

        assert_eq!(record.approximate_size(), 23 + 45 + 1 + 5 + 1 + 7);
    }

    #[test]
    fn unix_millis_round_trips_and_floors() {
        for millis in [0, 1, 1337, -1, -1337, 1_700_000_000_123, -86_400_000] {
            assert_eq!(unix_millis(from_unix_millis(millis).unwrap()), millis);
        }
        // Sub-millisecond parts round toward negative infinity, like `timestamp_millis`.
        assert_eq!(unix_millis(UNIX_EPOCH + Duration::from_micros(1999)), 1);
        assert_eq!(unix_millis(UNIX_EPOCH - Duration::from_micros(1)), -1);
        assert_eq!(unix_millis(UNIX_EPOCH - Duration::from_micros(1000)), -1);
        assert_eq!(unix_millis(UNIX_EPOCH - Duration::from_micros(1001)), -2);
    }
}
