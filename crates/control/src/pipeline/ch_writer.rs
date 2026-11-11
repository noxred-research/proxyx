//! ClickHouse [`BatchWriter`]: one `INSERT` per flush.

use std::marker::PhantomData;

use super::batch_handler::{BatchWriter, FlushTarget, WriteOutcome};

/// A [`FlushTarget`] whose docs become ClickHouse rows.
pub(crate) trait ChTarget: FlushTarget {
    /// ClickHouse row type. Must implement `clickhouse::RowWrite` (typically
    /// derived via `#[derive(clickhouse::Row, serde::Serialize)]`).
    type Row: clickhouse::Row
        + clickhouse::RowOwned
        + clickhouse::RowWrite
        + serde::Serialize
        + Send
        + 'static;

    /// Build a CH-serializable row from a buffered document.
    fn to_row(doc: &Self::Doc) -> Self::Row;
}

/// Writes batches of `T` rows into one ClickHouse table.
pub(crate) struct ClickHouseWriter<T: ChTarget> {
    client: clickhouse::Client,
    table: String,
    _target: PhantomData<fn() -> T>,
}

impl<T: ChTarget> ClickHouseWriter<T> {
    pub(crate) fn new(client: clickhouse::Client, table: String) -> Self {
        Self {
            client,
            table,
            _target: PhantomData,
        }
    }
}

#[async_trait::async_trait]
impl<T: ChTarget> BatchWriter<T> for ClickHouseWriter<T> {
    fn flush_span(&self, rows: usize, bytes: u64) -> tracing::Span {
        tracing::info_span!(
            "clickhouse.flush",
            db.system = "clickhouse",
            db.collection.name = %self.table,
            rows = rows,
            bytes = bytes,
            trace_id = tracing::field::Empty,
        )
    }

    async fn write(&self, docs: &[T::Doc]) -> WriteOutcome {
        let mut insert = match self.client.insert::<T::Row>(&self.table).await {
            Ok(insert) => insert,
            Err(e) => {
                tracing::error!(
                    target_table = T::NAME,
                    error = %e,
                    "failed to create ClickHouse insert",
                );
                return WriteOutcome::failed(docs.len(), Vec::new(), e.into());
            }
        };

        // Index-based iteration: holding the slice iterator across the
        // `insert.write().await` is avoided, borrowing just `&docs[i]` (a
        // `Sync` doc) per row.
        //
        // F2.10: On per-row write failure, report that single poison doc and
        // continue building the rest of the batch. Only a whole-insert
        // failure (insert.end() / client.insert()) retries.
        let mut poison: Vec<(usize, String)> = Vec::new();
        #[allow(clippy::needless_range_loop)] // iterator form holds the slice across await
        for i in 0..docs.len() {
            let row = T::to_row(&docs[i]);
            if let Err(e) = insert.write(&row).await {
                poison.push((i, e.to_string()));
            }
        }

        match insert.end().await {
            Ok(()) => WriteOutcome {
                poison,
                ..WriteOutcome::default()
            },
            // Poison docs are not retried: they would fail again and wedge
            // the pipeline.
            Err(e) => WriteOutcome::failed(docs.len(), poison, e.into()),
        }
    }
}
