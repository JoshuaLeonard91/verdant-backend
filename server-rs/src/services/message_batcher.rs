//! Message batch-insert service. Coalesces concurrent
//! `POST /api/channels/:id/messages` inserts into a single
//! multi-row INSERT every ~`MAX_BATCH_WINDOW_MS` (or sooner if
//! `MAX_BATCH_ROWS` is reached). The batcher does not change the
//! external semantics: each call still awaits commit success
//! before the response goes out, but PG sees one INSERT for up
//! to N rows instead of N round-trips.
//!
//! Why: batching turns one backend slot into many message inserts
//! per flush window under transaction-mode pooling.
//!
//! Design:
//! - Single mpsc channel feeds a single drainer task. Cross-channel
//!   batches are fine: `pg::messages::insert_batch` pushes one
//!   `INSERT ... VALUES (..),(..)` and PG's parser/planner doesn't
//!   care that rows are for different channels.
//! - Per-message oneshot reply channel: every waiter learns its own
//!   commit result. A failed batch fails every waiter in it (which
//!   matches today's "INSERT failed → handler returns 500" behaviour).
//! - Window trigger: first message starts a `Sleep(WINDOW_MS)`; we
//!   flush when the timer fires OR the buffer hits `MAX_BATCH_ROWS`.

use sqlx::PgPool;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

use crate::services::pg::messages::{MessageRow, insert_batch};

/// Time window the batcher waits after the first enqueued row before
/// flushing. ~2ms is invisible to interactive chat send latency
/// (typical p50 send is ~30ms across HTTP + auth + permission +
/// Redis publish), so the trade is "+2ms latency for ≤MAX_BATCH_ROWS×
/// throughput per backend slot".
const MAX_BATCH_WINDOW_MS: u64 = 2;

/// Hard cap on rows per flush. PG handles thousands of rows in one
/// INSERT fine, but bigger batches mean longer-held backend
/// connection — under our 20-slot pooler we want flushes to release
/// the slot quickly. 128 lets a single flush absorb a sub-millisecond
/// burst from every connected user (1k WS users × ~1 msg/sec) without
/// holding the slot longer than ~1ms.
const MAX_BATCH_ROWS: usize = 128;

/// Bound on the in-flight queue. If senders enqueue faster than the
/// drainer flushes, .send().await applies backpressure and the
/// handler awaits — better than unbounded memory growth.
const CHANNEL_BUFFER: usize = 4096;

/// One pending message + its commit-result reply channel.
struct PendingInsert {
    row: MessageRow,
    reply: oneshot::Sender<Result<(), sqlx::Error>>,
}

/// Batcher handle. Cheap to clone — wraps a `mpsc::Sender`.
pub struct MessageBatcher {
    tx: mpsc::Sender<PendingInsert>,
}

impl MessageBatcher {
    /// Start the batcher's drainer task. Pool is cloned cheaply
    /// (sqlx::PgPool is internally Arc'd) and held by the task for
    /// the process lifetime.
    pub fn start(pool: PgPool) -> Arc<Self> {
        let (tx, rx) = mpsc::channel::<PendingInsert>(CHANNEL_BUFFER);
        tokio::spawn(drain_loop(rx, pool));
        Arc::new(Self { tx })
    }

    /// Boot-time placeholder used while AppState is built before the
    /// PG pool is ready. Returns a batcher whose `enqueue_and_wait`
    /// would deadlock — caller must replace with `start(pool)` once
    /// the pool exists. Kept only for state-init ergonomics; never
    /// reachable from the request path because AppState wires the
    /// real one before serving.
    pub fn placeholder() -> Arc<Self> {
        let (tx, _rx) = mpsc::channel::<PendingInsert>(1);
        Arc::new(Self { tx })
    }

    /// Enqueue a row and await its commit result. Suspends until the
    /// drainer flushes the batch containing this row and PG ACKs.
    /// Errors:
    /// - `Err("batcher closed")` if the drainer task died (process is
    ///    in trouble; caller should bail with 500).
    /// - `Err(<sqlx error>)` if the batch INSERT failed.
    pub async fn enqueue_and_wait(&self, row: MessageRow) -> Result<(), String> {
        let (reply_tx, reply_rx) = oneshot::channel();
        self.tx
            .send(PendingInsert {
                row,
                reply: reply_tx,
            })
            .await
            .map_err(|_| "message batcher closed".to_string())?;
        match reply_rx.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(e.to_string()),
            Err(_) => Err("message batcher dropped reply".to_string()),
        }
    }
}

/// Drain loop: pulls from the mpsc, accumulates up to MAX_BATCH_ROWS
/// or until WINDOW_MS elapses since the first row of the current
/// batch, then flushes. Repeats forever.
async fn drain_loop(mut rx: mpsc::Receiver<PendingInsert>, pool: PgPool) {
    let window = Duration::from_millis(MAX_BATCH_WINDOW_MS);

    loop {
        // Wait for the first row of the next batch (no timer running
        // yet — we don't burn CPU when idle).
        let first = match rx.recv().await {
            Some(p) => p,
            None => return, // sender side dropped; process shutdown
        };

        let mut batch: Vec<PendingInsert> = Vec::with_capacity(MAX_BATCH_ROWS);
        batch.push(first);

        // Drain anything queued up immediately (already-buffered
        // sends arrive without a context-switch). This catches the
        // common "a request burst lands while the previous batch was
        // mid-flush" pattern without paying the timer wait at all.
        while batch.len() < MAX_BATCH_ROWS {
            match rx.try_recv() {
                Ok(p) => batch.push(p),
                Err(_) => break,
            }
        }

        // If we're still under the cap, hold the batch open for the
        // window so concurrent senders can pile in.
        if batch.len() < MAX_BATCH_ROWS {
            let deadline = tokio::time::Instant::now() + window;
            loop {
                let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
                if remaining.is_zero() || batch.len() >= MAX_BATCH_ROWS {
                    break;
                }
                tokio::select! {
                    biased;
                    maybe_p = rx.recv() => match maybe_p {
                        Some(p) => batch.push(p),
                        None => break, // shutdown
                    },
                    _ = tokio::time::sleep(remaining) => break,
                }
            }
        }

        flush(&pool, batch).await;
    }
}

/// Push the batch as a single multi-row INSERT and fan out the result
/// to every waiter's oneshot. On error every waiter gets the error
/// string — matches the pre-batch "INSERT failed → handler returns
/// 500" behaviour.
async fn flush(pool: &PgPool, batch: Vec<PendingInsert>) {
    if batch.is_empty() {
        return;
    }
    let rows: Vec<MessageRow> = batch.iter().map(|p| p.row.clone()).collect();
    let started = std::time::Instant::now();
    let res = insert_batch(pool, &rows).await;
    let elapsed_ms = started.elapsed().as_millis();

    match &res {
        Ok(()) => {
            tracing::debug!(
                rows = rows.len(),
                elapsed_ms,
                "message_batcher: flushed batch"
            );
        }
        Err(e) => {
            tracing::error!(
                rows = rows.len(),
                elapsed_ms,
                error = %e,
                "message_batcher: flush failed; failing every waiter in this batch"
            );
        }
    }

    // Distribute the (cloned) result to every waiter. sqlx::Error is
    // not Clone, so we map to a string for the error case — callers
    // only need the message for logging anyway.
    for p in batch {
        let r = match &res {
            Ok(()) => Ok(()),
            Err(e) => Err(sqlx_string_error(e)),
        };
        let _ = p.reply.send(r);
    }
}

/// sqlx::Error is not Clone. Round-trip via Display preserves the
/// failing constraint name + SQLSTATE — enough for the handler's
/// error log.
fn sqlx_string_error(e: &sqlx::Error) -> sqlx::Error {
    sqlx::Error::Protocol(e.to_string())
}
