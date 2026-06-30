//! # Sharded Fan-Out Broadcast Service
//!
//! Replaces sequential `publish_local_proto_first` with a parallel worker pool
//! for the primary `publish()` path (events that have both proto + JSON payloads).
//!
//! ## Architecture
//!
//! ```text
//!   publish() called
//!     │
//!     ├─ Enqueue PendingPublish → coalescer task
//!     │
//!   coalescer task (5ms window)
//!     │
//!     ├─ Buffers publishes by topic → merges multi-publish bursts
//!     ├─ At tick or on burst threshold: resolves subscribers, partitions
//!     └─ Sends BroadcastWork (with Vec<Payload>) to each worker
//!           │
//!           ├─ Worker 0: [conn 0, conn 4, conn 8, ...]
//!           ├─ Worker 1: [conn 1, conn 5, conn 9, ...]
//!           ├─ Worker 2: [conn 2, conn 6, conn 10, ...]
//!           └─ Worker 3: [conn 3, conn 7, conn 11, ...]
//! ```
//!
//! ## Sharding Strategy
//!
//! Subscribers are partitioned across workers using `conn_id % num_workers`.
//! Connection IDs are monotonically increasing (AtomicU64), so this produces
//! an even distribution across workers. Each worker independently looks up
//! the connection's encoding and sender from the shared `ConnectionManager`,
//! then delivers the appropriate payload (proto or JSON) for every queued
//! payload in the work item.
//!
//! ## Coalescing Window (phase 2, 2026-04-11)
//!
//! `publish()` no longer dispatches inline. It enqueues a `PendingPublish`
//! onto the coalescer channel and returns immediately. A single coalescer
//! task drains the channel and buffers pending publishes in a
//! `HashMap<topic, Vec<Payload>>` for up to 5ms. When the tick fires (or
//! the buffer exceeds `MAX_PENDING_BEFORE_FLUSH`), the coalescer flushes
//! every topic: it resolves the current subscriber set, partitions by
//! worker, and sends one `BroadcastWork` per worker carrying ALL queued
//! payloads for that topic.
//!
//! The downstream worker loop still emits one `OutboundMsg` per payload
//! per connection. Commit A's `feed() + flush()` in the per-conn write
//! task then coalesces those N sends into a single TCP write per drain
//! batch — which is where the actual syscall reduction comes from.
//!
//! Commit C will introduce a `WsMessage::Batch` proto variant so the
//! worker can pack all payloads into a single frame for conns that
//! advertise `capabilities.batch_frames = true`.
//!
//! ## Backpressure
//!
//! Coalescer and worker queues are bounded. If fan-out workers fall behind,
//! the coalescer waits on worker capacity; if the coalescer falls behind,
//! callers of `publish()` await queue capacity. This keeps memory bounded
//! without silently dropping whole broadcast work items.
//!
//! ## Tuning `num_workers`
//!
//! - Defaults to `std::thread::available_parallelism()` (one per CPU core),
//!   with a minimum of 2.
//! - On a 1-core machine: 2 workers still help because each worker's delivery
//!   loop involves DashMap lookups (which may contend) and mpsc sends. Two
//!   workers interleave better than one sequential loop.
//! - On a 4-core machine: 4 workers, each handling ~25% of connections.
//!   The tokio runtime's work-stealing scheduler distributes these across cores.
//! - More workers than cores is wasteful — the extra workers just contend for
//!   CPU time. The default (one per core) is optimal for most workloads.
//!
//! ## When to Use This vs. `publish_local`
//!
//! - `BroadcastService::publish()` — used by `topics::publish()` for events
//!   that have both proto + JSON payloads. This is the hot path (message send,
//!   member updates, channel updates).
//! - `ConnectionManager::publish_local()` — used by `publish_json()` for
//!   JSON-only events (typing, presence) and by the Redis subscriber bridge.
//!   These are lower-volume and don't benefit from sharding.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{MissedTickBehavior, interval};

use crate::proto::{Batch, WsMessage, ws_message};
use crate::ws::ConnectionManager;
use crate::ws::connection::{Encoding, OutboundMsg};
use prost::Message as ProstMessage;

/// Coalescing window: how long the coalescer buffers pending publishes
/// before dispatching. Larger = better coalescing, more latency.
const COALESCE_WINDOW_MS: u64 = 5;

/// If total pending payloads across all topics exceeds this, flush early
/// even if the tick hasn't fired. Protects against memory spikes on bursts.
const MAX_PENDING_BEFORE_FLUSH: usize = 256;

/// Pending publish queue bound. At 256-payload early flushes, 8192 entries
/// gives enough burst absorption for deploy/reconnect spikes while preventing
/// process-wide unbounded memory growth.
const COALESCE_QUEUE_CAPACITY: usize = 8192;

/// Per-worker fan-out queue bound. Backpressure propagates from workers to the
/// coalescer and then to publishers when this fills.
const WORKER_QUEUE_CAPACITY: usize = 1024;

/// A single payload pair (proto + JSON) ready to deliver to subscribers.
#[derive(Clone)]
struct Payload {
    /// Pre-built protobuf payload (shared via Arc, zero-copy clone across workers).
    proto: Arc<[u8]>,
    /// JSON text (shared via Arc, only used if any connection uses JSON encoding).
    json_text: Arc<str>,
}

/// A broadcast work item. Carries BOTH delivery modes:
///
/// - `indiv_conn_ids` receive each payload as a separate OutboundMsg
///   (one frame per event). Used for legacy clients, JSON clients, or
///   when the burst has only a single payload.
/// - `batch_conn_ids` receive the single `batch_proto` frame (one
///   OutboundMsg total, regardless of how many events were coalesced).
///   Populated only when `payloads.len() > 1` AND at least one
///   protobuf+batch-capable conn exists in this partition.
struct BroadcastWork {
    payloads: Vec<Payload>,
    batch_proto: Option<Arc<[u8]>>,
    indiv_conn_ids: Vec<u64>,
    batch_conn_ids: Vec<u64>,
}

/// A publish waiting in the coalescer buffer. Topic is stored inline so
/// the coalescer can group by topic without a separate index.
struct PendingPublish {
    topic: String,
    payload: Payload,
}

/// Runtime counters for the broadcast fan-out pipeline. All fields are
/// cumulative since process start. Sampled by the orchestrator via
/// `GET /api/admin/broadcast-stats`; the diff across samples gives per-
/// second rates.
#[derive(Default)]
pub struct BroadcastStats {
    /// Total calls to `publish()` (one per broadcast to a topic).
    pub publishes_total: AtomicU64,
    /// Total per-connection deliveries dispatched from workers — i.e.
    /// the number of OutboundMsgs the workers handed to per-connection
    /// senders. Does NOT include per-conn queue overflows.
    pub deliveries_total: AtomicU64,
    /// Items dropped at the worker queue layer. Should stay 0; a non-zero
    /// value means a worker task exited and its bounded receiver closed.
    pub worker_drops_total: AtomicU64,
    /// Conn_info lookups that missed (race: connection disconnected
    /// between partition time and delivery). Lets us estimate how
    /// much of the fan-out budget is spent on zombies.
    pub lookup_misses_total: AtomicU64,
    /// Sum of per-publish partition times in microseconds. Divide by
    /// publishes_total to get the avg partition cost per publish.
    pub partition_us_sum: AtomicU64,
    /// Sum of per-publish total times in microseconds (partition +
    /// worker dispatch). Divide by publishes_total for the full cost.
    pub publish_us_sum: AtomicU64,
    /// Max number of items seen waiting in any worker channel at a
    /// publish moment. Grows with saturation — peaks reveal queue
    /// pressure.
    pub max_worker_pending: AtomicU64,
    /// Flush events where a topic had more than one queued payload
    /// (i.e. real coalescing happened). Divide
    /// `coalesced_payloads_total / coalesced_batches_total` for
    /// average merge depth.
    pub coalesced_batches_total: AtomicU64,
    /// Sum of payload counts across all coalesced (batch_size > 1)
    /// flushes. Pair with `coalesced_batches_total` for average merge
    /// depth.
    pub coalesced_payloads_total: AtomicU64,
    /// Total flush ticks the coalescer executed (includes no-op ticks
    /// when the buffer was empty). Gives a sanity check that the
    /// coalescer loop is alive.
    pub coalescer_ticks_total: AtomicU64,
    /// Total `WsMessage::Batch` frames dispatched (one per batch-capable
    /// conn per coalesced flush). Divide by `batch_frames_sent_total /
    /// coalesced_batches_total` to see how many conns used batching.
    pub batch_frames_sent_total: AtomicU64,
}

impl BroadcastStats {
    /// Snapshot all counters for JSON serialization.
    pub fn snapshot(&self) -> serde_json::Value {
        let pubs = self.publishes_total.load(Ordering::Relaxed);
        let dels = self.deliveries_total.load(Ordering::Relaxed);
        let worker_drops = self.worker_drops_total.load(Ordering::Relaxed);
        let lookup_misses = self.lookup_misses_total.load(Ordering::Relaxed);
        let partition_us_sum = self.partition_us_sum.load(Ordering::Relaxed);
        let publish_us_sum = self.publish_us_sum.load(Ordering::Relaxed);
        let max_pending = self.max_worker_pending.load(Ordering::Relaxed);
        let coalesced_batches = self.coalesced_batches_total.load(Ordering::Relaxed);
        let coalesced_payloads = self.coalesced_payloads_total.load(Ordering::Relaxed);
        let coalescer_ticks = self.coalescer_ticks_total.load(Ordering::Relaxed);
        let batch_frames_sent = self.batch_frames_sent_total.load(Ordering::Relaxed);
        let avg_partition_us = if pubs > 0 {
            partition_us_sum as f64 / pubs as f64
        } else {
            0.0
        };
        let avg_publish_us = if pubs > 0 {
            publish_us_sum as f64 / pubs as f64
        } else {
            0.0
        };
        let avg_coalesce_batch = if coalesced_batches > 0 {
            coalesced_payloads as f64 / coalesced_batches as f64
        } else {
            0.0
        };
        serde_json::json!({
            "publishes_total": pubs,
            "deliveries_total": dels,
            "worker_drops_total": worker_drops,
            "lookup_misses_total": lookup_misses,
            "avg_partition_us": avg_partition_us,
            "avg_publish_us": avg_publish_us,
            "max_worker_pending": max_pending,
            "coalesced_batches_total": coalesced_batches,
            "coalesced_payloads_total": coalesced_payloads,
            "avg_coalesce_batch_size": avg_coalesce_batch,
            "coalescer_ticks_total": coalescer_ticks,
            "batch_frames_sent_total": batch_frames_sent,
        })
    }
}

/// Sharded fan-out broadcast service.
///
/// Spawns N worker tasks (one per CPU core) + a single coalescer task.
/// Publishes enter the coalescer, get buffered for up to `COALESCE_WINDOW_MS`,
/// and then fan out across workers by `conn_id % num_workers`.
pub struct BroadcastService {
    /// Entry point from `publish()` — sends `PendingPublish` to the coalescer.
    coalesce_tx: mpsc::Sender<PendingPublish>,
    pub stats: Arc<BroadcastStats>,
}

impl BroadcastService {
    /// Start the broadcast worker pool + coalescer task.
    ///
    /// Spawns `num_workers` worker tasks with unbounded channels and one
    /// coalescer task that buffers publishes in a 5ms window before
    /// dispatching to workers.
    pub fn start(conn_manager: Arc<ConnectionManager>) -> Arc<Self> {
        let num_workers = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2)
            .max(2);

        let stats = Arc::new(BroadcastStats::default());
        let mut workers = Vec::with_capacity(num_workers);

        for worker_id in 0..num_workers {
            let (tx, mut rx) = mpsc::channel::<BroadcastWork>(WORKER_QUEUE_CAPACITY);
            let cm = conn_manager.clone();
            let worker_stats = stats.clone();

            tokio::spawn(async move {
                while let Some(work) = rx.recv().await {
                    let mut delivered: u64 = 0;
                    let mut misses: u64 = 0;
                    let mut batch_frames: u64 = 0;

                    // Path 1: individual frames. Each conn gets every
                    // payload as a separate OutboundMsg. The per-conn
                    // write task (commit A) coalesces these into one
                    // TCP write via feed()+flush().
                    for &conn_id in &work.indiv_conn_ids {
                        if let Some(info) = cm.conn_info.get(&conn_id) {
                            let is_proto = info.1 == Encoding::Protobuf;
                            let mut closed = false;
                            for payload in &work.payloads {
                                let msg = if is_proto {
                                    OutboundMsg::Binary(payload.proto.clone())
                                } else {
                                    OutboundMsg::Text(payload.json_text.clone())
                                };
                                if info.0.try_send(msg).is_ok() {
                                    delivered += 1;
                                } else {
                                    closed = true;
                                    break;
                                }
                            }
                            if closed {
                                continue;
                            }
                        } else {
                            misses += 1;
                        }
                    }

                    // Path 2: packed Batch frame. Each conn gets ONE
                    // OutboundMsg carrying the pre-encoded
                    // WsMessage::Batch (contains N inner messages).
                    if let Some(batch_bytes) = work.batch_proto.as_ref() {
                        for &conn_id in &work.batch_conn_ids {
                            if let Some(info) = cm.conn_info.get(&conn_id) {
                                if info
                                    .0
                                    .try_send(OutboundMsg::Binary(batch_bytes.clone()))
                                    .is_ok()
                                {
                                    delivered += 1;
                                    batch_frames += 1;
                                }
                            } else {
                                misses += 1;
                            }
                        }
                    }

                    if delivered > 0 {
                        worker_stats
                            .deliveries_total
                            .fetch_add(delivered, Ordering::Relaxed);
                    }
                    if misses > 0 {
                        worker_stats
                            .lookup_misses_total
                            .fetch_add(misses, Ordering::Relaxed);
                    }
                    if batch_frames > 0 {
                        worker_stats
                            .batch_frames_sent_total
                            .fetch_add(batch_frames, Ordering::Relaxed);
                    }
                }
                tracing::info!(worker_id, "Broadcast worker exited");
            });

            workers.push(tx);
        }

        let (coalesce_tx, coalesce_rx) = mpsc::channel::<PendingPublish>(COALESCE_QUEUE_CAPACITY);
        tokio::spawn(run_coalescer(
            coalesce_rx,
            conn_manager.clone(),
            workers,
            num_workers,
            stats.clone(),
        ));

        tracing::info!(
            num_workers,
            coalesce_window_ms = COALESCE_WINDOW_MS,
            "Broadcast worker pool + coalescer started"
        );
        Arc::new(Self { coalesce_tx, stats })
    }

    /// Enqueue a publish into the coalescing buffer.
    ///
    /// Returns immediately after enqueuing. The actual fan-out happens on
    /// the coalescer task within ~5ms. The returned `usize` is 1 if the
    /// publish was accepted (into the buffer) and 0 if the coalescer
    /// channel is closed — it is NOT the subscriber count.
    ///
    /// The `_conn_manager` parameter is kept for API compatibility with
    /// the pre-coalescer signature; the coalescer task holds its own
    /// reference and resolves subscribers at flush time.
    pub async fn publish(
        &self,
        _conn_manager: &ConnectionManager,
        topic: &str,
        proto_bytes: &[u8],
        json_text: &str,
    ) -> usize {
        let payload = Payload {
            proto: Arc::from(proto_bytes),
            json_text: Arc::from(json_text),
        };
        let pending = PendingPublish {
            topic: topic.to_string(),
            payload,
        };
        if self.coalesce_tx.send(pending).await.is_err() {
            tracing::error!("Coalescer channel closed — publish dropped");
            return 0;
        }
        self.stats.publishes_total.fetch_add(1, Ordering::Relaxed);
        1
    }
}

/// The coalescer task. Drains `rx`, buffers publishes per-topic for up to
/// `COALESCE_WINDOW_MS`, then dispatches merged work items to the worker
/// pool. Exits when the sender is dropped (process shutdown).
async fn run_coalescer(
    mut rx: mpsc::Receiver<PendingPublish>,
    conn_manager: Arc<ConnectionManager>,
    workers: Vec<mpsc::Sender<BroadcastWork>>,
    num_workers: usize,
    stats: Arc<BroadcastStats>,
) {
    let mut buffer: HashMap<String, Vec<Payload>> = HashMap::new();
    let mut pending_count: usize = 0;
    let mut tick = interval(Duration::from_millis(COALESCE_WINDOW_MS));
    // Delay means: if we miss ticks (e.g. scheduler hiccup), the next
    // tick fires immediately without backfilling. We don't want a 50ms
    // stall to queue 10 flush events.
    tick.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            maybe_pub = rx.recv() => {
                match maybe_pub {
                    Some(p) => {
                        buffer.entry(p.topic).or_default().push(p.payload);
                        pending_count += 1;
                        // Flush early on large bursts to cap memory.
                        if pending_count >= MAX_PENDING_BEFORE_FLUSH {
                            flush_buffer(&mut buffer, &conn_manager, &workers, num_workers, &stats).await;
                            pending_count = 0;
                        }
                    }
                    None => {
                        // Drain remaining on shutdown.
                        if !buffer.is_empty() {
                            flush_buffer(&mut buffer, &conn_manager, &workers, num_workers, &stats).await;
                        }
                        tracing::info!("Broadcast coalescer exited");
                        return;
                    }
                }
            }
            _ = tick.tick() => {
                stats.coalescer_ticks_total.fetch_add(1, Ordering::Relaxed);
                if !buffer.is_empty() {
                    flush_buffer(&mut buffer, &conn_manager, &workers, num_workers, &stats).await;
                    pending_count = 0;
                }
            }
        }
    }
}

/// Flush every topic in `buffer`: resolve subscribers, partition across
/// workers (splitting batch-capable proto conns from the rest), and
/// dispatch one `BroadcastWork` per populated partition. `buffer` is
/// cleared on exit.
async fn flush_buffer(
    buffer: &mut HashMap<String, Vec<Payload>>,
    conn_manager: &ConnectionManager,
    workers: &[mpsc::Sender<BroadcastWork>],
    num_workers: usize,
    stats: &BroadcastStats,
) {
    let drained: Vec<(String, Vec<Payload>)> = buffer.drain().collect();
    for (topic, payloads) in drained {
        if payloads.is_empty() {
            continue;
        }

        let publish_start = std::time::Instant::now();

        // Track coalescing stats: batch_size > 1 means real merging happened.
        let batch_size = payloads.len();
        if batch_size > 1 {
            stats
                .coalesced_batches_total
                .fetch_add(1, Ordering::Relaxed);
            stats
                .coalesced_payloads_total
                .fetch_add(batch_size as u64, Ordering::Relaxed);
        }

        // Resolve current subscribers (at flush time, not publish time —
        // a late-joining conn gets only messages published after it
        // joined, matching prior semantics).
        let conns = match conn_manager.topic_subscribers.get(&topic) {
            Some(c) => c,
            None => continue,
        };
        if conns.is_empty() {
            continue;
        }

        // Partition subscribers by conn_id % num_workers. For coalesced
        // bursts (batch_size > 1), ALSO split batch-capable proto conns
        // from everyone else so the worker can take the fast "one
        // packed frame" path on them. We defer actually packing the
        // Batch frame until we know at least one subscriber qualifies,
        // so single-recipient bursts don't waste a decode+encode cycle.
        let partition_start = std::time::Instant::now();
        let mut indiv_parts: Vec<Vec<u64>> = (0..num_workers).map(|_| Vec::new()).collect();
        let mut batch_parts: Vec<Vec<u64>> = (0..num_workers).map(|_| Vec::new()).collect();
        let mut any_batch_candidate = false;
        for &conn_id in conns.iter() {
            let worker_idx = (conn_id as usize) % num_workers;
            let use_batch = batch_size > 1
                && conn_manager.is_batch_capable(conn_id)
                && conn_manager
                    .conn_info
                    .get(&conn_id)
                    .map(|info| info.1 == Encoding::Protobuf)
                    .unwrap_or(false);
            if use_batch {
                batch_parts[worker_idx].push(conn_id);
                any_batch_candidate = true;
            } else {
                indiv_parts[worker_idx].push(conn_id);
            }
        }
        let partition_us = partition_start.elapsed().as_micros() as u64;
        drop(conns);

        // Pack the Batch frame ONCE per topic, only if at least one
        // subscriber will actually receive it.
        let batch_proto: Option<Arc<[u8]>> = if any_batch_candidate {
            pack_batch_frame(&payloads)
        } else {
            None
        };
        // If packing failed, fall back to individual delivery for
        // everyone (including the would-be batch conns). Rare path.
        let batch_proto = if any_batch_candidate && batch_proto.is_none() {
            tracing::warn!(topic = %topic, "Batch pack failed — falling back to individual frames");
            for worker_idx in 0..num_workers {
                let mut stolen = std::mem::take(&mut batch_parts[worker_idx]);
                indiv_parts[worker_idx].append(&mut stolen);
            }
            None
        } else {
            batch_proto
        };

        // Dispatch one BroadcastWork per worker. The work item
        // contains BOTH the payloads (for indiv conns) and the
        // pre-packed batch frame (for batch conns). Each worker only
        // iterates its own slice of the conn_ids.
        for worker_idx in 0..num_workers {
            let indiv = std::mem::take(&mut indiv_parts[worker_idx]);
            let batch = std::mem::take(&mut batch_parts[worker_idx]);
            if indiv.is_empty() && batch.is_empty() {
                continue;
            }
            let work = BroadcastWork {
                payloads: payloads.clone(),
                batch_proto: batch_proto.clone(),
                indiv_conn_ids: indiv,
                batch_conn_ids: batch,
            };
            let worker = &workers[worker_idx];
            let pending = worker.max_capacity().saturating_sub(worker.capacity()) as u64;
            stats
                .max_worker_pending
                .fetch_max(pending, Ordering::Relaxed);
            if worker.send(work).await.is_err() {
                stats.worker_drops_total.fetch_add(1, Ordering::Relaxed);
                tracing::error!(
                    worker_idx,
                    topic = %topic,
                    "Broadcast worker channel closed — worker task died"
                );
            }
        }

        // Partition cost is attributed per publish (divide by
        // publishes_total which already counted all N of them).
        stats.partition_us_sum.fetch_add(
            partition_us.saturating_mul(batch_size as u64),
            Ordering::Relaxed,
        );
        stats.publish_us_sum.fetch_add(
            publish_start
                .elapsed()
                .as_micros()
                .saturating_mul(batch_size as u128) as u64,
            Ordering::Relaxed,
        );
    }
}

/// Decode each payload's cached proto bytes into a `WsMessage`, pack
/// them into a single `WsMessage::Batch`, and re-encode. Returns `None`
/// if any payload fails to decode — the coalescer falls back to
/// individual delivery in that case (never drops a message).
///
/// The per-payload decode is acceptable because it happens once per
/// coalesced flush, not per connection. For a 250-conn topic with a
/// 10-message burst, this replaces ~2500 TCP writes with ~250 packed
/// writes + one decode+encode — a clear win.
fn pack_batch_frame(payloads: &[Payload]) -> Option<Arc<[u8]>> {
    let mut messages = Vec::with_capacity(payloads.len());
    for p in payloads {
        match WsMessage::decode(&*p.proto) {
            Ok(m) => messages.push(m),
            Err(e) => {
                tracing::warn!(error = %e, "Failed to decode payload for Batch packing — falling back");
                return None;
            }
        }
    }
    let batch = WsMessage {
        payload: Some(ws_message::Payload::Batch(Batch { messages })),
    };
    let mut buf = Vec::with_capacity(batch.encoded_len());
    if batch.encode(&mut buf).is_err() {
        return None;
    }
    Some(Arc::from(buf))
}
