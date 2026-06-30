//! Cross-region NATS bridge.
//!
//! Wraps in-region Redis pub/sub payloads in a `CrossRegionEvent`
//! envelope and relays them to peer regions over a NATS supercluster.
//! Inbound envelopes from remote regions are dropped if they originated
//! here (loopback guard), then republished onto the local Redis topic
//! verbatim — the existing Redis subscriber handles local fan-out.
//!
//! Official-network only. Feature-flagged via `NATS_CROSS_REGION_ENABLED`;
//! when disabled, when the instance mode is not `official`, or when no
//! `NATS_AUTH_TOKEN` is configured, `NatsBridge::connect` returns `None`
//! and all publish/subscribe paths are no-ops.
//!
//! Durability: when JetStream is enabled on the local nats-server the
//! bridge upgrades to a local per-region stream + durable pull consumer,
//! closing the message-loss window around `systemctl restart nats-server`
//! (audit finding 2026-04-23). If stream bootstrap fails (JS not enabled,
//! older nats-server), the bridge falls back to core NATS — same behaviour
//! as before the JetStream change. This makes rollout order tolerant:
//! server-rs can ship before every droplet has the JS-enabled nats.conf.

use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_nats::jetstream::{
    self,
    consumer::{AckPolicy, DeliverPolicy, pull},
    stream::{DiscardPolicy, External, RetentionPolicy, Source, StorageType},
};
use async_nats::{Client, ConnectOptions};
use fred::interfaces::PubsubInterface;
use futures_util::StreamExt;
use prost::Message;
use tokio::task::AbortHandle;

use crate::config::{Config as AppConfig, InstanceMode, NatsTopology};
use crate::proto::CrossRegionEvent;

/// NATS subject prefix for cross-region traffic. Each region publishes
/// on exactly one subject: `verdant.xr.<region>`. The topic name (the
/// Redis channel we're relaying) lives in the `CrossRegionEvent`
/// envelope, not in the subject — this keeps the JS subject namespace
/// flat and avoids NATS-token escaping for colons in Redis topic names
/// like `channel:123`.
const XR_SUBJECT_PREFIX: &str = "verdant.xr.";
/// Core-NATS fallback wildcard: matches every region's publish subject.
const XR_SUBJECT_WILDCARD: &str = "verdant.xr.>";

/// Returns the publish / local-capture subject for a region.
fn xr_subject(region: &str) -> String {
    format!("{XR_SUBJECT_PREFIX}{region}")
}

/// Per-region *write* stream — captures local publishes only. Unique
/// names per region is the mechanism that makes JS API requests route
/// to the right cluster in a gateway supercluster (see the Synadia
/// "Virtual Streams" pattern; gateway-forwarded JS API requests resolve
/// by stream name, and with region-scoped names there is no collision).
fn local_stream_name(region: &str) -> String {
    format!("VERDANT_XR_{}", region.to_uppercase())
}

/// Per-region *fanout* stream — source-only, replicates each peer
/// region's write stream into this region via gateway sourcing. Durable
/// on both ends: if a gateway is down, the publish is held in the
/// source region's write stream; once the gateway reconnects, the
/// source copies the message into this region's fanout stream and the
/// local consumer picks it up.
fn fanout_stream_name(region: &str) -> String {
    format!("VERDANT_XR_IN_{}", region.to_uppercase())
}

/// Parse peer region names out of the `NATS_GATEWAYS` secret. The
/// format (set by the orchestrator's `cloud_nats_*` commands) is
/// `verdant-<region>:<host>:<port>,...`. Returns every region *other*
/// than `self_region` — i.e. the set whose write streams we need to
/// source from.
fn parse_peer_regions(gateways: &str, self_region: &str) -> Vec<String> {
    gateways
        .split(',')
        .filter_map(|entry| {
            let name = entry.split(':').next()?.trim();
            let region = name.strip_prefix("verdant-")?.trim();
            if region.is_empty() || region == self_region {
                None
            } else {
                Some(region.to_string())
            }
        })
        .collect()
}

/// Upper bound on how long a stream can hold an undelivered message.
/// Longer than any plausible nats-server restart or deploy window, but
/// short enough to keep disk bounded even during a long outage. NATS XR
/// is only a live-fan-out transport.
const XR_MAX_AGE: Duration = Duration::from_secs(10 * 60);

/// Hard cap on stream size (bytes). Backstop if a bug publishes at a
/// rate higher than `MaxAge` can drain. 256 MB ≈ 250 k messages at 1 KB.
const XR_MAX_BYTES: i64 = 256 * 1024 * 1024;

/// Backoff bounds for the core → JetStream upgrade retry loop. When
/// nats-server starts (especially right after a ZDT droplet restart),
/// the client connects before JetStream has finished its own bootstrap
/// and `ensure_stream` returns 503. We take the Core fallback so the
/// server keeps working, then poll in the background until JS answers,
/// and transparently promote the transport. Fixes: server-rs coming up
/// ~30s before nats-server JS was ready would stay stuck on core until
/// the container was manually restarted.
const JS_RETRY_INITIAL: Duration = Duration::from_secs(10);
const JS_RETRY_MAX: Duration = Duration::from_secs(60);

/// Topic prefixes that get relayed across regions. Keeping this
/// restrictive for phase 1 — only channel messages fan out globally.
/// Presence + user-scoped topics stay in-region.
const RELAYED_PREFIXES: &[&str] = &["channel:"];

/// Either a JetStream context (durable path) or nothing (core-NATS
/// fallback). The bridge prefers JS; the fallback exists so server-rs
/// keeps working when deployed against a pre-JetStream nats-server.
enum Transport {
    Jetstream {
        context: jetstream::Context,
        /// Fanout stream this region's consumer pulls from. Built from
        /// the region name at bootstrap (`VERDANT_XR_IN_<REGION>`) and
        /// held here so the subscriber doesn't have to recompute it.
        fanout_stream: String,
        consumer_name: String,
    },
    Core,
}

pub struct NatsBridge {
    client: Client,
    origin_region: String,
    /// Raw peer-region list parsed from `NATS_GATEWAYS` at connect
    /// time. Used on the JS upgrade path so `retry_jetstream_bootstrap`
    /// can recreate streams with the same source set without re-reading
    /// config. Order doesn't matter; duplicates filtered upstream.
    peer_regions: Vec<String>,
    /// Topology role (standalone / hub / spoke / gateway). Selects
    /// whether fanout-stream sources carry a per-peer `domain` field
    /// (leaf topology) or rely on a shared domain (gateway / solo).
    topology: NatsTopology,
    /// JS stream replica count. 1 for single-node-per-region, 3 for
    /// a proper JS cluster. Read from `NATS_STREAM_REPLICAS` env at
    /// connect time so ops can bump it without a code change once we
    /// go to 3-nodes-per-region.
    num_replicas: usize,
    /// Active transport. Starts as whatever `ensure_streams` reports at
    /// connect time and can be promoted from `Core` → `Jetstream` once
    /// by the background retry task. Never downgrades.
    transport: RwLock<Transport>,
    /// Abort handle for the currently-running subscriber task. The
    /// upgrade path aborts the old core subscriber before spawning a
    /// JetStream one; without this the core subscription would keep
    /// republishing in parallel and cause duplicate Redis fan-out.
    subscriber_handle: Mutex<Option<AbortHandle>>,
    /// Retained so the upgrade task can re-spawn the subscriber with
    /// the same Redis client the original connect() was handed.
    redis: fred::clients::Client,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct NatsBridgeStartupConfig {
    token: String,
    origin_region: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NatsBridgeStartupBlock {
    Disabled,
    NonOfficialInstanceMode(InstanceMode),
    MissingToken,
    MissingRegion,
}

fn resolve_bridge_startup_config(
    instance_mode: InstanceMode,
    enabled: bool,
    token: Option<&str>,
    region: Option<&str>,
) -> Result<NatsBridgeStartupConfig, NatsBridgeStartupBlock> {
    if !enabled {
        return Err(NatsBridgeStartupBlock::Disabled);
    }

    if instance_mode != InstanceMode::Official {
        return Err(NatsBridgeStartupBlock::NonOfficialInstanceMode(
            instance_mode,
        ));
    }

    let token = token
        .filter(|t| !t.trim().is_empty())
        .ok_or(NatsBridgeStartupBlock::MissingToken)?;
    let origin_region = region
        .filter(|r| !r.trim().is_empty())
        .ok_or(NatsBridgeStartupBlock::MissingRegion)?;

    Ok(NatsBridgeStartupConfig {
        token: token.to_string(),
        origin_region: origin_region.to_string(),
    })
}

impl NatsBridge {
    /// Attempt to connect to the local NATS server and start the
    /// cross-region subscriber. Returns `None` if the feature flag is
    /// off, required config is missing, or the initial connect fails
    /// — callers treat absence as "cross-region disabled", not an error.
    pub async fn connect(config: &AppConfig, redis: fred::clients::Client) -> Option<Arc<Self>> {
        let startup = match resolve_bridge_startup_config(
            config.instance_mode,
            config.nats_cross_region_enabled,
            config.nats_auth_token.as_deref(),
            config.verdant_region.as_deref(),
        ) {
            Ok(startup) => startup,
            Err(NatsBridgeStartupBlock::Disabled) => {
                tracing::info!("NATS cross-region disabled (NATS_CROSS_REGION_ENABLED=false)");
                return None;
            }
            Err(NatsBridgeStartupBlock::NonOfficialInstanceMode(mode)) => {
                tracing::warn!(
                    instance_mode = mode.as_str(),
                    "NATS cross-region is official-network only — bridge not started"
                );
                return None;
            }
            Err(NatsBridgeStartupBlock::MissingToken) => {
                tracing::warn!(
                    "NATS cross-region enabled but NATS_AUTH_TOKEN missing — bridge not started"
                );
                return None;
            }
            Err(NatsBridgeStartupBlock::MissingRegion) => {
                tracing::warn!(
                    "NATS cross-region enabled but VERDANT_REGION missing — bridge not started"
                );
                return None;
            }
        };

        // user/password instead of token so nats.conf can use the
        // accounts{} form. That form unlocks $SYS (meta admin ops —
        // server cluster peer-remove, meta stepdown) which is needed
        // to evict ghost peers when a droplet is deleted/crashed and
        // a stream Raft group loses quorum.
        // Credential is the same NATS_AUTH_TOKEN value as before —
        // just sent as a password instead of an auth_token in
        // CONNECT. Username is the fixed "app" string; the render
        // script creates the corresponding user in account APP.
        let token = startup.token;
        let origin_region = startup.origin_region;

        let opts = ConnectOptions::new()
            .user_and_password("app".to_string(), token)
            .name(format!("verdant-server-{}", origin_region))
            .retry_on_initial_connect();

        let client = match opts.connect(&config.nats_url).await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(
                    url = %config.nats_url,
                    error = %e,
                    "NATS connect failed — cross-region bridge not started"
                );
                return None;
            }
        };
        tracing::info!(
            url = %config.nats_url,
            region = %origin_region,
            "NATS cross-region bridge connected"
        );

        // Discover peer regions from the same `NATS_GATEWAYS` secret
        // cloud-init uses to wire up the gateway mesh. These drive the
        // fanout stream's `sources` list; single-region deploys get an
        // empty list and the fanout stream is created idle.
        let peer_regions = config
            .nats_gateways
            .as_deref()
            .map(|gw| parse_peer_regions(gw, &origin_region))
            .unwrap_or_default();
        let topology = config.nats_topology;
        let num_replicas = std::env::var("NATS_STREAM_REPLICAS")
            .ok()
            .and_then(|v| v.parse::<usize>().ok())
            .filter(|n| *n >= 1)
            .unwrap_or(1);
        tracing::info!(
            region = %origin_region,
            peer_regions = ?peer_regions,
            topology = ?topology,
            num_replicas,
            "NATS cross-region peer list"
        );

        // Prefer durable JetStream transport. `ensure_streams` creates
        // (or updates) the local write stream + fanout stream. If the
        // local nats-server has JetStream disabled, or JS is still
        // bootstrapping after a ZDT restart, this fails and we fall
        // back to core NATS; `retry_jetstream_bootstrap` will promote
        // us once JS comes online.
        let transport = match ensure_streams(
            &client,
            &origin_region,
            &peer_regions,
            topology,
            num_replicas,
        )
        .await
        {
            Ok(context) => {
                let fanout_stream = fanout_stream_name(&origin_region);
                // Consumer name is region + hostname so multiple app-
                // servers in the same region each maintain independent
                // replay state. Durable: server restart → resumes from
                // last-acked sequence.
                let hostname = std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
                let consumer_name = sanitize_consumer_name(&format!("{origin_region}-{hostname}"));
                tracing::info!(
                    stream = %fanout_stream,
                    consumer = %consumer_name,
                    "JetStream transport enabled for cross-region XR"
                );
                Transport::Jetstream {
                    context,
                    fanout_stream,
                    consumer_name,
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "JetStream bootstrap failed — falling back to core NATS (no durability)"
                );
                Transport::Core
            }
        };

        let started_as_core = matches!(transport, Transport::Core);

        let bridge = Arc::new(Self {
            client: client.clone(),
            origin_region: origin_region.clone(),
            peer_regions,
            topology,
            num_replicas,
            transport: RwLock::new(transport),
            subscriber_handle: Mutex::new(None),
            redis: redis.clone(),
        });

        bridge.clone().spawn_subscriber();

        if started_as_core {
            let b = bridge.clone();
            tokio::spawn(async move { b.retry_jetstream_bootstrap().await });
        }

        Some(bridge)
    }

    /// Wrap `payload` in a `CrossRegionEvent` and publish it to the
    /// peer regions. `subject` is the Redis topic name (e.g.
    /// `channel:123`) — it will be echoed verbatim on the receiving
    /// side. No-op if the topic is not in the relay whitelist.
    pub fn publish_xr(&self, subject: &str, payload: &[u8]) {
        if !should_relay(subject) {
            return;
        }

        let envelope = CrossRegionEvent {
            origin_region: self.origin_region.clone(),
            ts_ms: now_millis(),
            subject: subject.to_string(),
            payload: payload.to_vec(),
        };
        let encoded = envelope.encode_to_vec();
        // One publish subject per region: `verdant.xr.<region>`. The
        // local write stream (`VERDANT_XR_<REGION>`) captures this
        // subject and nothing else. Redis topic name (`subject`) lives
        // in the envelope, not the NATS subject, so we don't need to
        // escape characters like `:` that aren't strictly legal in JS
        // subject tokens.
        let nats_subject = xr_subject(&self.origin_region);
        let bytes = encoded.len();
        let origin = self.origin_region.clone();

        // Snapshot the transport under the read lock. We clone the
        // `jetstream::Context` (cheap — it's Arc-backed) so the lock is
        // released before we spawn the publish task.
        let snapshot = {
            let t = self.transport.read().expect("nats transport lock poisoned");
            match &*t {
                Transport::Jetstream { context, .. } => {
                    PublishTransport::Jetstream(context.clone())
                }
                Transport::Core => PublishTransport::Core(self.client.clone()),
            }
        };

        match snapshot {
            PublishTransport::Jetstream(context) => {
                // JetStream publish returns `Future<Future<PublishAck>>`:
                // outer resolves when the request is on the wire, inner
                // resolves when the server acks durability. We await
                // both in a background task so `publish_xr` stays non-
                // blocking. A failed ack logs + metrics; we don't retry
                // at this layer (stream `MaxAge` covers transient gaps).
                tokio::spawn(async move {
                    match context.publish(nats_subject.clone(), encoded.into()).await {
                        Ok(ack_fut) => match ack_fut.await {
                            Ok(ack) => tracing::info!(
                                subject = %nats_subject,
                                origin = %origin,
                                bytes,
                                seq = ack.sequence,
                                "nats xr publish (js durable)"
                            ),
                            Err(e) => tracing::warn!(
                                subject = %nats_subject,
                                error = %e,
                                "NATS JetStream publish ack failed"
                            ),
                        },
                        Err(e) => tracing::warn!(
                            subject = %nats_subject,
                            error = %e,
                            "NATS JetStream publish request failed"
                        ),
                    }
                });
            }
            PublishTransport::Core(client) => {
                tokio::spawn(async move {
                    match client.publish(nats_subject.clone(), encoded.into()).await {
                        Ok(()) => tracing::info!(
                            subject = %nats_subject,
                            origin = %origin,
                            bytes,
                            "nats xr publish (core)"
                        ),
                        Err(e) => tracing::warn!(
                            subject = %nats_subject,
                            error = %e,
                            "NATS cross-region publish failed"
                        ),
                    }
                });
            }
        }
    }

    /// Pick the right subscriber loop for the active transport and
    /// store its abort handle so the upgrade path can stop it cleanly.
    /// Replaces any previously-stored handle.
    fn spawn_subscriber(self: Arc<Self>) {
        let redis = self.redis.clone();
        let self_region = self.origin_region.clone();

        let handle = {
            let t = self.transport.read().expect("nats transport lock poisoned");
            match &*t {
                Transport::Jetstream {
                    context,
                    fanout_stream,
                    consumer_name,
                } => {
                    let context = context.clone();
                    let fanout_stream = fanout_stream.clone();
                    let consumer_name = consumer_name.clone();
                    tokio::spawn(async move {
                        run_jetstream_subscriber(
                            context,
                            fanout_stream,
                            consumer_name,
                            redis,
                            self_region,
                        )
                        .await;
                    })
                    .abort_handle()
                }
                Transport::Core => {
                    let client = self.client.clone();
                    tokio::spawn(async move {
                        run_core_subscriber(client, redis, self_region).await;
                    })
                    .abort_handle()
                }
            }
        };

        let old = self
            .subscriber_handle
            .lock()
            .expect("nats subscriber handle lock poisoned")
            .replace(handle);
        if let Some(old_handle) = old {
            old_handle.abort();
        }
    }

    /// Poll `ensure_stream` in the background while transport is
    /// `Core`. JetStream can come online later than the NATS client
    /// connection itself — especially in the ZDT cloud-init flow, where
    /// docker-compose brings server-rs up while `nats-server` is still
    /// finishing its JS meta-group bootstrap and returns 503. Without
    /// this retry, the container stays on core-NATS (non-durable) until
    /// it is manually restarted.
    async fn retry_jetstream_bootstrap(self: Arc<Self>) {
        let mut backoff = JS_RETRY_INITIAL;
        loop {
            tokio::time::sleep(backoff).await;
            backoff = (backoff * 2).min(JS_RETRY_MAX);

            // Bail if something else already upgraded us.
            {
                let t = self.transport.read().expect("nats transport lock poisoned");
                if matches!(*t, Transport::Jetstream { .. }) {
                    return;
                }
            }

            match ensure_streams(
                &self.client,
                &self.origin_region,
                &self.peer_regions,
                self.topology,
                self.num_replicas,
            )
            .await
            {
                Ok(context) => {
                    let fanout_stream = fanout_stream_name(&self.origin_region);
                    let hostname =
                        std::env::var("HOSTNAME").unwrap_or_else(|_| "unknown".to_string());
                    let consumer_name =
                        sanitize_consumer_name(&format!("{}-{}", self.origin_region, hostname));
                    tracing::info!(
                        stream = %fanout_stream,
                        consumer = %consumer_name,
                        "JetStream became available — promoting transport from core to JetStream"
                    );
                    {
                        let mut t = self
                            .transport
                            .write()
                            .expect("nats transport lock poisoned");
                        *t = Transport::Jetstream {
                            context,
                            fanout_stream,
                            consumer_name,
                        };
                    }
                    self.clone().spawn_subscriber();
                    return;
                }
                Err(e) => {
                    tracing::debug!(
                        error = %e,
                        next_retry_secs = backoff.as_secs(),
                        "JetStream still unavailable — will retry"
                    );
                }
            }
        }
    }
}

/// Publish-time snapshot of the transport, taken under a read lock and
/// then dropped so spawned tasks don't touch the lock.
enum PublishTransport {
    Jetstream(jetstream::Context),
    Core(Client),
}

/// Create-or-update both streams this region owns for cross-region
/// fanout, following the Synadia "Virtual Streams" pattern on a
/// gateway supercluster:
///   * `VERDANT_XR_<REGION>` — local write stream. Captures publishes
///     on `verdant.xr.<region>`. Only this region writes here.
///   * `VERDANT_XR_IN_<REGION>` — local fanout stream. Source-only;
///     each peer region's write stream is added as a `Source`, so
///     messages published there are store-and-forward replicated into
///     this stream over the gateway mesh. This is the stream the
///     local consumer reads.
///
/// Does NOT call `jetstream::with_domain` — we deliberately use the
/// default (unset) domain on every node. `domain:` is a leaf-node
/// isolation primitive and has no isolating effect across gateways
/// (docs.nats.io). The per-region isolation here comes from the
/// unique stream names, which is the officially documented pattern
/// in `natsbyexample.com/cross-region-streams-supercluster` and the
/// Synadia blog "Multi-Region Consistency: Have Your Cake and Eat it
/// Too!".
///
/// Idempotent: on boot this is called against whatever config already
/// lives on disk. If the local write stream doesn't exist it is
/// created; if it does, we call `update_stream` to pick up any config
/// drift. Same for the fanout stream, whose `sources` list changes
/// as regions are added/removed from `NATS_GATEWAYS`.
async fn ensure_streams(
    client: &Client,
    region: &str,
    peer_regions: &[String],
    topology: NatsTopology,
    num_replicas: usize,
) -> Result<jetstream::Context, String> {
    let context = jetstream::new(client.clone());

    // Clean-slate-on-drift: wipe any `VERDANT_XR_*` streams that don't
    // belong to this region before we create our own. Orphans appear
    // when an app-server briefly connects to the wrong region's NATS
    // during the bootstrap window (e.g. Doppler reconcile hasn't patched
    // NATS_URL yet after a region provision). An orphan `VERDANT_XR_<peer>`
    // in our local JS gets picked up by our fanout stream's internal
    // sourcing and produces duplicate deliveries — validated 2026-04-24
    // when 1 real publish fanned out 3x on the receiver. Best-effort:
    // failures are logged and don't block bridge startup.
    purge_orphan_xr_streams(&context, region).await;

    // Local write stream: captures publishes from this region's
    // server-rs instances.
    let local_name = local_stream_name(region);
    let local_config = jetstream::stream::Config {
        name: local_name.clone(),
        subjects: vec![xr_subject(region)],
        retention: RetentionPolicy::Limits,
        storage: StorageType::File,
        max_age: XR_MAX_AGE,
        max_bytes: XR_MAX_BYTES,
        discard: DiscardPolicy::Old,
        num_replicas,
        ..Default::default()
    };
    ensure_stream_config(&context, local_config).await?;

    // Fanout stream: source-only, one `Source` per peer region. If
    // there are no peers (single-region deployment, or first region
    // provisioned), the stream is created with an empty sources list
    // and simply sits idle — harmless.
    //
    // In leaf topology (hub/spoke) each region has its own JS `domain`,
    // so the local JS can't resolve a peer stream by bare name — we
    // have to point the source at the peer's domain (`$JS.<peer>.API`).
    //
    // We set `Source.external` explicitly rather than using the
    // `Source.domain` convenience: async-nats 0.37 only translates
    // `domain` → `external.api_prefix` inside `create_stream`, NOT
    // inside `update_stream` (verified in async-nats context.rs:290-303
    // vs context.rs:523-546). Multiple app-servers racing at boot hit
    // a failure mode where create_stream wins once (external set), then
    // a subsequent update_stream from a sibling strips external because
    // our Source payload only carried `domain`. Stored config ends up
    // with neither field → lon1 IN stream silently no-ops (2026-04-24
    // V1 test: 5 messages delivered via initial create, then 3 further
    // publishes never crossed because update_stream races stripped
    // external). Setting `external` explicitly sidesteps the whole
    // convenience layer.
    //
    // In gateway / standalone topology there's one JS domain cluster-
    // wide, so leave `external` unset and let the supercluster's name
    // resolution find the stream locally.
    let fanout_name = fanout_stream_name(region);
    let cross_domain = topology.needs_cross_domain_sources();
    let sources = peer_regions
        .iter()
        .map(|peer| Source {
            name: local_stream_name(peer),
            external: if cross_domain {
                Some(External {
                    api_prefix: format!("$JS.{peer}.API"),
                    delivery_prefix: None,
                })
            } else {
                None
            },
            ..Default::default()
        })
        .collect::<Vec<_>>();
    let fanout_config = jetstream::stream::Config {
        name: fanout_name.clone(),
        // No `subjects`: the stream is populated exclusively via
        // sourcing. Direct publishes to this stream are not possible.
        subjects: vec![],
        sources: if sources.is_empty() {
            None
        } else {
            Some(sources)
        },
        retention: RetentionPolicy::Limits,
        storage: StorageType::File,
        max_age: XR_MAX_AGE,
        max_bytes: XR_MAX_BYTES,
        discard: DiscardPolicy::Old,
        num_replicas,
        ..Default::default()
    };
    ensure_stream_config(&context, fanout_config).await?;

    Ok(context)
}

/// Delete every `VERDANT_XR_*` stream that doesn't belong to
/// `self_region`. Each region's local JS should own exactly two XR
/// streams: `VERDANT_XR_<SELF>` (write) and `VERDANT_XR_IN_<SELF>`
/// (fanout). Peer-region data arrives via `external.api` sources and
/// never materializes a local peer-named stream. Anything else under
/// the `VERDANT_XR_` prefix is a bootstrap-race orphan — most commonly
/// an app-server that ran `ensure_streams` against the wrong region's
/// NATS before mesh reconcile patched its `NATS_URL`. Left in place,
/// the local fanout stream's internal sourcing multiplexes the orphan
/// into duplicate deliveries (1 publish → N receives).
///
/// Safe on every boot because XR streams carry no business data. Errors are
/// logged and swallowed so the bridge can still start.
async fn purge_orphan_xr_streams(context: &jetstream::Context, self_region: &str) {
    let self_upper = self_region.to_uppercase();
    let expected_write = format!("VERDANT_XR_{}", self_upper);
    let expected_fanout = format!("VERDANT_XR_IN_{}", self_upper);

    let mut names = context.stream_names();
    while let Some(result) = names.next().await {
        let name = match result {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "stream_names iter failed during orphan purge — aborting scan, bridge will continue"
                );
                return;
            }
        };
        if !name.starts_with("VERDANT_XR_") {
            continue;
        }
        if name == expected_write || name == expected_fanout {
            continue;
        }
        tracing::warn!(
            stream = %name,
            self_region = %self_region,
            "deleting orphan XR stream — belongs to a peer region (bootstrap-race leftover)"
        );
        if let Err(e) = context.delete_stream(&name).await {
            tracing::warn!(
                stream = %name,
                error = %e,
                "delete_stream failed during orphan purge — will retry on next boot"
            );
        }
    }
}

/// Idempotent create-or-update. Required because `get_or_create_stream`
/// is create-only — if the stream already exists but has different
/// config (e.g. the peer-region list grew since last boot), that call
/// returns the old stream unchanged and our new sources never take
/// effect. Branch on existence and then either create or update in
/// place.
///
/// When `update_stream` fails (commonly: Raft group wedged mid
/// scale-down with a ghost peer → "jetstream request timed out"),
/// fall through to delete + create. These XR fan-out streams carry
/// no durable business data (MaxAge 10m), so recreating is safe and
/// is the only path that unwedges a stream whose own Raft group has
/// lost quorum — `delete_stream` is a meta-group op which retains
/// quorum as long as the meta has majority, independent of any one
/// stream's health.
async fn ensure_stream_config(
    context: &jetstream::Context,
    config: jetstream::stream::Config,
) -> Result<(), String> {
    let name = config.name.clone();
    match context.get_stream(&name).await {
        Ok(stream) => {
            // Source-config drift detection: `update_stream` silently
            // discards any change to `source.external` when the caller
            // submits a Source that doesn't carry `external`. This
            // matters because async-nats 0.37 only translates
            // `source.domain` → `source.external` inside create_stream,
            // not update_stream — so a stream created in the wrong
            // topology (or whose external got stripped by a racing
            // update_stream call) can't be fixed in-place.
            //
            // Detect the mismatch ourselves and force delete+create when
            // desired sources require `external` but on-disk ones lack it.
            let existing = stream.cached_info();
            let external_drift = sources_external_drift(
                existing.config.sources.as_deref(),
                config.sources.as_deref(),
            );
            if external_drift {
                tracing::warn!(
                    stream = %name,
                    "source-external drift detected (existing sources lack external.api but desired requires it) — delete+recreate"
                );
                context
                    .delete_stream(&name)
                    .await
                    .map_err(|e| format!("delete_stream({name}) on domain-drift: {e}"))?;
                context
                    .create_stream(config)
                    .await
                    .map_err(|e| format!("recreate_stream({name}) on domain-drift: {e}"))?;
            } else if let Err(update_err) = context.update_stream(&config).await {
                tracing::warn!(
                    stream = %name,
                    error = %update_err,
                    "update_stream failed — falling back to delete+create (XR streams are ephemeral)"
                );
                context
                    .delete_stream(&name)
                    .await
                    .map_err(|e| format!("delete_stream({name}) after update failure: {e}"))?;
                context
                    .create_stream(config)
                    .await
                    .map_err(|e| format!("recreate_stream({name}) after update failure: {e}"))?;
            }
        }
        Err(_) => {
            context
                .create_stream(config)
                .await
                .map_err(|e| format!("create_stream({name}): {e}"))?;
        }
    }
    Ok(())
}

/// Returns true when desired sources require `external.api_prefix` on
/// at least one peer but the existing on-disk source config is missing
/// it (or has a different prefix). Only this direction matters: adding
/// external to a previously external-less source can't be done via
/// update_stream; removing external (hub/spoke → standalone) can, so
/// that case falls through to the normal update path.
fn sources_external_drift(existing: Option<&[Source]>, desired: Option<&[Source]>) -> bool {
    let Some(desired) = desired else {
        return false;
    };
    let existing = existing.unwrap_or(&[]);
    for want in desired {
        let Some(want_ext) = want.external.as_ref() else {
            continue;
        };
        match existing.iter().find(|s| s.name == want.name) {
            Some(have) => match have.external.as_ref() {
                Some(have_ext) if have_ext.api_prefix == want_ext.api_prefix => continue,
                _ => return true,
            },
            None => return true,
        }
    }
    false
}

/// Durable pull-consumer loop wrapped in an indefinite reconnect so
/// transient server-side events (sibling app-server's ensure_streams
/// hit the drift path and delete+recreated the stream, nats-server
/// restarted, etc.) don't leave this app-server's bridge silent until
/// the next container restart.
///
/// Inner `run_jetstream_subscriber_inner` runs one attempt — creates
/// the consumer, pulls until the messages stream ends or an explicit
/// reset signal arrives, returns a `SubscriberExit` describing why it
/// exited. The outer loop then either reconnects (with backoff) or
/// terminates for unrecoverable errors.
/// The wrapper recreates a consumer if stream maintenance deletes it.
async fn run_jetstream_subscriber(
    context: jetstream::Context,
    fanout_stream: String,
    consumer_name: String,
    redis: fred::clients::Client,
    self_region: String,
) {
    let mut backoff = Duration::from_secs(1);
    let max_backoff = Duration::from_secs(30);
    loop {
        let exit = run_jetstream_subscriber_inner(
            context.clone(),
            fanout_stream.clone(),
            consumer_name.clone(),
            redis.clone(),
            self_region.clone(),
        )
        .await;
        match exit {
            SubscriberExit::StreamEnded | SubscriberExit::ConsumerDeleted => {
                tracing::warn!(
                    stream = %fanout_stream,
                    consumer = %consumer_name,
                    backoff_ms = backoff.as_millis(),
                    "JetStream subscriber exited — reconnecting after backoff"
                );
                tokio::time::sleep(backoff).await;
                backoff = (backoff * 2).min(max_backoff);
            }
            SubscriberExit::PermanentError(msg) => {
                tracing::error!(
                    stream = %fanout_stream,
                    consumer = %consumer_name,
                    error = %msg,
                    "JetStream subscriber hit permanent error — giving up"
                );
                return;
            }
        }
    }
}

#[allow(dead_code)]
enum SubscriberExit {
    /// Normal `messages.next()` returned None (connection closed or
    /// server-side reset). Retry.
    StreamEnded,
    /// Fetch returned the specific "consumer deleted" error, which
    /// happens after a sibling app-server delete+created our stream.
    /// Retry — get_or_create_consumer will recreate on next attempt.
    ConsumerDeleted,
    /// Reserved for future unrecoverable errors (auth revoked, JS
    /// permanently disabled, etc.) where retrying is pointless. No
    /// current return site — every failure class today is retriable.
    PermanentError(String),
}

async fn run_jetstream_subscriber_inner(
    context: jetstream::Context,
    fanout_stream: String,
    consumer_name: String,
    redis: fred::clients::Client,
    self_region: String,
) -> SubscriberExit {
    let stream = match context.get_stream(&fanout_stream).await {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(
                stream = %fanout_stream,
                error = %e,
                "JetStream get_stream failed — will retry"
            );
            return SubscriberExit::StreamEnded;
        }
    };

    let consumer_config = pull::Config {
        durable_name: Some(consumer_name.clone()),
        ack_policy: AckPolicy::Explicit,
        deliver_policy: DeliverPolicy::All,
        ack_wait: Duration::from_secs(30),
        ..Default::default()
    };

    let consumer = match stream
        .get_or_create_consumer::<pull::Config>(&consumer_name, consumer_config)
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(
                consumer = %consumer_name,
                error = %e,
                "JetStream get_or_create_consumer failed — will retry"
            );
            return SubscriberExit::StreamEnded;
        }
    };

    tracing::info!(
        stream = %fanout_stream,
        consumer = %consumer_name,
        "NATS cross-region subscriber started (JetStream durable)"
    );

    let mut messages = match consumer.messages().await {
        Ok(m) => m,
        Err(e) => {
            tracing::warn!(error = %e, "JetStream messages() failed — will retry");
            return SubscriberExit::StreamEnded;
        }
    };

    while let Some(res) = messages.next().await {
        let msg = match res {
            Ok(m) => m,
            Err(e) => {
                let msg = e.to_string();
                // "consumer deleted" means our durable's gone — a sibling
                // app-server's ensure_streams delete+recreated the stream.
                // Break out so the outer loop reconnects; the new
                // get_or_create_consumer call will spin up a fresh durable
                // on the new stream and resume from start-of-stream (all
                // messages are <10m old by MaxAge, so any gap is bounded).
                if msg.contains("consumer deleted") || msg.contains("stream not found") {
                    tracing::warn!(error = %msg, "consumer/stream removed — reconnecting");
                    return SubscriberExit::ConsumerDeleted;
                }
                // Other fetch errors (decode, transient): log and keep
                // reading, same as before.
                tracing::warn!(error = %msg, "JetStream message fetch error");
                continue;
            }
        };

        let decoded = CrossRegionEvent::decode(&*msg.payload);
        match decoded {
            Ok(envelope) => {
                if envelope.origin_region == self_region {
                    tracing::info!(
                        subject = %envelope.subject,
                        origin = "self",
                        "nats xr drop (loopback, js)"
                    );
                } else if !should_relay(&envelope.subject) {
                    tracing::warn!(
                        origin = %envelope.origin_region,
                        subject = %envelope.subject,
                        "nats xr drop (subject not allowed)"
                    );
                } else {
                    republish_to_redis(&redis, &envelope).await;
                }
            }
            Err(e) => {
                tracing::warn!(
                    subject = %msg.subject,
                    error = %e,
                    "NATS cross-region decode failed — dropping"
                );
            }
        }

        if let Err(e) = msg.ack().await {
            tracing::warn!(error = %e, "JetStream ack failed");
        }
    }

    tracing::warn!("NATS cross-region subscriber (JetStream) stream ended — reconnecting");
    SubscriberExit::StreamEnded
}

/// Core-NATS fallback subscriber. No durability during disconnects.
async fn run_core_subscriber(client: Client, redis: fred::clients::Client, self_region: String) {
    let mut sub = match client.subscribe(XR_SUBJECT_WILDCARD).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "NATS cross-region subscribe failed");
            return;
        }
    };
    tracing::info!(
        subject = XR_SUBJECT_WILDCARD,
        "NATS cross-region subscriber started (core, no durability)"
    );

    while let Some(msg) = sub.next().await {
        let envelope = match CrossRegionEvent::decode(&*msg.payload) {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(
                    subject = %msg.subject,
                    error = %e,
                    "NATS cross-region decode failed — dropping"
                );
                continue;
            }
        };

        if envelope.origin_region == self_region {
            tracing::info!(
                subject = %envelope.subject,
                origin = "self",
                "nats xr drop (loopback)"
            );
            continue;
        }

        if !should_relay(&envelope.subject) {
            tracing::warn!(
                origin = %envelope.origin_region,
                subject = %envelope.subject,
                "nats xr drop (subject not allowed)"
            );
            continue;
        }

        republish_to_redis(&redis, &envelope).await;
    }

    tracing::error!("NATS cross-region subscriber stream ended");
}

/// Emit the inner payload onto the local Redis topic named by
/// `envelope.subject`. The embedded remote `node_id` in that payload
/// ensures the existing Redis subscriber's self-origin filter doesn't
/// drop it. Shared between both transport paths.
async fn republish_to_redis(redis: &fred::clients::Client, envelope: &CrossRegionEvent) {
    tracing::info!(
        origin = %envelope.origin_region,
        subject = %envelope.subject,
        bytes = envelope.payload.len(),
        "nats xr recv → republish local"
    );

    let redis = redis.clone();
    let topic = envelope.subject.clone();
    let payload = envelope.payload.clone();
    tokio::spawn(async move {
        if let Err(e) = redis.publish::<i64, _, _>(topic.clone(), payload).await {
            tracing::warn!(
                topic = %topic,
                error = %e,
                "Redis republish from NATS failed"
            );
        }
    });
}

fn should_relay(subject: &str) -> bool {
    RELAYED_PREFIXES.iter().any(|p| subject.starts_with(p))
}

/// JetStream consumer names restrict chars. Keep letters/digits/`_-`
/// only; swap anything else (dots, colons from a container hostname)
/// so two app-servers in the same region can't collide on name.
fn sanitize_consumer_name(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn now_millis() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_peer_regions_and_excludes_self() {
        let gw = "verdant-nyc1:10.0.0.1:7222,verdant-ams3:10.0.0.2:7222,verdant-sfo3:10.0.0.3:7222";
        let peers = parse_peer_regions(gw, "nyc1");
        assert_eq!(peers, vec!["ams3".to_string(), "sfo3".to_string()]);
    }

    #[test]
    fn parses_peer_regions_empty_for_single_region() {
        assert!(parse_peer_regions("", "nyc1").is_empty());
        assert!(parse_peer_regions("verdant-nyc1:10.0.0.1:7222", "nyc1").is_empty());
    }

    #[test]
    fn parses_peer_regions_ignores_malformed() {
        // Entries without `verdant-` prefix are dropped; the well-formed
        // ones still come through.
        let gw = "badentry,verdant-ams3:10.0.0.2:7222,,verdant-sfo3:10.0.0.3:7222";
        let peers = parse_peer_regions(gw, "nyc1");
        assert_eq!(peers, vec!["ams3".to_string(), "sfo3".to_string()]);
    }

    #[test]
    fn stream_and_subject_names_are_region_scoped() {
        assert_eq!(local_stream_name("nyc1"), "VERDANT_XR_NYC1");
        assert_eq!(fanout_stream_name("ams3"), "VERDANT_XR_IN_AMS3");
        assert_eq!(xr_subject("nyc1"), "verdant.xr.nyc1");
    }

    #[test]
    fn relay_whitelist_only_allows_channel_topics() {
        assert!(should_relay("channel:123"));
        assert!(!should_relay("user:123"));
        assert!(!should_relay("system"));
        assert!(!should_relay("channel_notify:123"));
    }

    #[test]
    fn bridge_startup_rejects_non_official_instance_modes() {
        for mode in [
            InstanceMode::Standalone,
            InstanceMode::Linked,
            InstanceMode::Federated,
        ] {
            let startup =
                resolve_bridge_startup_config(mode, true, Some("test-token"), Some("nyc1"));

            assert_eq!(
                startup,
                Err(NatsBridgeStartupBlock::NonOfficialInstanceMode(mode))
            );
        }
    }

    #[test]
    fn bridge_startup_accepts_official_mode_with_required_fields() {
        let startup = resolve_bridge_startup_config(
            InstanceMode::Official,
            true,
            Some("token"),
            Some("nyc1"),
        );

        assert_eq!(
            startup,
            Ok(NatsBridgeStartupConfig {
                token: "token".to_string(),
                origin_region: "nyc1".to_string(),
            })
        );
    }

    #[test]
    fn bridge_startup_rejects_missing_required_fields() {
        assert_eq!(
            resolve_bridge_startup_config(
                InstanceMode::Official,
                false,
                Some("token"),
                Some("nyc1")
            ),
            Err(NatsBridgeStartupBlock::Disabled)
        );
        assert_eq!(
            resolve_bridge_startup_config(InstanceMode::Official, true, None, Some("nyc1")),
            Err(NatsBridgeStartupBlock::MissingToken)
        );
        assert_eq!(
            resolve_bridge_startup_config(InstanceMode::Official, true, Some("token"), None),
            Err(NatsBridgeStartupBlock::MissingRegion)
        );
    }
}
