use fred::clients::{Client, SubscriberClient};
use fred::prelude::*;
use std::sync::Arc;
use std::time::Duration;

use crate::config::Config as AppConfig;
use crate::middleware::rate_limit::LocalRateLimiter;
use crate::services::bot_gateway::BotGatewayManager;
use crate::services::broadcast::BroadcastService;
use crate::services::content_scanner::{self, ContentScanner};
use crate::services::email::EmailService;
use crate::services::feature_flags::FeatureFlagService;
use crate::services::field_crypto::FieldEncryptionKeyring;
use crate::services::message_cache::MessageCache;
use crate::services::permissions::PermissionCache;
use crate::services::s3::S3Service;
use crate::services::user_cache::UserProfileCache;
use crate::services::voice::VoiceService;
use crate::snowflake::SnowflakeGenerator;
use crate::ws::ConnectionManager;

#[derive(Clone, Debug, Default, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct NodeRuntimeInfo {
    pub droplet_id: Option<String>,
    pub name: Option<String>,
    pub public_ip: Option<String>,
    pub region: Option<String>,
}

impl NodeRuntimeInfo {
    async fn detect() -> Self {
        let env_or = |key: &str| std::env::var(key).ok().filter(|v| !v.trim().is_empty());
        let disabled = std::env::var("DO_METADATA_DISABLED")
            .ok()
            .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);

        if disabled {
            return Self {
                droplet_id: env_or("APP_DROPLET_ID"),
                name: env_or("APP_NODE_NAME"),
                public_ip: env_or("APP_PUBLIC_IP"),
                region: env_or("VERDANT_REGION"),
            };
        }

        let client = match reqwest::Client::builder()
            .timeout(Duration::from_millis(350))
            .build()
        {
            Ok(c) => c,
            Err(_) => {
                return Self {
                    droplet_id: env_or("APP_DROPLET_ID"),
                    name: env_or("APP_NODE_NAME"),
                    public_ip: env_or("APP_PUBLIC_IP"),
                    region: env_or("VERDANT_REGION"),
                };
            }
        };

        async fn get_metadata(client: &reqwest::Client, path: &str) -> Option<String> {
            let url = format!("http://169.254.169.254/metadata/v1/{path}");
            let text = client
                .get(url)
                .send()
                .await
                .ok()?
                .error_for_status()
                .ok()?
                .text()
                .await
                .ok()?;
            let value = text.trim();
            if value.is_empty() {
                None
            } else {
                Some(value.to_string())
            }
        }

        let (droplet_id, name, public_ip, region) = tokio::join!(
            get_metadata(&client, "id"),
            get_metadata(&client, "hostname"),
            get_metadata(&client, "interfaces/public/0/ipv4/address"),
            get_metadata(&client, "region"),
        );

        Self {
            droplet_id: env_or("APP_DROPLET_ID").or(droplet_id),
            name: env_or("APP_NODE_NAME").or(name),
            public_ip: env_or("APP_PUBLIC_IP").or(public_ip),
            region: env_or("VERDANT_REGION").or(region),
        }
    }
}

fn make_pg_pool(url: &str, max_connections: u32, label: &str) -> sqlx::PgPool {
    let connect_opts: sqlx::postgres::PgConnectOptions =
        url.parse().unwrap_or_else(|_| panic!("invalid {label}"));
    let connect_opts = connect_opts.statement_cache_capacity(0);

    sqlx::postgres::PgPoolOptions::new()
        .max_connections(max_connections)
        // Sqlx default is 30s for connect timeout; bump for cold-start
        // managed-pg cases where the first SSL handshake can be slow.
        .acquire_timeout(Duration::from_secs(10))
        // Idle timeout reaps connections sitting unused for >10 min so
        // we don't pin pg connections per server-rs idle window.
        .idle_timeout(Some(Duration::from_secs(600)))
        // Test connections that have been idle for a while before
        // handing them out. Cheap; protects against silent NAT drops.
        .test_before_acquire(true)
        .connect_lazy_with(connect_opts)
}

/// Shared application state, wrapped in `Arc` for cheap cloning.
#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<AppStateInner>,
}

/// Core application state shared across all handlers via Axum's State extractor.
///
/// Redis is used for ephemeral state (sessions index caches, rate
/// limits, pub/sub fan-out, short-lived verification codes, per-user
/// streams like audit log and login history).
pub struct AppStateInner {
    pub redis: Client,
    pub redis_sub: SubscriberClient,
    /// Postgres connection pool. Size set by `DATABASE_POOL_SIZE`
    /// (default 30). Sqlx prepares + caches
    /// statements per connection, so heavy reuse is free across handlers.
    pub pg: sqlx::PgPool,
    /// Optional non-owner Postgres pool for request paths that should run
    /// under row-level security with a transaction-local `app.user_id`.
    pub pg_app: Option<sqlx::PgPool>,
    pub config: AppConfig,
    pub field_crypto: Option<FieldEncryptionKeyring>,
    pub snowflake: SnowflakeGenerator,
    pub ws: Arc<ConnectionManager>,
    pub bot_gateway: Arc<BotGatewayManager>,
    /// Sharded fan-out broadcast service for parallel message delivery.
    /// Used by `topics::publish()` for events with both proto + JSON payloads.
    pub broadcast: Arc<BroadcastService>,
    pub permissions: Arc<PermissionCache>,
    pub feature_flags: Arc<FeatureFlagService>,
    pub s3: Option<S3Service>,
    pub s3_evidence: Option<S3Service>,
    pub email: Option<EmailService>,
    pub voice: Arc<VoiceService>,
    pub geoip: Option<crate::services::geoip::GeoIpService>,
    pub user_profiles: Arc<UserProfileCache>,
    pub local_rate_limiter: Arc<LocalRateLimiter>,
    pub content_scanner: Box<dyn ContentScanner>,
    pub message_cache: Arc<MessageCache>,
    pub message_batcher: Arc<crate::services::message_batcher::MessageBatcher>,
    /// Set to true during graceful shutdown. Disconnect handlers check this
    /// to skip presence broadcasts (avoids UI flicker during a clean roll).
    pub shutting_down: std::sync::atomic::AtomicBool,
    /// Set to true when this node has been removed from the load balancer
    /// and is intentionally closing sockets so clients reconnect elsewhere.
    pub draining: std::sync::atomic::AtomicBool,
    /// Unique identifier for this server instance, used to skip self-originated
    /// Redis pub/sub messages and prevent double-delivery on single-instance setups.
    pub node_id: String,
    pub node: NodeRuntimeInfo,
    /// Cross-region NATS bridge. `Some` when
    /// `NATS_CROSS_REGION_ENABLED=true` and the connect succeeded,
    /// `None` otherwise — `topics::publish` checks and no-ops when
    /// absent.
    pub nats_bridge: Option<Arc<crate::services::nats::NatsBridge>>,
}

impl AppState {
    pub async fn new(config: AppConfig) -> Self {
        // Connect to Redis: main client and subscriber in parallel
        let redis_config = Config::from_url(&config.redis_url).expect("Invalid REDIS_URL");
        let redis = Builder::from_config(redis_config.clone())
            .with_connection_config(|c| {
                c.connection_timeout = Duration::from_secs(5);
            })
            .set_policy(ReconnectPolicy::new_exponential(0, 100, 30_000, 2))
            .build()
            .expect("Failed to create Redis client");
        let redis_sub = Builder::from_config(redis_config)
            .with_connection_config(|c| {
                c.connection_timeout = Duration::from_secs(5);
            })
            .with_performance_config(|c| {
                // fred default broadcast buffer is 32, which overflows
                // the moment a 1000-WS-client server bursts a few hundred
                // MESSAGE_CREATE pubsub envelopes faster than the bridge
                // task can drain them. 4096 covers a multi-second burst
                // at our observed broadcast rate (~1-2K/s) and costs only
                // ~4096 × small_msg ≈ 200KB of memory.
                c.broadcast_channel_capacity = 4096;
            })
            .set_policy(ReconnectPolicy::new_exponential(0, 100, 30_000, 2))
            .build_subscriber_client()
            .expect("Failed to create Redis subscriber client");
        let (redis_init, redis_sub_init) = tokio::join!(redis.init(), redis_sub.init());
        redis_init.expect("Failed to connect to Redis");
        redis_sub_init.expect("Failed to connect Redis subscriber");
        let _ = redis_sub.manage_subscriptions();
        tracing::info!("Connected to Redis (main + subscriber)");

        // Postgres pool. We use Lazy here so a transient pg outage at boot
        // doesn't crash the process — connections are established on first
        // use. Pool runs sqlx migrations once the binary starts handling
        // traffic; we don't gate boot on the pool being warm.
        // PgBouncer transaction-mode rebinds backends per transaction.
        // sqlx's per-connection prepared-statement cache breaks under
        // that rebinding ("prepared statement \"sqlx_s_N\" does not
        // exist") because a prepared name resolves on whatever backend
        // PgBouncer happened to attach to the previous transaction.
        // Disabling the cache forces parse-each-query — costs a few µs
        // of re-parse but PG's plan cache is on the backend, not on
        // sqlx, so we don't lose plan reuse.
        let pg = make_pg_pool(
            &config.database_url,
            config.database_pool_size,
            "DATABASE_URL",
        );
        tracing::info!(
            max_connections = config.database_pool_size,
            "Postgres pool initialized (lazy — first query establishes connection)"
        );
        let pg_app = config.database_app_url.as_ref().map(|url| {
            let pool = make_pg_pool(url, config.database_pool_size, "DATABASE_APP_URL");
            tracing::info!(
                max_connections = config.database_pool_size,
                "Postgres RLS app pool initialized (lazy — user-scoped requests can use DATABASE_APP_URL)"
            );
            pool
        });
        if pg_app.is_none() {
            tracing::warn!(
                "DATABASE_APP_URL is not set; RLS-scoped helpers will fall back to DATABASE_URL and may be bypassed by the table owner"
            );
        }

        let field_crypto = config.app_field_encryption_key.as_ref().map(|secret| {
            FieldEncryptionKeyring::from_hex_secret(secret, 1)
                .expect("APP_FIELD_ENCRYPTION_KEY was validated during config load")
        });
        if field_crypto.is_some() {
            tracing::info!("Application field encryption initialized");
        }

        // Generate a random node ID for Redis pub/sub deduplication
        let node_id = format!("{:016x}", rand::random::<u64>());
        tracing::info!(node_id = %node_id, "Instance node ID generated");
        let node = NodeRuntimeInfo::detect().await;
        tracing::info!(
            droplet_id = ?node.droplet_id,
            node_name = ?node.name,
            public_ip = ?node.public_ip,
            region = ?node.region,
            "Runtime node metadata detected"
        );

        // Worker ID for snowflake IDs: derive from env var (multi-instance),
        // or generate a random 10-bit value (single-instance). Random is safe
        // for single-instance because collision probability across deploys is
        // negligible (1/1024 per ms). For multi-instance, set SNOWFLAKE_WORKER_ID
        // per instance (0-1023) to guarantee uniqueness.
        let worker_id: u16 = std::env::var("SNOWFLAKE_WORKER_ID")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or_else(|| (rand::random::<u16>()) % 1024);
        tracing::info!(worker_id, "Snowflake generator initialized");
        let snowflake = SnowflakeGenerator::new(worker_id);
        let ws = Arc::new(ConnectionManager::new());
        let bot_gateway = Arc::new(BotGatewayManager::new());
        let broadcast = BroadcastService::start(Arc::clone(&ws));
        let feature_flags = Arc::new(FeatureFlagService::new());

        let s3 = S3Service::from_config(
            config.s3_endpoint.as_deref(),
            config.s3_bucket.as_deref(),
            config.s3_access_key.as_deref(),
            config.s3_secret_key.as_deref(),
            config.s3_region.as_deref(),
            config.storage_path_style,
        );
        if s3.is_some() {
            tracing::info!("S3 storage service initialized");
        }

        // Evidence bucket (separate R2 bucket, no custom domain = private)
        let s3_evidence = config.evidence_bucket.as_deref().and_then(|bucket| {
            S3Service::from_config(
                config.s3_endpoint.as_deref(),
                Some(bucket),
                config.s3_access_key.as_deref(),
                config.s3_secret_key.as_deref(),
                config.s3_region.as_deref(),
                config.storage_path_style,
            )
        });
        if s3_evidence.is_some() {
            tracing::info!("S3 evidence bucket initialized");
        }

        let email = if config.email_enabled() {
            EmailService::from_config(
                config.resend_api_key.as_deref(),
                config.email_from.as_deref(),
                config.frontend_url.as_deref(),
            )
        } else {
            None
        };
        if email.is_some() {
            tracing::info!("Email service initialized");
        }

        let geoip = crate::services::geoip::GeoIpService::init().await;

        let voice = VoiceService::new();
        let user_profiles = UserProfileCache::new();
        user_profiles.start_cleanup_task();
        let local_rate_limiter = Arc::new(LocalRateLimiter::new());
        local_rate_limiter.start_cleanup_task();

        let content_scanner = content_scanner::try_create_scanner(
            &config.content_scan_provider,
            config.content_scan_api_key.as_deref(),
            config.content_scan_mock_hashes.as_deref(),
        )
        .unwrap_or_else(|err| panic!("content scanner configuration error: {err}"));

        let message_cache = MessageCache::new(redis.clone());
        let message_batcher = crate::services::message_batcher::MessageBatcher::start(pg.clone());

        // PermissionCache reads from PG (cache-on-miss). The DashMap
        // caches in front are the load-bearing optimization; the pool
        // is only consulted on lazy-load + invalidation paths.
        let permissions = PermissionCache::new(pg.clone());
        permissions.start_idle_sweep();
        permissions.start_invalidation_subscriber(&redis_sub, &node_id);

        // Cross-region NATS bridge (optional, feature-flagged).
        let nats_bridge = crate::services::nats::NatsBridge::connect(&config, redis.clone()).await;

        Self {
            inner: Arc::new(AppStateInner {
                redis,
                redis_sub,
                pg,
                pg_app,
                config,
                field_crypto,
                snowflake,
                ws,
                bot_gateway,
                broadcast,
                permissions,
                feature_flags,
                s3,
                s3_evidence,
                email,
                voice,
                geoip,
                user_profiles,
                local_rate_limiter,
                content_scanner,
                message_cache,
                message_batcher,
                shutting_down: std::sync::atomic::AtomicBool::new(false),
                draining: std::sync::atomic::AtomicBool::new(false),
                node_id,
                node,
                nats_bridge,
            }),
        }
    }
}

// ─── Permission convenience methods ─────────────────────────────────────
// Shorthand for the membership + permission check two-liner that appears in every handler.

impl AppState {
    /// Start a user-scoped Postgres transaction with `app.user_id` set for
    /// row-level security policies. Uses `DATABASE_APP_URL` when configured.
    pub async fn rls_transaction(
        &self,
        user_id: i64,
    ) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, sqlx::Error> {
        let pool = self.pg_app.as_ref().unwrap_or(&self.pg);
        crate::services::rls::begin_user_transaction(pool, user_id).await
    }

    /// Verify user is a member of the server. Returns `Err(Forbidden)` if not.
    pub async fn require_membership(
        &self,
        user_id: i64,
        server_id: i64,
    ) -> crate::error::AppResult<()> {
        self.permissions.check_membership(user_id, server_id).await
    }

    /// Verify user is a member **and** has the given permission bits.
    /// Audit note: use this for server-scoped mutations; channel-scoped work
    /// still needs channel visibility/override checks at the call site.
    pub async fn require_permission(
        &self,
        user_id: i64,
        server_id: i64,
        permission: i64,
    ) -> crate::error::AppResult<()> {
        self.permissions
            .check_membership(user_id, server_id)
            .await?;
        self.permissions
            .check_server_permission(user_id, server_id, permission)
            .await
    }
}

// Deref so handlers can do `state.redis` instead of `state.inner.redis`
impl std::ops::Deref for AppState {
    type Target = AppStateInner;
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}
