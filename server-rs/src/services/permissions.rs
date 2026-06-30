// ─── Permission Cache ────────────────────────────────────────────────────────
//
// Lazy, in-memory permission cache using DashMap.
//
// Design principles:
//   • IDENTIFY only populates lightweight user data (server_ids, member_roles,
//     dm_channel_ids) and a channel_index (channel_id → server_id).
//   • Server data (roles, channel overrides) is lazy-loaded on first access
//     and stored in a per-server ServerCacheEntry with sorted Vecs for
//     cache-line-friendly binary search.
//   • Redis pub/sub cache invalidation broadcasts changes across instances.
//
// Discord-style permission resolution:
//   1. channel_index → server_id lookup
//   2. DM → check dm_channel_ids, no permission bits
//   3. Owner → all permissions (!0)
//   4. Base = @everyone role permissions
//   5. Merge assigned role permissions via OR
//   6. ADMINISTRATOR → all permissions
//   7. Apply channel overrides (@everyone first, then role overrides)
// ─────────────────────────────────────────────────────────────────────────────

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::task::JoinHandle;

use crate::error::{AppError, AppResult};
use crate::services::pg::{channels as pg_channels, roles as pg_roles, servers as pg_servers};
use sqlx::PgPool;

// ─── Permission Bit Constants ────────────────────────────────────────────────
// Must match packages/shared/src/constants/permissions.ts exactly.

pub mod bits {
    pub const VIEW_CHANNEL: i64 = 1 << 0;
    pub const SEND_MESSAGES: i64 = 1 << 1;
    pub const MANAGE_MESSAGES: i64 = 1 << 2;
    pub const MANAGE_CHANNELS: i64 = 1 << 3;
    pub const MANAGE_SERVER: i64 = 1 << 4;
    pub const MANAGE_ROLES: i64 = 1 << 5;
    pub const KICK_MEMBERS: i64 = 1 << 6;
    pub const BAN_MEMBERS: i64 = 1 << 7;
    pub const ATTACH_FILES: i64 = 1 << 8;
    pub const USE_CUSTOM_EMOJIS: i64 = 1 << 9;
    pub const ADMINISTRATOR: i64 = 1 << 10;
    pub const CREATE_INVITE: i64 = 1 << 11;
    pub const CONNECT: i64 = 1 << 12;
    pub const SPEAK: i64 = 1 << 13;
    pub const MUTE_MEMBERS: i64 = 1 << 14;
    pub const DEAFEN_MEMBERS: i64 = 1 << 15;

    /// Check if a permission bitfield includes the given bit(s).
    /// Returns true immediately if ADMINISTRATOR is set.
    pub fn has(perms: i64, perm: i64) -> bool {
        if perms & ADMINISTRATOR != 0 {
            return true;
        }
        perms & perm == perm
    }
}

// ─── Cache Result ────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum CacheResult<T> {
    /// Cache hit with data.
    Hit(T),
    /// Not cached — caller should fall back to DB.
    Miss,
    /// Cached and access denied.
    Denied(AppError),
}

// ─── Cache Structs ───────────────────────────────────────────────────────────

/// Role data stored in sorted Vec (sorted by id for binary search).
#[derive(Debug, Clone)]
pub struct CachedRole {
    pub id: i64,
    pub permissions: i64,
    pub position: i32,
    pub color_only: bool,
}

/// Channel override stored in sorted Vec (sorted by role_id for binary search).
#[derive(Debug, Clone)]
pub struct CachedOverride {
    pub role_id: i64,
    pub allow: i64,
    pub deny: i64,
}

/// Channel data stored inside ServerCacheEntry (sorted by id for binary search).
#[derive(Debug, Clone)]
pub struct CachedChannel {
    pub id: i64,
    pub channel_type: i32,
    pub overrides: Vec<CachedOverride>, // sorted by role_id
}

/// Per-server cache entry, lazy-loaded on first access.
#[derive(Debug, Clone)]
pub struct ServerCacheEntry {
    pub owner_id: i64,
    /// The @everyone role id (position == 0).
    pub everyone_role_id: i64,
    /// All roles for this server, sorted by role id for binary search.
    pub roles: Vec<CachedRole>,
    /// All channels for this server, sorted by channel id for binary search.
    pub channels: Vec<CachedChannel>,
    /// Number of users referencing this server entry.
    pub ref_count: u32,
    /// When this entry was last accessed (for eviction).
    pub last_accessed: Instant,
}

impl ServerCacheEntry {
    /// Find a role by id via binary search.
    pub fn find_role(&self, role_id: i64) -> Option<&CachedRole> {
        self.roles
            .binary_search_by_key(&role_id, |r| r.id)
            .ok()
            .map(|idx| &self.roles[idx])
    }

    /// Find a channel by id via binary search.
    pub fn find_channel(&self, channel_id: i64) -> Option<&CachedChannel> {
        self.channels
            .binary_search_by_key(&channel_id, |c| c.id)
            .ok()
            .map(|idx| &self.channels[idx])
    }
}

impl CachedChannel {
    /// Find an override for a role via binary search.
    pub fn find_override(&self, role_id: i64) -> Option<&CachedOverride> {
        self.overrides
            .binary_search_by_key(&role_id, |o| o.role_id)
            .ok()
            .map(|idx| &self.overrides[idx])
    }
}

/// Lightweight user cache entry populated at IDENTIFY.
#[derive(Debug, Clone)]
pub struct UserCacheEntry {
    /// Set of server IDs this user is a member of.
    pub server_ids: HashSet<i64>,
    /// Per-server role assignments: server_id → set of role_ids.
    pub member_roles: HashMap<i64, HashSet<i64>>,
    /// DM channel IDs this user participates in.
    pub dm_channel_ids: HashSet<i64>,
    /// Last activity timestamp for idle sweep.
    pub last_active: Instant,
}

// ─── Input Data for populate_from_identify ───────────────────────────────────

pub struct IdentifyCacheData {
    pub server_ids: Vec<i64>,
    pub servers: Vec<IdentifyServer>,
    pub member_roles: Vec<(i64, i64)>, // (server_id, role_id)
    pub dm_channel_ids: Vec<i64>,
    /// Lightweight channel index data: (channel_id, server_id).
    /// Used to populate the channel_index for fast channel→server lookups.
    pub channel_index_entries: Vec<(i64, i64)>,
}

pub struct IdentifyServer {
    pub id: i64,
    pub owner_id: i64,
}

// ─── Cache Invalidation Events (for Redis pub/sub) ──────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(tag = "type")]
pub enum CacheInvalidationEvent {
    /// Server roles were created/updated/deleted.
    ServerRolesChanged { server_id: i64 },
    /// A user's role assignments changed in a server.
    UserRolesChanged { user_id: i64, server_id: i64 },
    /// Channel permission overrides changed.
    ChannelOverridesChanged { channel_id: i64, server_id: i64 },
    /// Server data changed (owner, etc.).
    ServerChanged { server_id: i64 },
}

// ─── Permission Cache ────────────────────────────────────────────────────────

const CLEANUP_GRACE_SECS: u64 = 60;
const IDLE_SWEEP_INTERVAL_SECS: u64 = 300; // 5 minutes
const IDLE_TIMEOUT_SECS: u64 = 14400; // 4 hours

pub struct PermissionCache {
    /// Lightweight channel → server mapping. Populated at IDENTIFY for all
    /// server channels the user belongs to. DM channels map to 0.
    channel_index: DashMap<i64, i64>,
    /// Per-server cache entries, lazy-loaded on first permission check.
    servers: DashMap<i64, ServerCacheEntry>,
    /// Per-user cache entries, populated at IDENTIFY.
    users: DashMap<i64, UserCacheEntry>,
    /// Pending cleanup timers for user eviction.
    cleanup_timers: DashMap<i64, JoinHandle<()>>,
    /// Postgres pool — used for every lazy-load, fallback, and
    /// invalidation read path. The DashMap caches in front of this
    /// (server roles + channels + member_roles) are the load-bearing
    /// optimisation; the pool is only hit on cache miss.
    pg: PgPool,
}

impl PermissionCache {
    pub fn new(pg: PgPool) -> Arc<Self> {
        Arc::new(Self {
            channel_index: DashMap::new(),
            servers: DashMap::new(),
            users: DashMap::new(),
            cleanup_timers: DashMap::new(),
            pg,
        })
    }

    // ─── Populate from IDENTIFY ──────────────────────────────────────

    /// Populate the cache from data fetched during the IDENTIFY handshake.
    /// Only lightweight data is cached — server details are lazy-loaded.
    pub fn populate_from_identify(&self, user_id: i64, data: IdentifyCacheData) {
        // Cancel any pending cleanup for this user
        self.cancel_cleanup(user_id);

        // Populate channel_index (channel_id → server_id)
        for &(channel_id, server_id) in &data.channel_index_entries {
            self.channel_index.insert(channel_id, server_id);
        }

        // DM channels map to 0 in channel_index
        for &dm_id in &data.dm_channel_ids {
            self.channel_index.insert(dm_id, 0);
        }

        // Increment ref counts on server entries (if they exist from other users)
        for srv in &data.servers {
            if let Some(mut entry) = self.servers.get_mut(&srv.id) {
                entry.ref_count += 1;
                entry.owner_id = srv.owner_id; // keep up to date
            }
            // Don't create server entries — they are lazy-loaded on first access
        }

        // Populate user entry
        let mut member_roles: HashMap<i64, HashSet<i64>> = HashMap::new();
        for &(server_id, role_id) in &data.member_roles {
            member_roles.entry(server_id).or_default().insert(role_id);
        }

        self.users.insert(
            user_id,
            UserCacheEntry {
                server_ids: data.server_ids.iter().copied().collect(),
                member_roles,
                dm_channel_ids: data.dm_channel_ids.iter().copied().collect(),
                last_active: Instant::now(),
            },
        );

        tracing::info!(
            user_id,
            servers = data.server_ids.len(),
            channel_index = data.channel_index_entries.len(),
            dm_channels = data.dm_channel_ids.len(),
            "Permission cache populated from IDENTIFY"
        );
    }

    // ─── Lazy Loading ────────────────────────────────────────────────

    /// Lazy-load a server's roles and channel data from VerdantDB.
    /// Returns true if the server was loaded, false if it was already cached.
    pub async fn lazy_load_server(&self, server_id: i64) -> AppResult<bool> {
        // Check if already loaded
        if let Some(mut entry) = self.servers.get_mut(&server_id) {
            entry.last_accessed = Instant::now();
            return Ok(false);
        }

        tracing::debug!(server_id, "Lazy-loading server into permission cache (PG)");

        // Fetch server owner
        let server_record = pg_servers::by_id(&self.pg, server_id)
            .await
            .map_err(|e| {
                tracing::error!(server_id, error = %e, "lazy_load_server: PG server read failed");
                AppError::Internal
            })?
            .ok_or(AppError::NotFound("server"))?;
        let owner_id = server_record.owner_id;

        // Fetch roles, channels, and overrides in parallel, then merge
        // overrides onto channel rows.
        let (roles_res, channels_res, overrides_res) = tokio::join!(
            pg_roles::list_for_server(&self.pg, server_id),
            pg_channels::list_for_server(&self.pg, server_id),
            pg_channels::list_overrides_for_server(&self.pg, server_id),
        );
        let pg_roles_vec = roles_res.map_err(|e| {
            tracing::error!(server_id, error = %e, "lazy_load_server: PG roles read failed");
            AppError::Internal
        })?;
        let pg_channels_vec = channels_res.map_err(|e| {
            tracing::error!(server_id, error = %e, "lazy_load_server: PG channels read failed");
            AppError::Internal
        })?;
        let pg_overrides_vec = overrides_res.map_err(|e| {
            tracing::error!(server_id, error = %e, "lazy_load_server: PG overrides read failed");
            AppError::Internal
        })?;

        // Bucket overrides by channel_id once — single pass.
        let mut overrides_by_channel: std::collections::HashMap<i64, Vec<CachedOverride>> =
            std::collections::HashMap::new();
        for o in pg_overrides_vec {
            overrides_by_channel
                .entry(o.channel_id)
                .or_default()
                .push(CachedOverride {
                    role_id: o.role_id,
                    allow: o.allow_bits,
                    deny: o.deny_bits,
                });
        }

        // Build sorted roles
        let mut everyone_role_id = 0i64;
        let mut roles: Vec<CachedRole> = pg_roles_vec
            .into_iter()
            .map(|r| {
                if !r.color_only && r.position == 0 {
                    everyone_role_id = r.id;
                }
                CachedRole {
                    id: r.id,
                    permissions: r.permissions,
                    position: r.position,
                    color_only: r.color_only,
                }
            })
            .collect();
        roles.sort_unstable_by_key(|r| r.id);

        // Build sorted channels — merge overrides per channel.
        let mut channels: Vec<CachedChannel> = pg_channels_vec
            .into_iter()
            .map(|c| {
                let mut overrides = overrides_by_channel.remove(&c.id).unwrap_or_default();
                overrides.sort_unstable_by_key(|o| o.role_id);
                CachedChannel {
                    id: c.id,
                    channel_type: c.r#type,
                    overrides,
                }
            })
            .collect();
        channels.sort_unstable_by_key(|c| c.id);

        // Also populate channel_index for any channels we didn't know about
        for ch in &channels {
            self.channel_index.entry(ch.id).or_insert(server_id);
        }

        // Count existing refs (users already connected to this server)
        let ref_count = self
            .users
            .iter()
            .filter(|u| u.value().server_ids.contains(&server_id))
            .count() as u32;

        self.servers.insert(
            server_id,
            ServerCacheEntry {
                owner_id,
                everyone_role_id,
                roles,
                channels,
                ref_count: ref_count.max(1), // at least 1 since someone triggered the load
                last_accessed: Instant::now(),
            },
        );

        tracing::debug!(server_id, "Server lazy-loaded into permission cache");
        Ok(true)
    }

    /// Ensure a server is loaded into cache, loading lazily if needed.
    async fn ensure_server_loaded(&self, server_id: i64) -> AppResult<()> {
        if self.servers.contains_key(&server_id) {
            if let Some(mut entry) = self.servers.get_mut(&server_id) {
                entry.last_accessed = Instant::now();
            }
            return Ok(());
        }
        self.lazy_load_server(server_id).await?;
        Ok(())
    }

    // ─── Permission Computation ──────────────────────────────────────

    /// Compute the effective channel permissions for a user.
    /// Returns None if any required data is missing from cache.
    pub fn compute_permissions(&self, user_id: i64, channel_id: i64) -> Option<i64> {
        // Look up server_id from channel_index
        let server_id = *self.channel_index.get(&channel_id)?;

        if server_id == 0 {
            // DM channels don't use permission bits — access is binary
            return None;
        }

        let server_ref = self.servers.get(&server_id)?;
        let server = server_ref.value();

        // Owner gets everything
        if server.owner_id == user_id {
            return Some(!0i64);
        }

        // Start with @everyone permissions
        let everyone_perms = server
            .find_role(server.everyone_role_id)
            .map(|r| r.permissions)
            .unwrap_or(0);

        let mut perms = everyone_perms;

        // Merge assigned role permissions
        let user_ref = self.users.get(&user_id)?;
        let user = user_ref.value();
        if let Some(role_ids) = user.member_roles.get(&server_id) {
            for role_id in role_ids {
                if let Some(role) = server.find_role(*role_id) {
                    if !role.color_only {
                        perms |= role.permissions;
                    }
                }
            }
        }

        // ADMINISTRATOR bypass
        if perms & bits::ADMINISTRATOR != 0 {
            return Some(!0i64);
        }

        // Apply channel overrides
        if let Some(channel) = server.find_channel(channel_id) {
            // 1. Apply @everyone override first
            if let Some(ov) = channel.find_override(server.everyone_role_id) {
                perms = (perms & !ov.deny) | ov.allow;
            }

            // 2. Accumulate role overrides (merge all allows and denies, then apply)
            let mut role_allow: i64 = 0;
            let mut role_deny: i64 = 0;
            if let Some(role_ids) = user.member_roles.get(&server_id) {
                for role_id in role_ids {
                    let Some(role) = server.find_role(*role_id) else {
                        continue;
                    };
                    if role.color_only {
                        continue;
                    }
                    if let Some(ov) = channel.find_override(*role_id) {
                        role_allow |= ov.allow;
                        role_deny |= ov.deny;
                    }
                }
            }
            perms = (perms & !role_deny) | role_allow;
        }

        Some(perms)
    }

    /// Compute server-level permissions (no channel overrides).
    pub fn compute_server_permissions(&self, user_id: i64, server_id: i64) -> Option<i64> {
        let server_ref = self.servers.get(&server_id)?;
        let server = server_ref.value();

        if server.owner_id == user_id {
            return Some(!0i64);
        }

        let everyone_perms = server
            .find_role(server.everyone_role_id)
            .map(|r| r.permissions)
            .unwrap_or(0);

        let mut perms = everyone_perms;

        let user_ref = self.users.get(&user_id)?;
        let user = user_ref.value();
        if let Some(role_ids) = user.member_roles.get(&server_id) {
            for role_id in role_ids {
                if let Some(role) = server.find_role(*role_id) {
                    if !role.color_only {
                        perms |= role.permissions;
                    }
                }
            }
        }

        if perms & bits::ADMINISTRATOR != 0 {
            return Some(!0i64);
        }

        Some(perms)
    }

    // ─── Access Verification ─────────────────────────────────────────

    /// Cache-first channel access verification.
    /// Returns CacheResult::Hit(server_id) for server channels,
    /// CacheResult::Hit(0) for DMs, or CacheResult::Denied/Miss.
    pub fn verify_access(&self, user_id: i64, channel_id: i64) -> CacheResult<i64> {
        // Look up server_id from channel_index
        let server_id = match self.channel_index.get(&channel_id) {
            Some(sid) => *sid,
            None => return CacheResult::Miss,
        };

        let user_ref = match self.users.get(&user_id) {
            Some(u) => u,
            None => return CacheResult::Miss,
        };

        if server_id == 0 {
            // DM channel
            if user_ref.dm_channel_ids.contains(&channel_id) {
                return CacheResult::Hit(0);
            } else {
                return CacheResult::Denied(AppError::NotMember);
            }
        }

        // Server channel — check membership
        if !user_ref.server_ids.contains(&server_id) {
            return CacheResult::Denied(AppError::NotMember);
        }

        // Drop user_ref before compute_permissions (which also takes a user ref)
        drop(user_ref);

        // Check VIEW_CHANNEL permission (only if server is loaded)
        if let Some(perms) = self.compute_permissions(user_id, channel_id) {
            if !bits::has(perms, bits::VIEW_CHANNEL) {
                return CacheResult::Denied(AppError::MissingPermission);
            }
        }
        // If server not loaded, we still know they're a member — allow access
        // (permissions will be checked when the server is lazy-loaded)

        CacheResult::Hit(server_id)
    }

    /// Check if a user has a specific permission in a channel.
    /// Returns true if permission is granted, false if denied, None if cache miss.
    /// Get the @everyone role's permissions for a server from cache.
    fn get_server_everyone_perms(&self, server_id: i64) -> Option<i64> {
        let server = self.servers.get(&server_id)?;
        server
            .find_role(server.everyone_role_id)
            .map(|r| r.permissions)
    }

    pub fn has_channel_permission(
        &self,
        user_id: i64,
        channel_id: i64,
        permission: i64,
    ) -> Option<bool> {
        let perms = self.compute_permissions(user_id, channel_id)?;
        Some(bits::has(perms, permission))
    }

    /// Check if a user has a specific permission at the server level.
    /// Returns true if permission is granted, false if denied, None if cache miss.
    pub fn has_server_permission(
        &self,
        user_id: i64,
        server_id: i64,
        permission: i64,
    ) -> Option<bool> {
        let perms = self.compute_server_permissions(user_id, server_id)?;
        Some(bits::has(perms, permission))
    }

    /// Collect user_ids of every currently-cached (online) member of
    /// `server_id` who can view a role-gated resource. A user qualifies
    /// if any of the following hold:
    ///   • They are the server owner.
    ///   • They have ADMINISTRATOR (synchronous permission check).
    ///   • They hold at least one role in `allowed_role_ids`.
    ///
    /// Used by the WS broadcast layer to scope FEED_* / ANNOUNCEMENT_*
    /// events to entitled members only. We iterate the permission cache
    /// (which holds ~online users) rather than scanning every server member.
    pub fn collect_entitled_online_members(
        &self,
        server_id: i64,
        allowed_role_ids: &HashSet<i64>,
    ) -> HashSet<i64> {
        let mut out: HashSet<i64> = HashSet::new();

        // Owner is always entitled (short-circuit, even if their
        // member_roles row is somehow missing from the cache).
        if let Some(server) = self.servers.get(&server_id) {
            out.insert(server.owner_id);
        }

        for entry in self.users.iter() {
            let user_id = *entry.key();
            let user = entry.value();
            let Some(roles) = user.member_roles.get(&server_id) else {
                continue;
            };
            if self
                .has_server_permission(user_id, server_id, bits::ADMINISTRATOR)
                .unwrap_or(false)
                || roles.iter().any(|r| allowed_role_ids.contains(r))
            {
                out.insert(user_id);
            }
        }
        out
    }

    /// Collect currently-online server members who can view `channel_id`.
    ///
    /// Used for visibility reconciliation, not topic subscription. Realtime
    /// channel topics are connection-scoped and added only by FOCUS_CHANNEL.
    pub fn collect_online_channel_viewers(&self, server_id: i64, channel_id: i64) -> HashSet<i64> {
        let mut out = HashSet::new();

        for entry in self.users.iter() {
            let user_id = *entry.key();
            let is_member = entry.value().server_ids.contains(&server_id);
            drop(entry);

            if is_member
                && self
                    .has_channel_permission(user_id, channel_id, bits::VIEW_CHANNEL)
                    .unwrap_or(false)
            {
                out.insert(user_id);
            }
        }

        out
    }

    /// Collect currently-online cached members of a server.
    ///
    /// Used after role permission changes to reconcile which connected
    /// clients should gain or lose channel rows. Offline users refetch
    /// channel visibility through READY on their next connection.
    pub fn collect_online_server_members(&self, server_id: i64) -> HashSet<i64> {
        let mut out = HashSet::new();
        for entry in self.users.iter() {
            let user_id = *entry.key();
            if entry.value().server_ids.contains(&server_id) {
                out.insert(user_id);
            }
        }
        out
    }

    /// Check server permission with lazy-load fallback for HTTP handlers.
    /// Returns Ok(()) if permission is granted, Err(AppError) if denied.
    pub async fn check_server_permission(
        &self,
        user_id: i64,
        server_id: i64,
        permission: i64,
    ) -> AppResult<()> {
        // Ensure server is loaded into cache
        self.ensure_server_loaded(server_id).await?;

        // Try cache
        if let Some(has) = self.has_server_permission(user_id, server_id, permission) {
            if !has {
                tracing::warn!(
                    user_id,
                    server_id,
                    permission,
                    "Server permission denied (cached)"
                );
            }
            return if has {
                Ok(())
            } else {
                Err(AppError::MissingPermission)
            };
        }

        // Fallback (user not in cache — shouldn't happen normally)
        tracing::debug!(
            user_id,
            server_id,
            permission,
            "Server permission cache miss after lazy load"
        );
        let perms = self.resolve_perms_from_vdb(user_id, server_id).await?;

        if bits::has(perms, permission) {
            Ok(())
        } else {
            tracing::warn!(
                user_id,
                server_id,
                permission,
                "Server permission denied (storage fallback)"
            );
            Err(AppError::MissingPermission)
        }
    }

    /// Resolve the user's effective server-level permissions from storage.
    /// Shared fallback between `check_server_permission`,
    /// `resolve_server_permissions` and (with overrides applied on top)
    /// `check_channel_permission`. Reads the server record for ownership,
    /// the user's member_roles blob for assigned role ids, and the
    /// per-server role list for the @everyone row + permission bitfields.
    async fn resolve_perms_from_vdb(&self, user_id: i64, server_id: i64) -> AppResult<i64> {
        // Server ownership → all bits
        let server = pg_servers::by_id(&self.pg, server_id)
            .await
            .map_err(|e| {
                tracing::error!(server_id, error = %e, "perms: PG server read failed");
                AppError::Internal
            })?
            .ok_or(AppError::NotFound("server"))?;
        if server.owner_id == user_id {
            return Ok(!0i64);
        }

        // All roles for the server (@everyone + custom)
        let server_roles = pg_roles::list_for_server(&self.pg, server_id)
            .await
            .map_err(|e| {
                tracing::error!(server_id, error = %e, "perms: PG roles read failed");
                AppError::Internal
            })?;

        // The user's role assignments for *this* server
        let user_role_ids = self
            .vdb_user_role_ids_for_server(user_id, server_id)
            .await?;

        // Start with @everyone (position 0), then OR in each assigned role
        let mut perms: i64 = 0;
        for role in &server_roles {
            if role.color_only {
                continue;
            }
            if role.position == 0 || user_role_ids.contains(&role.id) {
                perms |= role.permissions;
            }
        }
        Ok(perms)
    }

    /// Fetch the role ids assigned to `user_id` within `server_id`.
    async fn vdb_user_role_ids_for_server(
        &self,
        user_id: i64,
        server_id: i64,
    ) -> AppResult<HashSet<i64>> {
        // Function name kept for call-site compatibility; backend is PG.
        let role_ids = pg_roles::list_role_ids(&self.pg, user_id, server_id)
            .await
            .map_err(|e| {
                tracing::error!(user_id, error = %e, "perms: PG member_roles read failed");
                AppError::Internal
            })?;
        Ok(role_ids.into_iter().collect())
    }

    /// Resolve a user's effective server-level permissions with lazy-load fallback.
    pub async fn resolve_server_permissions(&self, user_id: i64, server_id: i64) -> AppResult<i64> {
        // Ensure server is loaded
        self.ensure_server_loaded(server_id).await?;

        // Try cache first
        if let Some(perms) = self.compute_server_permissions(user_id, server_id) {
            return Ok(perms);
        }

        // Storage fallback shared by all server-level lookups.
        let perms = self.resolve_perms_from_vdb(user_id, server_id).await?;

        if perms & bits::ADMINISTRATOR != 0 {
            return Ok(!0i64);
        }
        Ok(perms)
    }

    /// Check channel permission with lazy-load fallback for HTTP handlers.
    ///
    /// Handles two cases:
    /// 1. WS-connected users: user data is in cache → fast cache check
    /// 2. HTTP-only users: user data NOT in cache → full storage computation
    ///    including channel overrides (prevents the deny-bypass bug)
    pub async fn check_channel_permission(
        &self,
        user_id: i64,
        channel_id: i64,
        server_id: i64,
        permission: i64,
    ) -> AppResult<()> {
        // Ensure server is loaded into cache
        self.ensure_server_loaded(server_id).await?;

        // Try cache (works when user is WS-connected and data is populated)
        if let Some(has) = self.has_channel_permission(user_id, channel_id, permission) {
            if !has {
                tracing::warn!(
                    user_id,
                    channel_id,
                    server_id,
                    permission,
                    "Channel permission denied (cached)"
                );
            }
            return if has {
                Ok(())
            } else {
                Err(AppError::MissingPermission)
            };
        }

        // Cache miss: compute permissions from storage, including channel overrides.
        tracing::info!(
            user_id,
            channel_id,
            server_id,
            permission,
            "Channel permission cache miss — computing from storage"
        );

        // 1. Get the user's roles in this server
        let user_role_ids = self
            .vdb_user_role_ids_for_server(user_id, server_id)
            .await?;

        // 2. Start with @everyone permissions
        let mut perms = self.get_server_everyone_perms(server_id).unwrap_or(0);

        // 3. Merge assigned role permissions
        if let Some(server) = self.servers.get(&server_id) {
            for role_id in &user_role_ids {
                if let Some(role) = server.find_role(*role_id) {
                    if !role.color_only {
                        perms |= role.permissions;
                    }
                }
            }
        }

        // 4. ADMINISTRATOR bypass
        if perms & bits::ADMINISTRATOR != 0 {
            return Ok(());
        }

        // 5. Apply channel overrides — overrides live in their own
        //    table now, so we just fetch them by channel_id (the
        //    channel record itself isn't needed for the override
        //    application below).
        let pg_overrides = pg_channels::list_overrides(&self.pg, channel_id)
            .await
            .map_err(|e| {
                tracing::error!(channel_id, error = %e, "check_channel_permission: PG overrides read failed");
                AppError::Internal
            })?;
        let overrides: Vec<CachedOverride> = pg_overrides
            .into_iter()
            .map(|o| CachedOverride {
                role_id: o.role_id,
                allow: o.allow_bits,
                deny: o.deny_bits,
            })
            .collect();

        // Find @everyone role ID
        let everyone_role_id = self
            .servers
            .get(&server_id)
            .map(|s| s.everyone_role_id)
            .unwrap_or(0);

        // Apply @everyone override first
        for ov in &overrides {
            if ov.role_id == everyone_role_id {
                perms = (perms & !ov.deny) | ov.allow;
                break;
            }
        }

        // Accumulate role overrides
        let mut role_allow: i64 = 0;
        let mut role_deny: i64 = 0;
        for ov in &overrides {
            let role_is_permission_role = self
                .servers
                .get(&server_id)
                .and_then(|server| server.find_role(ov.role_id).map(|role| !role.color_only))
                .unwrap_or(true);
            if role_is_permission_role && user_role_ids.contains(&ov.role_id) {
                role_allow |= ov.allow;
                role_deny |= ov.deny;
            }
        }
        perms = (perms & !role_deny) | role_allow;

        if bits::has(perms, permission) {
            Ok(())
        } else {
            tracing::info!(
                user_id,
                channel_id,
                server_id,
                permission,
                perms,
                "Channel permission denied (storage computed)"
            );
            Err(AppError::MissingPermission)
        }
    }

    // ─── Cleanup & Eviction ──────────────────────────────────────────

    /// Schedule cache eviction for a user after the grace period.
    pub fn schedule_cleanup(self: &Arc<Self>, user_id: i64) {
        tracing::debug!(
            user_id,
            grace_secs = CLEANUP_GRACE_SECS,
            "Scheduling permission cache cleanup"
        );
        let cache = Arc::clone(self);
        let handle = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(CLEANUP_GRACE_SECS)).await;
            cache.evict_user(user_id);
        });

        // Store handle (replacing any previous one)
        if let Some((_key, old_handle)) = self.cleanup_timers.remove(&user_id) {
            old_handle.abort();
        }
        self.cleanup_timers.insert(user_id, handle);
    }

    /// Cancel pending cleanup for a user (called on reconnect).
    pub fn cancel_cleanup(&self, user_id: i64) {
        if let Some((_key, handle)) = self.cleanup_timers.remove(&user_id) {
            handle.abort();
        }
    }

    /// Evict all cached data for a user.
    fn evict_user(&self, user_id: i64) {
        let user = match self.users.remove(&user_id) {
            Some((_k, u)) => u,
            None => return,
        };

        let server_count = user.server_ids.len();
        // Decrement ref counts on servers
        for server_id in &user.server_ids {
            self.decrement_server_ref(*server_id);
        }

        // Remove DM channels from channel_index
        for dm_id in &user.dm_channel_ids {
            // Only remove if no other user references this DM
            // (DMs are shared — check if any other user has it)
            let other_has_it = self
                .users
                .iter()
                .any(|u| u.value().dm_channel_ids.contains(dm_id));
            if !other_has_it {
                self.channel_index.remove(dm_id);
            }
        }

        self.cleanup_timers.remove(&user_id);
        tracing::info!(user_id, servers = server_count, "Permission cache evicted");
    }

    /// Decrement a server's ref count. If it reaches 0, evict server data.
    fn decrement_server_ref(&self, server_id: i64) {
        let should_evict = {
            let mut entry = match self.servers.get_mut(&server_id) {
                Some(e) => e,
                None => return,
            };
            entry.ref_count = entry.ref_count.saturating_sub(1);
            entry.ref_count == 0
        };

        if should_evict {
            self.evict_server_data(server_id);
        }
    }

    /// Remove all cached data for a server.
    fn evict_server_data(&self, server_id: i64) {
        if let Some((_, entry)) = self.servers.remove(&server_id) {
            // Remove channel_index entries for this server's channels
            for ch in &entry.channels {
                self.channel_index.remove(&ch.id);
            }
        }
    }

    /// Start the idle sweep background task. Runs every 5 minutes, evicts
    /// users inactive for 4+ hours.
    pub fn start_idle_sweep(self: &Arc<Self>) {
        let cache = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(IDLE_SWEEP_INTERVAL_SECS));
            loop {
                interval.tick().await;
                let cutoff = Instant::now() - Duration::from_secs(IDLE_TIMEOUT_SECS);
                let stale_users: Vec<i64> = cache
                    .users
                    .iter()
                    .filter(|entry| entry.value().last_active < cutoff)
                    .map(|entry| *entry.key())
                    .collect();

                for user_id in &stale_users {
                    // Cancel any pending cleanup timer before evicting (avoids orphaned timer entries)
                    if let Some((_, handle)) = cache.cleanup_timers.remove(user_id) {
                        handle.abort();
                    }
                    cache.evict_user(*user_id);
                }

                // Also evict server entries that haven't been accessed recently
                // and have no active refs
                let server_cutoff = Instant::now() - Duration::from_secs(IDLE_TIMEOUT_SECS);
                let stale_servers: Vec<i64> = cache
                    .servers
                    .iter()
                    .filter(|entry| {
                        entry.value().ref_count == 0 && entry.value().last_accessed < server_cutoff
                    })
                    .map(|entry| *entry.key())
                    .collect();

                for server_id in stale_servers {
                    cache.evict_server_data(server_id);
                }
            }
        });
    }

    // ─── Invalidation ────────────────────────────────────────────────

    /// Invalidate a user's role assignments for a specific server.
    /// Called when roles are assigned/removed from a member.
    pub async fn invalidate_user_roles(&self, user_id: i64, server_id: i64) {
        let role_ids = match pg_roles::list_role_ids(&self.pg, user_id, server_id).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(user_id, error = %e, "invalidate_user_roles: PG read failed");
                return;
            }
        };

        if let Some(mut user) = self.users.get_mut(&user_id) {
            user.member_roles
                .insert(server_id, role_ids.into_iter().collect());
        }
    }

    /// Re-fetch all roles for a server (called when a role is created/updated/deleted).
    pub async fn invalidate_server_roles(&self, server_id: i64) {
        // Only invalidate if the server is currently cached
        if !self.servers.contains_key(&server_id) {
            return;
        }

        let pg_roles_vec = match pg_roles::list_for_server(&self.pg, server_id).await {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(server_id, error = %e, "invalidate_server_roles: PG read failed");
                return;
            }
        };

        if let Some(mut server) = self.servers.get_mut(&server_id) {
            let mut new_roles: Vec<CachedRole> = pg_roles_vec
                .into_iter()
                .map(|r| {
                    if !r.color_only && r.position == 0 {
                        server.everyone_role_id = r.id;
                    }
                    CachedRole {
                        id: r.id,
                        permissions: r.permissions,
                        position: r.position,
                        color_only: r.color_only,
                    }
                })
                .collect();
            new_roles.sort_unstable_by_key(|r| r.id);
            server.roles = new_roles;
        }
    }

    /// Re-fetch channel overrides (called when overrides are modified).
    /// Overrides live inline on the VdbChannel record post-rip, so one
    /// `query_channel_by_id` fetches the whole new list.
    pub async fn invalidate_channel_overrides(&self, channel_id: i64) {
        // Find server_id from channel_index
        let server_id = match self.channel_index.get(&channel_id) {
            Some(sid) => *sid,
            None => return,
        };

        if server_id == 0 {
            return; // DM channels don't have overrides
        }

        // Only invalidate if the server is currently cached
        if !self.servers.contains_key(&server_id) {
            return;
        }

        // Fetch overrides + channel record (for `channel_type` on the
        // cache-insert branch) in parallel.
        let (overrides_res, channel_res) = tokio::join!(
            pg_channels::list_overrides(&self.pg, channel_id),
            pg_channels::by_id(&self.pg, channel_id),
        );
        let pg_overrides = match overrides_res {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(channel_id, error = %e, "invalidate_channel_overrides: PG read failed");
                return;
            }
        };
        let channel = match channel_res {
            Ok(Some(c)) => c,
            Ok(None) => {
                tracing::debug!(
                    channel_id,
                    "invalidate_channel_overrides: channel not in PG — skipping"
                );
                return;
            }
            Err(e) => {
                tracing::warn!(channel_id, error = %e, "invalidate_channel_overrides: PG channel read failed");
                return;
            }
        };

        let mut new_overrides: Vec<CachedOverride> = pg_overrides
            .into_iter()
            .map(|o| CachedOverride {
                role_id: o.role_id,
                allow: o.allow_bits,
                deny: o.deny_bits,
            })
            .collect();
        new_overrides.sort_unstable_by_key(|o| o.role_id);

        if let Some(mut server) = self.servers.get_mut(&server_id) {
            match server.channels.binary_search_by_key(&channel_id, |c| c.id) {
                Ok(idx) => {
                    server.channels[idx].overrides = new_overrides;
                }
                Err(idx) => {
                    server.channels.insert(
                        idx,
                        CachedChannel {
                            id: channel_id,
                            channel_type: channel.r#type,
                            overrides: new_overrides,
                        },
                    );
                }
            }
        }
    }

    /// Add a channel's metadata to the channel_index.
    pub fn add_channel_meta(&self, channel_id: i64, server_id: i64, channel_type: i32) {
        self.channel_index.insert(channel_id, server_id);

        // If the server is cached, also add the channel to its entry
        if let Some(mut server) = self.servers.get_mut(&server_id) {
            // Insert into sorted position
            let pos = server
                .channels
                .binary_search_by_key(&channel_id, |c| c.id)
                .unwrap_or_else(|pos| pos);
            if pos >= server.channels.len() || server.channels[pos].id != channel_id {
                server.channels.insert(
                    pos,
                    CachedChannel {
                        id: channel_id,
                        channel_type,
                        overrides: Vec::new(),
                    },
                );
            }
        }
    }

    /// Remove a channel from the cache.
    pub fn remove_channel_meta(&self, channel_id: i64) {
        if let Some((_, server_id)) = self.channel_index.remove(&channel_id) {
            // If the server is cached, also remove the channel from its entry
            if let Some(mut server) = self.servers.get_mut(&server_id) {
                if let Ok(idx) = server.channels.binary_search_by_key(&channel_id, |c| c.id) {
                    server.channels.remove(idx);
                }
            }
        }
    }

    /// Add a user to a server in the cache (called on invite accept / server join).
    pub fn add_user_server(&self, user_id: i64, server_id: i64) {
        if let Some(mut user) = self.users.get_mut(&user_id) {
            user.server_ids.insert(server_id);
            user.member_roles.entry(server_id).or_default();
        }

        // Increment ref count if server is loaded
        if let Some(mut server) = self.servers.get_mut(&server_id) {
            server.ref_count += 1;
        }
    }

    /// Remove a user from a server in the cache (called on kick/ban/leave).
    pub fn remove_user_server(&self, user_id: i64, server_id: i64) {
        if let Some(mut user) = self.users.get_mut(&user_id) {
            user.server_ids.remove(&server_id);
            user.member_roles.remove(&server_id);
        }

        self.decrement_server_ref(server_id);
    }

    /// Check if a user is a member of a server from cache.
    /// Returns `Some(true/false)` if the user is in cache, `None` on cache miss.
    pub fn is_member_cached(&self, user_id: i64, server_id: i64) -> Option<bool> {
        let user = self.users.get(&user_id)?;
        Some(user.server_ids.contains(&server_id))
    }

    /// Check membership with cache-first storage fallback.
    /// Returns Ok(()) if member, Err(NotMember) if not.
    ///
    /// Cache is only trusted for positive hits because membership can change after IDENTIFY.
    pub async fn check_membership(&self, user_id: i64, server_id: i64) -> AppResult<()> {
        // Cache hit: member → allow immediately
        if self.is_member_cached(user_id, server_id) == Some(true) {
            return Ok(());
        }

        // Cache miss → verify against PG. The `server_members` table
        // gives a direct (server_id, user_id) probe; cheaper than
        // listing every server the user belongs to.
        let is_member = pg_servers::is_member(&self.pg, server_id, user_id)
            .await
            .map_err(|e| {
                tracing::error!(user_id, error = %e, "check_membership: PG read failed");
                AppError::Internal
            })?;
        if !is_member {
            return Err(AppError::NotMember);
        }

        // Storage confirmed membership; update cache so future checks are fast.
        self.add_user_server(user_id, server_id);
        Ok(())
    }

    /// Register a DM channel in the cache so subsequent access checks are instant.
    pub fn add_dm_channel(&self, user_id: i64, channel_id: i64) {
        // Add to channel_index (DM → server_id 0)
        self.channel_index.entry(channel_id).or_insert(0);
        // Add to user's dm_channel_ids set
        if let Some(mut user) = self.users.get_mut(&user_id) {
            user.dm_channel_ids.insert(channel_id);
        }
    }

    /// Touch user's last_active timestamp (called on WS activity).
    pub fn touch_user(&self, user_id: i64) {
        if let Some(mut user) = self.users.get_mut(&user_id) {
            user.last_active = Instant::now();
        }
    }

    // ─── Delta READY accessors ──────────────────────────────────────

    /// Get the set of server IDs from a cached user. Returns None if user not cached.
    pub fn get_user_server_ids(&self, user_id: i64) -> Option<Vec<i64>> {
        self.users
            .get(&user_id)
            .map(|u| u.server_ids.iter().copied().collect())
    }

    /// Get the set of DM channel IDs from a cached user. Returns None if user not cached.
    pub fn get_user_dm_channel_ids(&self, user_id: i64) -> Option<Vec<i64>> {
        self.users
            .get(&user_id)
            .map(|u| u.dm_channel_ids.iter().copied().collect())
    }

    /// Get all channel IDs from the channel_index that belong to the given server IDs.
    pub fn get_channel_ids_for_servers(&self, server_ids: &[i64]) -> Vec<i64> {
        self.channel_index
            .iter()
            .filter(|entry| server_ids.contains(entry.value()))
            .map(|entry| *entry.key())
            .collect()
    }

    /// Get the highest role position for a user in a server.
    /// Returns 0 if the user only has @everyone, or the highest position among assigned roles.
    /// Server owner always returns i32::MAX.
    pub fn get_highest_role_position(&self, user_id: i64, server_id: i64) -> Option<i32> {
        let server = self.servers.get(&server_id)?;
        if server.owner_id == user_id {
            return Some(i32::MAX);
        }

        let user = self.users.get(&user_id)?;
        let role_ids = user.member_roles.get(&server_id)?;

        let mut highest = 0i32; // @everyone is position 0
        for role_id in role_ids.iter() {
            if let Some(role) = server.find_role(*role_id) {
                if !role.color_only {
                    highest = highest.max(role.position);
                }
            }
        }
        Some(highest)
    }

    /// Check role hierarchy: actor must have a higher role position than target.
    pub async fn check_hierarchy(
        &self,
        actor_id: i64,
        target_id: i64,
        server_id: i64,
    ) -> AppResult<()> {
        // Ensure server is loaded for hierarchy checks
        self.ensure_server_loaded(server_id).await?;

        // Try cache
        if let (Some(actor_pos), Some(target_pos)) = (
            self.get_highest_role_position(actor_id, server_id),
            self.get_highest_role_position(target_id, server_id),
        ) {
            if actor_pos <= target_pos {
                return Err(AppError::WithCode {
                    status: axum::http::StatusCode::FORBIDDEN,
                    code: "ROLE_HIERARCHY",
                    message: "You cannot perform this action on a user with equal or higher role"
                        .into(),
                });
            }
            return Ok(());
        }

        // PG fallback: resolve the highest role position for each user.
        // Server ownership is the short-circuit — owners always outrank
        // everyone, regardless of whether they hold any assigned roles.
        let server = pg_servers::by_id(&self.pg, server_id)
            .await
            .map_err(|e| {
                tracing::error!(server_id, error = %e, "check_hierarchy: PG server read failed");
                AppError::Internal
            })?
            .ok_or(AppError::NotFound("server"))?;
        if server.owner_id == actor_id {
            return Ok(());
        }

        // Pull the role list once and reuse it to resolve actor + target
        // highest positions.
        let server_roles = pg_roles::list_for_server(&self.pg, server_id)
            .await
            .map_err(|e| {
                tracing::error!(server_id, error = %e, "check_hierarchy: PG roles read failed");
                AppError::Internal
            })?;

        let actor_role_ids = self
            .vdb_user_role_ids_for_server(actor_id, server_id)
            .await?;
        let target_role_ids = self
            .vdb_user_role_ids_for_server(target_id, server_id)
            .await?;

        let actor_pos = server_roles
            .iter()
            .filter(|r| actor_role_ids.contains(&r.id))
            .filter(|r| !r.color_only)
            .map(|r| r.position)
            .max()
            .unwrap_or(0);
        let target_pos = server_roles
            .iter()
            .filter(|r| target_role_ids.contains(&r.id))
            .filter(|r| !r.color_only)
            .map(|r| r.position)
            .max()
            .unwrap_or(0);

        if actor_pos <= target_pos {
            return Err(AppError::WithCode {
                status: axum::http::StatusCode::FORBIDDEN,
                code: "ROLE_HIERARCHY",
                message: "You cannot perform this action on a user with equal or higher role"
                    .into(),
            });
        }

        Ok(())
    }

    // ─── Redis Cache Invalidation ────────────────────────────────────

    /// Publish a cache invalidation event to Redis for cross-instance sync.
    /// The `node_id` prefix allows the subscriber to skip self-originated messages.
    pub async fn publish_invalidation(
        &self,
        redis: &fred::clients::Client,
        event: CacheInvalidationEvent,
        node_id: &str,
    ) {
        let json = match serde_json::to_string(&event) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("Failed to serialize cache invalidation event: {e}");
                return;
            }
        };
        let payload = format!("{node_id}\n{json}");
        let redis = redis.clone();
        tokio::spawn(async move {
            let _: Result<i64, _> = fred::interfaces::PubsubInterface::publish(
                &redis,
                "verdant:cache-invalidation",
                payload,
            )
            .await;
        });
    }

    /// Handle an incoming cache invalidation event from Redis.
    /// Evicts stale data so the next access triggers a lazy reload.
    /// Uses `evict_server_data` to also clean up `channel_index` entries.
    pub fn handle_invalidation_event(&self, event: CacheInvalidationEvent) {
        match event {
            CacheInvalidationEvent::ServerRolesChanged { server_id } => {
                // Evict the server entry + channel_index — next access will lazy-reload
                self.evict_server_data(server_id);
                tracing::debug!(server_id, "Evicted server cache (remote role change)");
            }
            CacheInvalidationEvent::UserRolesChanged { user_id, server_id } => {
                // Update the user's member_roles — need to re-fetch from DB
                // For simplicity, just mark the user as needing refresh
                // The lazy_load on next check_server_permission will handle it
                if let Some(mut user) = self.users.get_mut(&user_id) {
                    user.member_roles.remove(&server_id);
                    tracing::debug!(
                        user_id,
                        server_id,
                        "Cleared user role cache (remote change)"
                    );
                }
            }
            CacheInvalidationEvent::ChannelOverridesChanged { server_id, .. } => {
                // Evict the server entry + channel_index — next access will lazy-reload with fresh overrides
                self.evict_server_data(server_id);
                tracing::debug!(server_id, "Evicted server cache (remote override change)");
            }
            CacheInvalidationEvent::ServerChanged { server_id } => {
                self.evict_server_data(server_id);
                tracing::debug!(server_id, "Evicted server cache (remote server change)");
            }
        }
    }

    /// Start the Redis cache invalidation subscriber.
    /// Listens on "verdant:cache-invalidation" and processes events.
    /// Skips messages originating from `node_id` (this instance).
    pub fn start_invalidation_subscriber(
        self: &Arc<Self>,
        subscriber: &fred::clients::SubscriberClient,
        node_id: &str,
    ) {
        let cache = Arc::clone(self);
        let node_id = node_id.to_string();
        let mut rx = fred::interfaces::EventInterface::message_rx(subscriber);

        tokio::spawn(async move {
            tracing::info!("Cache invalidation subscriber started");
            while let Ok(msg) = rx.recv().await {
                let channel = msg.channel.to_string();
                if channel != "verdant:cache-invalidation" {
                    continue;
                }
                let raw: String = match msg.value.convert() {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                // Parse node_id prefix and skip self-originated messages
                let (origin, payload) = match raw.split_once('\n') {
                    Some((origin, json)) => (origin, json),
                    None => ("", raw.as_str()), // Legacy message without prefix
                };
                if origin == node_id {
                    continue;
                }
                match serde_json::from_str::<CacheInvalidationEvent>(payload) {
                    Ok(event) => {
                        tracing::debug!(?event, "Received cache invalidation event");
                        cache.handle_invalidation_event(event);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse cache invalidation event: {e}");
                    }
                }
            }
            tracing::warn!("Cache invalidation subscriber exited");
        });

        // Subscribe to the invalidation channel
        let sub = subscriber.clone();
        tokio::spawn(async move {
            match fred::interfaces::PubsubInterface::subscribe(&sub, "verdant:cache-invalidation")
                .await
            {
                Ok(()) => tracing::info!("Cache invalidation Redis topic subscribed"),
                Err(e) => tracing::warn!(
                    error = %e,
                    "Cache invalidation Redis topic subscribe failed"
                ),
            }
        });
    }
}
