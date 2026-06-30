//! In-memory user profile cache backed by Postgres.

use crate::services::cdn;
use crate::services::pg::users as pg_users;
use dashmap::DashMap;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::{Duration, Instant};

const CACHE_TTL_SECS: u64 = 300; // 5 minutes
const CLEANUP_INTERVAL_SECS: u64 = 300; // sweep every 5 minutes
const MAX_CACHE_SIZE: usize = 10_000; // hard cap to bound memory usage

#[derive(Debug, Clone)]
pub struct CachedUserProfile {
    pub username: String,
    pub avatar_url: Option<String>,
    pub display_name: Option<String>,
    pub is_deleted: bool,
    cached_at: Instant,
}

impl CachedUserProfile {
    fn is_fresh(&self) -> bool {
        self.cached_at.elapsed() < Duration::from_secs(CACHE_TTL_SECS)
    }
}

pub struct UserProfileCache {
    entries: DashMap<i64, CachedUserProfile>,
}

impl UserProfileCache {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            entries: DashMap::new(),
        })
    }

    /// Cache hit: return immediately. Cache miss: fetch from PG, fold
    /// into the cache, return resolved avatar URL (CDN-rewritten).
    pub async fn get_or_fetch(
        &self,
        pool: &PgPool,
        user_id: i64,
    ) -> (String, Option<String>, Option<String>) {
        if let Some(entry) = self.entries.get(&user_id) {
            if entry.is_fresh() {
                return (
                    entry.username.clone(),
                    cdn::resolve(entry.avatar_url.as_deref()),
                    entry.display_name.clone(),
                );
            }
        }

        let (username, avatar_url, display_name, is_deleted) =
            match pg_users::by_id(pool, user_id).await {
                Ok(Some(u)) => (
                    u.username,
                    u.avatar_url,
                    u.display_name,
                    u.deleted_at.is_some(),
                ),
                _ => match crate::services::pg::bots::by_id(pool, user_id).await {
                    Ok(Some(bot)) => (bot.name, bot.avatar_url, None, false),
                    _ => ("Unknown".to_string(), None, None, false),
                },
            };

        // Hard-cap eviction (10% oldest) before insert.
        if self.entries.len() >= MAX_CACHE_SIZE {
            self.evict_oldest();
        }

        self.entries.insert(
            user_id,
            CachedUserProfile {
                username: username.clone(),
                avatar_url: avatar_url.clone(),
                display_name: display_name.clone(),
                is_deleted,
                cached_at: Instant::now(),
            },
        );

        (username, cdn::resolve(avatar_url.as_deref()), display_name)
    }

    /// Resolve N user profiles in at most one PG round-trip (only
    /// for cache misses). Returned map keys every requested id; ids
    /// not in PG resolve to ("Unknown", None, None) — same fallback
    /// shape as `get_or_fetch`. Avatars are CDN-resolved.
    ///
    /// Why: the GET /messages handler used to loop `get_or_fetch` per
    /// row, fanning out to N sequential PG SELECTs on cold cache. With
    /// this method, one batch SELECT covers every miss; cache hits
    /// short-circuit before we ever build the miss list.
    pub async fn get_or_fetch_many(
        &self,
        pool: &PgPool,
        user_ids: &[i64],
    ) -> std::collections::HashMap<i64, (String, Option<String>, Option<String>)> {
        let mut out: std::collections::HashMap<i64, (String, Option<String>, Option<String>)> =
            std::collections::HashMap::with_capacity(user_ids.len());
        let mut misses: Vec<i64> = Vec::new();

        for id in user_ids {
            if out.contains_key(id) {
                continue;
            }
            if let Some(entry) = self.entries.get(id) {
                if entry.is_fresh() {
                    out.insert(
                        *id,
                        (
                            entry.username.clone(),
                            cdn::resolve(entry.avatar_url.as_deref()),
                            entry.display_name.clone(),
                        ),
                    );
                    continue;
                }
            }
            misses.push(*id);
        }

        if !misses.is_empty() {
            // Ensure cap before inserting batch (eviction may run once).
            if self.entries.len() + misses.len() >= MAX_CACHE_SIZE {
                self.evict_oldest();
            }

            match pg_users::by_ids(pool, &misses).await {
                Ok(rows) => {
                    let now = Instant::now();
                    let mut found: std::collections::HashSet<i64> =
                        std::collections::HashSet::with_capacity(rows.len());
                    for u in rows {
                        found.insert(u.id);
                        let avatar_url = u.avatar_url.clone();
                        let display_name = u.display_name.clone();
                        let username = u.username.clone();
                        let is_deleted = u.deleted_at.is_some();
                        self.entries.insert(
                            u.id,
                            CachedUserProfile {
                                username: username.clone(),
                                avatar_url: avatar_url.clone(),
                                display_name: display_name.clone(),
                                is_deleted,
                                cached_at: now,
                            },
                        );
                        out.insert(
                            u.id,
                            (username, cdn::resolve(avatar_url.as_deref()), display_name),
                        );
                    }
                    let missing: Vec<i64> = misses
                        .iter()
                        .copied()
                        .filter(|id| !found.contains(id))
                        .collect();
                    if !missing.is_empty() {
                        match crate::services::pg::bots::by_ids(pool, &missing).await {
                            Ok(bots) => {
                                for bot in bots {
                                    found.insert(bot.id);
                                    let avatar_url = bot.avatar_url.clone();
                                    let username = bot.name.clone();
                                    self.entries.insert(
                                        bot.id,
                                        CachedUserProfile {
                                            username: username.clone(),
                                            avatar_url: avatar_url.clone(),
                                            display_name: None,
                                            is_deleted: false,
                                            cached_at: now,
                                        },
                                    );
                                    out.insert(
                                        bot.id,
                                        (username, cdn::resolve(avatar_url.as_deref()), None),
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    error = %e,
                                    n = missing.len(),
                                    "user_cache.get_or_fetch_many: bot fallback by_ids failed"
                                );
                            }
                        }
                    }
                    // Unknown / deleted-from-table ids: fill the
                    // sentinel so the caller's HashMap lookup never
                    // panics. Don't pollute the cache with them — a
                    // re-fetch a few seconds later might find a row
                    // that just got created.
                    for id in &misses {
                        if !found.contains(id) {
                            out.insert(*id, ("Unknown".to_string(), None, None));
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, n = misses.len(), "user_cache.get_or_fetch_many: pg by_ids failed");
                    for id in &misses {
                        out.insert(*id, ("Unknown".to_string(), None, None));
                    }
                }
            }
        }

        out
    }

    pub async fn is_deleted(&self, pool: &PgPool, user_id: i64) -> bool {
        if let Some(entry) = self.entries.get(&user_id) {
            if entry.is_fresh() {
                return entry.is_deleted;
            }
        }
        let _ = self.get_or_fetch(pool, user_id).await;
        self.entries
            .get(&user_id)
            .map(|e| e.is_deleted)
            .unwrap_or(false)
    }

    /// AppState-aware wrapper kept for call-site compatibility.
    pub async fn get_or_fetch_vdb(
        &self,
        state: &crate::state::AppState,
        user_id: i64,
    ) -> (String, Option<String>, Option<String>) {
        self.get_or_fetch(&state.pg, user_id).await
    }

    pub async fn is_deleted_vdb(&self, state: &crate::state::AppState, user_id: i64) -> bool {
        self.is_deleted(&state.pg, user_id).await
    }

    pub fn invalidate(&self, user_id: i64) {
        self.entries.remove(&user_id);
    }

    /// Sync cache-only check: is this user a loadtest synthetic user?
    /// Returns false on cache miss — safe default (caller falls back to
    /// normal rate limiting). The cache is expected to be warm from
    /// IDENTIFY by the time a loadtest user actually sends messages.
    pub fn is_loadtest_user(&self, user_id: i64) -> bool {
        self.entries
            .get(&user_id)
            .map(|e| e.username.starts_with("loadtest_user_"))
            .unwrap_or(false)
    }

    /// 10%-oldest eviction.
    fn evict_oldest(&self) {
        let evict_count = MAX_CACHE_SIZE / 10;
        let mut entries: Vec<(i64, Instant)> = self
            .entries
            .iter()
            .map(|e| (*e.key(), e.value().cached_at))
            .collect();
        entries.sort_by_key(|(_, t)| *t);
        for (key, _) in entries.into_iter().take(evict_count) {
            self.entries.remove(&key);
        }
    }

    /// Background sweeper. Drops stale entries on a fixed cadence and
    /// re-applies the hard cap if traffic blew it open.
    pub fn start_cleanup_task(self: &Arc<Self>) {
        let cache = Arc::clone(self);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(CLEANUP_INTERVAL_SECS)).await;
                let before = cache.entries.len();
                cache.entries.retain(|_, entry| entry.is_fresh());
                let after_stale = cache.entries.len();
                if before > after_stale {
                    tracing::debug!(
                        "User profile cache cleanup: evicted {} stale entries",
                        before - after_stale
                    );
                }
                if cache.entries.len() > MAX_CACHE_SIZE {
                    cache.evict_oldest();
                    tracing::debug!(
                        "User profile cache capped: {} -> {} entries",
                        after_stale,
                        cache.entries.len()
                    );
                }
            }
        });
    }
}
