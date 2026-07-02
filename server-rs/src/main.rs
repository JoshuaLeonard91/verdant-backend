use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    http::header,
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post, put},
};
use fred::interfaces::ClientLike;
use serde_json::{Value, json};
use std::{net::SocketAddr, path::PathBuf};
use tower_http::cors::CorsLayer;
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use tracing_subscriber::EnvFilter;

// Module tree lives in src/lib.rs so that auxiliary binaries under
// src/bin/ can share the same crate. Importing via `use` preserves
// the unqualified `state::`, `services::`, etc. references used
// throughout the rest of this file.
use verdant_server::{config, handlers, middleware, services, state, ws};

use state::AppState;

const MIN_GLOBAL_BODY_LIMIT_BYTES: usize = 1024 * 1024;
const MAX_GLOBAL_BODY_LIMIT_BYTES: usize = 1024 * 1024 * 1024;

fn global_body_limit_bytes(local_capabilities: &config::LocalCapabilities) -> usize {
    if !local_capabilities.image_uploads && !local_capabilities.file_sharing {
        return MIN_GLOBAL_BODY_LIMIT_BYTES;
    }
    let configured_upload_cap =
        usize::try_from(local_capabilities.max_upload_bytes).unwrap_or(MAX_GLOBAL_BODY_LIMIT_BYTES);
    configured_upload_cap.clamp(MIN_GLOBAL_BODY_LIMIT_BYTES, MAX_GLOBAL_BODY_LIMIT_BYTES)
}

async fn health(State(state): State<AppState>) -> Json<Value> {
    // PG round-trip — primary storage post-migration.
    let pg_ok = sqlx::query_scalar::<_, i32>("SELECT 1")
        .fetch_one(&state.pg)
        .await
        .map(|v| v == 1)
        .unwrap_or(false);

    let redis_ok: bool = state
        .redis
        .ping::<String>(None)
        .await
        .map(|r| r == "PONG")
        .unwrap_or(false);

    Json(json!({
        "status": if pg_ok && redis_ok { "ok" } else { "degraded" },
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn global_body_limit_tracks_configured_upload_cap_with_minimum() {
        assert_eq!(
            super::global_body_limit_bytes(&local_capabilities(false, false, 0)),
            super::MIN_GLOBAL_BODY_LIMIT_BYTES
        );
        assert_eq!(
            super::global_body_limit_bytes(&local_capabilities(true, false, 25 * 1024 * 1024)),
            25 * 1024 * 1024
        );
        assert_eq!(
            super::global_body_limit_bytes(&local_capabilities(
                true,
                false,
                super::MAX_GLOBAL_BODY_LIMIT_BYTES as u64
            )),
            super::MAX_GLOBAL_BODY_LIMIT_BYTES
        );
    }

    #[test]
    fn global_body_limit_uses_minimum_when_upload_capabilities_are_disabled() {
        assert_eq!(
            super::global_body_limit_bytes(&local_capabilities(false, false, 25 * 1024 * 1024)),
            super::MIN_GLOBAL_BODY_LIMIT_BYTES
        );
    }

    fn local_capabilities(
        image_uploads: bool,
        file_sharing: bool,
        max_upload_bytes: u64,
    ) -> verdant_server::config::LocalCapabilities {
        verdant_server::config::LocalCapabilities {
            image_uploads,
            file_sharing,
            message_attachments: file_sharing,
            voice_chat: true,
            video_streaming: false,
            cross_server_emoji: false,
            animated_avatar: false,
            animated_banner: false,
            member_list_banner: false,
            max_upload_bytes,
            max_voice_bitrate: 96_000,
        }
    }
}

// ─── Static pages ────────────────────────────────────────────────────

const LANDING_HTML: &str = include_str!("static/landing.html");
const STATUS_HTML: &str = include_str!("static/status.html");
const INVITE_HTML: &str = include_str!("static/invite.html");
const TOS_HTML: &str = include_str!("static/tos.html");
const PRIVACY_HTML: &str = include_str!("static/privacy.html");
const BOT_DOCS_HTML: &str = include_str!("static/bot-docs.html");
const SITE_CSS: &str = include_str!("static/assets/site.css");
const TREE_ICON_SVG: &str = include_str!("static/assets/neon-tree-small.svg");
const ROBOTS_TXT: &str = "User-agent: *\nAllow: /\nDisallow: /api/\nDisallow: /ws\nDisallow: /bot-gateway\nDisallow: /app\nSitemap: https://verdant.chat/sitemap.xml\n";
const SITEMAP_XML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://verdant.chat/</loc>
    <lastmod>2026-05-07</lastmod>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
  </url>
  <url>
    <loc>https://verdant.chat/docs/bots</loc>
    <lastmod>2026-05-07</lastmod>
    <changefreq>weekly</changefreq>
    <priority>0.7</priority>
  </url>
  <url>
    <loc>https://verdant.chat/status</loc>
    <lastmod>2026-05-07</lastmod>
    <changefreq>daily</changefreq>
    <priority>0.5</priority>
  </url>
  <url>
    <loc>https://verdant.chat/privacy</loc>
    <lastmod>2026-05-07</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.3</priority>
  </url>
  <url>
    <loc>https://verdant.chat/tos</loc>
    <lastmod>2026-05-07</lastmod>
    <changefreq>monthly</changefreq>
    <priority>0.3</priority>
  </url>
</urlset>
"#;

// Per-page CSP with SHA-256 hashes for inline scripts/styles (no 'unsafe-inline')
const LANDING_CSP: &str = "default-src 'none'; style-src 'self' 'sha256-8HRb25IPsseke/jG71AW5sLkkFEBIkKLvXvZ2zthV+o='; font-src 'none'; img-src 'self' data:; connect-src 'self'; script-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
const STATUS_CSP: &str = "default-src 'none'; style-src 'self' 'sha256-4gRivawG5Ksf/C5pmjWs9MNpIeLn3av7IEJgdTnrFbU=' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; script-src 'sha256-0yZGumvdFMTCGjNA8qpPWLnLxJ5VMYiioOl8qVHlwC0='; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
const INVITE_CSP: &str = "default-src 'none'; style-src 'self' 'sha256-mIBDx5+NmcxeabjukDamPRYWXcDiF274InYXAUXjIIc=' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; script-src 'sha256-1B4WhVY4/yZN+EgNOad8YJDccPcQv8Oq6BUZXEgWaP4='; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

// Next static export uses framework bootstrapping scripts. Keep this limited
// to public site pages only; API, websocket, and app routes do not use it.
const NEXT_STATIC_CSP: &str = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

fn web_dist_dir() -> PathBuf {
    std::env::var_os("WEB_DIST_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("web-dist"))
}

fn web_dist_file(relative_path: &str) -> PathBuf {
    web_dist_dir().join(relative_path)
}

async fn static_page_or_embedded(
    relative_path: &'static str,
    embedded_html: &'static str,
    embedded_csp: &'static str,
    cache_control: &'static str,
) -> Response {
    if let Ok(html) = tokio::fs::read_to_string(web_dist_file(relative_path)).await {
        return (
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (header::CACHE_CONTROL, cache_control),
                (header::CONTENT_SECURITY_POLICY, NEXT_STATIC_CSP),
            ],
            html,
        )
            .into_response();
    }

    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, cache_control),
            (header::CONTENT_SECURITY_POLICY, embedded_csp),
        ],
        embedded_html,
    )
        .into_response()
}

async fn landing_page() -> Response {
    static_page_or_embedded(
        "index.html",
        LANDING_HTML,
        LANDING_CSP,
        "public, max-age=60, must-revalidate",
    )
    .await
}

async fn status_page() -> Response {
    static_page_or_embedded("status.html", STATUS_HTML, STATUS_CSP, "public, max-age=60").await
}

/// Serve the invite redirect page for /invite/:code.
/// The page tries to open verdant://invite/CODE in the desktop app,
/// with a fallback download link if the app isn't installed.
async fn invite_page() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=300"),
            (header::CONTENT_SECURITY_POLICY, INVITE_CSP),
        ],
        INVITE_HTML,
    )
}

// Per-page CSP with SHA-256 hashes for inline styles (no scripts needed)
const TOS_CSP: &str = "default-src 'none'; style-src 'self' 'sha256-ZeUdwXF4Z2PzzV95VXCG1Sv/FL186S7MH4BQIqFgUIo=' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; script-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
const PRIVACY_CSP: &str = "default-src 'none'; style-src 'self' 'sha256-rJReYRzBO8Z9IGmR/3yKtNGX12OCeZjVy8+sqQpmEus=' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; script-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
const BOT_DOCS_CSP: &str = "default-src 'none'; style-src 'self' 'sha256-c1+MsnXkwCEH3R5IPkyjZ3hCWDXvZFCVh7YGLYPH4Qg=' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'; script-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";

async fn tos_page() -> Response {
    static_page_or_embedded("tos.html", TOS_HTML, TOS_CSP, "public, max-age=3600").await
}

async fn privacy_page() -> Response {
    static_page_or_embedded(
        "privacy.html",
        PRIVACY_HTML,
        PRIVACY_CSP,
        "public, max-age=3600",
    )
    .await
}

async fn bot_docs_page() -> Response {
    static_page_or_embedded(
        "docs/bots.html",
        BOT_DOCS_HTML,
        BOT_DOCS_CSP,
        "public, max-age=3600",
    )
    .await
}

async fn site_css() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        SITE_CSS,
    )
}

async fn tree_icon_svg() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/svg+xml; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        TREE_ICON_SVG,
    )
}

async fn downloadable_tree_icon_svg() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/svg+xml; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
            (
                header::CONTENT_DISPOSITION,
                "attachment; filename=\"verdant-icon.svg\"",
            ),
        ],
        TREE_ICON_SVG,
    )
}

async fn robots_txt() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        ROBOTS_TXT,
    )
}

async fn sitemap_xml() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "application/xml; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        SITEMAP_XML,
    )
}

fn auth_routes() -> Router<AppState> {
    Router::new()
        .route("/register", post(handlers::auth::register))
        .route("/login", post(handlers::auth::login))
        .route("/login/2fa", post(handlers::auth::login_2fa))
        .route("/refresh", post(handlers::auth::refresh))
        .route("/logout", post(handlers::auth::logout))
        .route(
            "/revoke-session",
            post(handlers::auth::revoke_session_handler),
        )
        .route("/verify-session", post(handlers::auth::verify_session))
        .route(
            "/resend-session-code",
            post(handlers::auth::resend_session_code),
        )
        .route("/verify-email", post(handlers::email_verify::verify_email))
}

/// Routes that require authentication.
/// Auth middleware is applied as a layer on this router.
fn protected_routes(state: AppState) -> Router<AppState> {
    // Users
    let users = Router::new()
        .route("/me", get(handlers::users::get_me))
        .route("/me", patch(handlers::users::update_me))
        .route("/me/avatar", post(handlers::uploads::upload_avatar))
        .route("/me/avatar", delete(handlers::uploads::delete_avatar))
        .route("/me/banner", post(handlers::uploads::upload_banner))
        .route("/me/banner", delete(handlers::uploads::delete_banner))
        .route(
            "/me/banner/crop",
            patch(handlers::uploads::update_my_banner_crop),
        )
        .route(
            "/me/member-list-banner",
            post(handlers::uploads::upload_member_list_banner),
        )
        .route(
            "/me/member-list-banner",
            delete(handlers::uploads::delete_member_list_banner),
        )
        .route(
            "/me/member-list-banner/crop",
            patch(handlers::uploads::update_my_member_list_banner_crop),
        )
        .route(
            "/me/server-order",
            patch(handlers::users::update_server_order),
        )
        .route(
            "/me/favorite-order",
            patch(handlers::users::update_favorite_order),
        )
        .route("/me/sessions", get(handlers::users::list_sessions))
        .route(
            "/me/sessions/{sessionId}",
            delete(handlers::users::revoke_session),
        )
        .route(
            "/me/sessions/revoke-all",
            post(handlers::users::revoke_all_sessions),
        )
        .route(
            "/me/notifications",
            get(handlers::notifications::list_notification_prefs),
        )
        .route(
            "/me/notifications",
            put(handlers::notifications::upsert_notification_pref),
        )
        .route("/me/delete", post(handlers::users::delete_account))
        .route("/me/change-email", post(handlers::users::change_email))
        .route(
            "/me/change-email/confirm",
            post(handlers::users::confirm_email_change),
        )
        .route(
            "/me/resend-verification",
            post(handlers::email_verify::resend_verification),
        )
        .route("/me/username", post(handlers::users::set_username))
        .route(
            "/me/subscription/ring-style",
            patch(handlers::users::set_ring_style),
        )
        .route(
            "/@me/subscription/ring-style",
            patch(handlers::users::set_ring_style),
        )
        .route(
            "/me/preferences",
            patch(handlers::users::update_preferences),
        )
        .route("/{userId}", get(handlers::users::get_user))
        .route("/{userId}/report", post(handlers::reports::report_user))
        .route(
            "/{userId}/mutual-servers",
            get(handlers::users::get_mutual_servers),
        );

    // Users (emoji shortcut)
    let user_emojis = Router::new().route("/@me/emojis", get(handlers::emojis::list_user_emojis));

    // Servers
    let servers = Router::new()
        .route("/", post(handlers::servers::create_server))
        .route("/", get(handlers::servers::list_servers))
        .route("/{serverId}", get(handlers::servers::get_server))
        .route("/{serverId}", patch(handlers::servers::update_server))
        .route("/{serverId}", delete(handlers::servers::delete_server))
        .route(
            "/{serverId}/workspace",
            get(handlers::server_workspace::get_server_workspace),
        )
        .route(
            "/{serverId}/restore",
            post(handlers::servers::restore_server),
        )
        .route("/{serverId}/members", get(handlers::servers::list_members))
        .route("/{serverId}/leave", delete(handlers::servers::leave_server))
        // Server icon
        .route(
            "/{serverId}/icon",
            post(handlers::uploads::upload_server_icon),
        )
        .route(
            "/{serverId}/icon",
            delete(handlers::uploads::delete_server_icon),
        )
        // Server banner
        .route(
            "/{serverId}/banner",
            post(handlers::uploads::upload_server_banner),
        )
        .route(
            "/{serverId}/banner",
            delete(handlers::uploads::delete_server_banner),
        )
        .route(
            "/{serverId}/banner/crop",
            patch(handlers::servers::update_server_banner_crop),
        )
        // Categories
        .route(
            "/{serverId}/categories",
            post(handlers::categories::create_category),
        )
        .route(
            "/{serverId}/categories",
            get(handlers::categories::list_categories),
        )
        .route(
            "/{serverId}/categories/{categoryId}",
            patch(handlers::categories::update_category),
        )
        .route(
            "/{serverId}/categories/{categoryId}",
            delete(handlers::categories::delete_category),
        )
        // Channels (under server)
        .route(
            "/{serverId}/channels",
            post(handlers::channels::create_channel),
        )
        .route(
            "/{serverId}/channels",
            get(handlers::channels::list_channels),
        )
        // Layout
        .route("/{serverId}/layout", get(handlers::categories::get_layout))
        // Roles
        .route("/{serverId}/roles", post(handlers::roles::create_role))
        .route("/{serverId}/roles", get(handlers::roles::list_roles))
        .route(
            "/{serverId}/roles/reorder",
            patch(handlers::roles::reorder_roles),
        )
        .route(
            "/{serverId}/roles/{roleId}",
            patch(handlers::roles::update_role),
        )
        .route(
            "/{serverId}/roles/{roleId}",
            delete(handlers::roles::delete_role),
        )
        .route(
            "/{serverId}/members/@me/name-color",
            patch(handlers::roles::set_own_name_color),
        )
        .route(
            "/{serverId}/members/{userId}/roles/{roleId}",
            put(handlers::roles::assign_role),
        )
        .route(
            "/{serverId}/members/{userId}/roles/{roleId}",
            delete(handlers::roles::remove_role),
        )
        // Invites (server-scoped)
        .route(
            "/{serverId}/invites",
            post(handlers::invites::create_invite),
        )
        .route("/{serverId}/invites", get(handlers::invites::list_invites))
        .route(
            "/{serverId}/invites/{code}",
            delete(handlers::invites::revoke_invite),
        )
        // Emojis
        .route(
            "/{serverId}/custom-expressions/import",
            post(handlers::uploads::import_custom_expression),
        )
        .route("/{serverId}/emojis", post(handlers::uploads::upload_emoji))
        .route(
            "/{serverId}/emojis",
            get(handlers::emojis::list_server_emojis),
        )
        .route(
            "/{serverId}/emojis/{emojiId}",
            patch(handlers::emojis::rename_emoji),
        )
        .route(
            "/{serverId}/emojis/{emojiId}",
            delete(handlers::emojis::delete_emoji),
        )
        // Stickers
        .route(
            "/{serverId}/stickers",
            post(handlers::uploads::upload_sticker),
        )
        .route(
            "/{serverId}/stickers",
            get(handlers::stickers::list_server_stickers),
        )
        .route(
            "/{serverId}/stickers/{stickerId}",
            patch(handlers::stickers::rename_sticker),
        )
        .route(
            "/{serverId}/stickers/{stickerId}",
            delete(handlers::stickers::delete_sticker),
        )
        // Moderation
        .route(
            "/{serverId}/members/{userId}/kick",
            post(handlers::moderation::kick_member),
        )
        .route(
            "/{serverId}/bans/{userId}",
            post(handlers::moderation::ban_member),
        )
        .route(
            "/{serverId}/bans/{userId}",
            delete(handlers::moderation::unban_member),
        )
        .route("/{serverId}/bans", get(handlers::moderation::list_bans))
        // Audit log
        .route("/{serverId}/audit-log", get(handlers::audit::get_audit_log))
        // Reorder
        .route("/{serverId}/reorder", put(handlers::reorder::reorder))
        // Welcome dismissal
        .route(
            "/{serverId}/members/@me/welcome",
            patch(handlers::servers::dismiss_welcome),
        )
        // Bots
        .route("/{serverId}/bots", post(handlers::bots::create_bot))
        .route("/{serverId}/bots", get(handlers::bots::list_bots))
        .route(
            "/{serverId}/bots/{botId}",
            delete(handlers::bots::delete_bot),
        )
        .route(
            "/{serverId}/bots/{botId}",
            patch(handlers::bots::update_bot),
        )
        .route(
            "/{serverId}/bots/{botId}/avatar",
            post(handlers::uploads::upload_bot_avatar),
        )
        .route(
            "/{serverId}/bots/{botId}/avatar",
            delete(handlers::uploads::delete_bot_avatar),
        )
        .route(
            "/{serverId}/bots/{botId}/banner",
            post(handlers::uploads::upload_bot_banner),
        )
        .route(
            "/{serverId}/bots/{botId}/banner",
            delete(handlers::uploads::delete_bot_banner),
        )
        .route(
            "/{serverId}/bots/{botId}/banner/crop",
            patch(handlers::bots::update_bot_banner_crop),
        )
        .route(
            "/{serverId}/bots/{botId}/roles/{roleId}",
            put(handlers::bots::assign_bot_role),
        )
        .route(
            "/{serverId}/bots/{botId}/roles/{roleId}",
            delete(handlers::bots::remove_bot_role),
        )
        .route(
            "/{serverId}/bots/{botId}/tokens",
            post(handlers::bots::generate_token),
        )
        .route(
            "/{serverId}/bots/{botId}/tokens/{tokenId}",
            delete(handlers::bots::revoke_token),
        )
        // Announcement Feeds
        .route("/{serverId}/feeds", post(handlers::feeds::create_feed))
        .route("/{serverId}/feeds", get(handlers::feeds::list_feeds))
        .route(
            "/{serverId}/feeds/{feedId}",
            patch(handlers::feeds::update_feed),
        )
        .route(
            "/{serverId}/feeds/{feedId}",
            delete(handlers::feeds::delete_feed),
        );

    // Channels (by channelId)
    let channels = Router::new()
        .route("/{channelId}", patch(handlers::channels::update_channel))
        .route("/{channelId}", delete(handlers::channels::delete_channel))
        .route("/{channelId}/ack", post(handlers::channels::ack_channel))
        // Messages
        .route(
            "/{channelId}/messages",
            get(handlers::messages::get_messages),
        )
        .route(
            "/{channelId}/messages",
            post(handlers::messages::create_message),
        )
        .route(
            "/{channelId}/announcements",
            post(handlers::messages::create_announcement),
        )
        .route(
            "/{channelId}/messages/search",
            get(handlers::messages::search_messages),
        )
        .route(
            "/{channelId}/activity",
            get(handlers::messages::get_channel_activity),
        )
        .route(
            "/{channelId}/messages/{messageId}",
            patch(handlers::messages::update_message),
        )
        .route(
            "/{channelId}/messages/{messageId}",
            delete(handlers::messages::delete_message),
        )
        // Attachments
        .route(
            "/{channelId}/attachments",
            post(handlers::uploads::upload_attachment),
        )
        // Reactions
        .route(
            "/{channelId}/messages/{messageId}/reactions/{emoji}",
            put(handlers::reactions::add_reaction),
        )
        .route(
            "/{channelId}/messages/{messageId}/reactions/{emoji}",
            delete(handlers::reactions::remove_reaction),
        )
        // Reports
        .route(
            "/{channelId}/messages/{messageId}/report",
            post(handlers::reports::report_message),
        )
        // Pins
        .route("/{channelId}/pins", get(handlers::pins::list_pins))
        .route(
            "/{channelId}/pins/{messageId}",
            put(handlers::pins::pin_message),
        )
        .route(
            "/{channelId}/pins/{messageId}",
            delete(handlers::pins::unpin_message),
        )
        // Channel permission overrides
        .route(
            "/{channelId}/overrides",
            get(handlers::channel_overrides::list_overrides),
        )
        .route(
            "/{channelId}/overrides/{roleId}",
            put(handlers::channel_overrides::upsert_override),
        )
        .route(
            "/{channelId}/overrides/{roleId}",
            delete(handlers::channel_overrides::delete_override),
        )
        // Voice
        .route("/{channelId}/voice/join", post(handlers::voice::voice_join))
        .route(
            "/{channelId}/voice/leave",
            delete(handlers::voice::voice_leave),
        )
        .route(
            "/{channelId}/voice/mute/{targetUserId}",
            post(handlers::voice::voice_mute),
        )
        .route(
            "/{channelId}/voice/deafen/{targetUserId}",
            post(handlers::voice::voice_deafen),
        )
        .route(
            "/{channelId}/voice/participants",
            get(handlers::voice::voice_participants),
        );

    // Invites (top-level)
    let invites = Router::new()
        .route("/{code}", get(handlers::invites::preview_invite))
        .route("/{code}/accept", post(handlers::invites::accept_invite));

    // DMs
    let dms = Router::new()
        .route("/", post(handlers::dms::create_dm))
        .route("/", get(handlers::dms::list_dms))
        .route(
            "/{channelId}/name-color",
            put(handlers::dms::update_name_color),
        );

    // Relationships
    let relationships = Router::new()
        .route("/", get(handlers::relationships::list_relationships))
        .route("/", post(handlers::relationships::send_friend_request))
        .route(
            "/{userId}",
            patch(handlers::relationships::accept_friend_request),
        )
        .route(
            "/{userId}",
            delete(handlers::relationships::delete_relationship),
        )
        .route("/{userId}/block", put(handlers::relationships::block_user))
        .route(
            "/{userId}/metadata",
            put(handlers::relationships::update_metadata),
        );

    // 2FA
    let twofa = Router::new()
        .route("/status", get(handlers::twofa::twofa_status))
        .route("/setup", post(handlers::twofa::twofa_setup))
        .route("/verify-setup", post(handlers::twofa::twofa_verify_setup))
        .route("/disable", post(handlers::twofa::twofa_disable))
        .route(
            "/backup-codes/regenerate",
            post(handlers::twofa::twofa_regenerate_backup_codes),
        );

    // Invite codes (user-generated registration keys)
    let invite_codes = Router::new()
        .route("/", post(handlers::invite_codes::create_invite_code))
        .route("/", get(handlers::invite_codes::list_invite_codes))
        .route("/{key}", delete(handlers::invite_codes::delete_invite_code));

    // Voice (standalone)
    let voice = Router::new().route("/state", patch(handlers::voice::voice_state));

    // Bug reports
    let bug_reports = Router::new()
        .route("/", post(handlers::bug_reports::create_bug_report))
        .route("/me", get(handlers::bug_reports::list_my_bug_reports));

    // Account linking (identity metadata only; no cross-instance authority)
    let account_links = Router::new()
        .route("/", get(handlers::account_links::list_account_links))
        .route(
            "/issued",
            get(handlers::account_links::list_issued_account_link_grants),
        )
        .route(
            "/intents",
            post(handlers::account_links::create_account_link_intent),
        )
        .route(
            "/proofs",
            post(handlers::account_links::issue_account_link_proof),
        )
        .route(
            "/complete",
            post(handlers::account_links::complete_account_link),
        )
        .route(
            "/sync-revocations",
            post(handlers::account_links::sync_account_link_revocations),
        )
        .route(
            "/issued/{grantId}",
            delete(handlers::account_links::revoke_issued_account_link_grant),
        )
        .route(
            "/{linkId}",
            delete(handlers::account_links::revoke_account_link),
        );

    // Media (Klipy proxy — GIFs, Stickers, Clips, Memes)
    let gifs = Router::new()
        .route("/trending", get(handlers::media::gifs_trending))
        .route("/search", get(handlers::media::gifs_search))
        .route("/categories", get(handlers::media::gifs_categories))
        .route("/recent/{customer_id}", get(handlers::media::gifs_recent));

    let stickers = Router::new()
        .route("/trending", get(handlers::media::stickers_trending))
        .route("/search", get(handlers::media::stickers_search))
        .route("/categories", get(handlers::media::stickers_categories))
        .route(
            "/recent/{customer_id}",
            get(handlers::media::stickers_recent),
        );

    let clips = Router::new()
        .route("/trending", get(handlers::media::clips_trending))
        .route("/search", get(handlers::media::clips_search))
        .route("/categories", get(handlers::media::clips_categories))
        .route("/recent/{customer_id}", get(handlers::media::clips_recent));

    let memes = Router::new()
        .route("/trending", get(handlers::media::memes_trending))
        .route("/search", get(handlers::media::memes_search))
        .route("/categories", get(handlers::media::memes_categories))
        .route("/recent/{customer_id}", get(handlers::media::memes_recent));

    // Announcements (under /api/feeds — standalone, not nested under servers)
    let announcement_feeds = Router::new()
        .route(
            "/{feedId}/announcements",
            post(handlers::announcements::create_announcement),
        )
        .route(
            "/{feedId}/announcements",
            get(handlers::announcements::list_announcements),
        )
        .route(
            "/{feedId}/announcements/{announcementId}",
            patch(handlers::announcements::update_announcement),
        )
        .route(
            "/{feedId}/announcements/{announcementId}",
            delete(handlers::announcements::delete_announcement),
        );

    let bot_api = Router::new()
        .route("/me", get(handlers::bots::bot_me))
        .route("/uploads/images", post(handlers::uploads::upload_bot_image))
        .route(
            "/feeds/{feedId}/announcements",
            post(handlers::announcements::create_bot_announcement),
        )
        .route(
            "/channels/{channelId}/cards",
            post(handlers::messages::create_bot_card),
        );

    let protected_media = Router::new().route(
        "/attachments/{attachmentId}",
        get(handlers::uploads::get_attachment_media),
    );

    let link_previews = Router::new()
        .route("/", post(handlers::link_previews::create_link_preview))
        .route(
            "/image",
            get(handlers::link_previews::get_link_preview_image),
        );
    let sync = Router::new().route("/summary", get(handlers::sync::summary));
    let federation_invites = Router::new().route(
        "/invites/join",
        post(handlers::invites::join_federated_invite),
    );
    let federation_memberships = handlers::federation_memberships::routes();

    let mut routes = Router::new()
        .nest("/api/users", users.merge(user_emojis))
        .nest("/api/servers", servers)
        .nest("/api/channels", channels)
        .nest("/api/sync", sync)
        .nest("/api/media", protected_media)
        .nest("/api/link-previews", link_previews)
        .nest("/api/invites", invites)
        .nest("/api/dms", dms)
        .nest("/api/feeds", announcement_feeds)
        .nest("/api/bot", bot_api)
        .nest("/api/users/me/relationships", relationships)
        .nest("/api/2fa", twofa)
        .nest("/api/invite-codes", invite_codes)
        .nest("/api/voice", voice)
        .nest("/api/bug-reports", bug_reports)
        .nest("/api/account-links", account_links)
        .nest("/api/federation", federation_invites)
        .nest("/api/federation/memberships", federation_memberships)
        .nest("/api/gifs", gifs)
        .nest("/api/stickers", stickers)
        .nest("/api/clips", clips)
        .nest("/api/memes", memes);

    if config::billing_routes_enabled(state.config.instance_mode, state.config.billing_mode) {
        let billing = Router::new()
            .route(
                "/checkout",
                post(handlers::billing::create_checkout_session),
            )
            .route("/portal", post(handlers::billing::create_portal_session));
        routes = routes.nest("/api/billing", billing);
    }

    routes.route_layer(axum::middleware::from_fn_with_state(
        state,
        middleware::auth::auth_middleware,
    ))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env().add_directive("verdant_server=info".parse().unwrap()),
        )
        .init();

    tracing::info!("Starting Verdant server (Rust)");

    // Load .env from project root (one level up from server-rs/)
    dotenvy::from_filename("../.env").ok();
    dotenvy::dotenv().ok();
    let config = config::Config::from_env();
    let port = config.port;

    let origins: Vec<_> = config
        .cors_origins
        .iter()
        .map(|o| o.parse().expect("invalid CORS origin"))
        .collect();

    let cors = CorsLayer::new()
        .allow_origin(origins)
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::PATCH,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers([
            axum::http::header::CONTENT_TYPE,
            axum::http::header::AUTHORIZATION,
            axum::http::HeaderName::from_static("x-client-version"),
            axum::http::HeaderName::from_static("idempotency-key"),
        ])
        // Expose the region stamp so the Tauri client (or any
        // cross-origin debugger) can actually read it — without
        // this it's invisible to JS even though the server sends it.
        .expose_headers([axum::http::HeaderName::from_static("x-verdant-region")])
        .allow_credentials(true);

    // Initialize CDN URL resolver (must be before AppState so responses can resolve URLs)
    services::cdn::init(config.cdn_base_url.clone());
    if services::cdn::enabled() {
        // Log the resolved base URL (after scheme auto-fix) — not the raw env var
        let sample = services::cdn::resolve(Some("_test")).unwrap_or_default();
        let base = sample.trim_end_matches("/_test");
        tracing::info!("CDN enabled: {base}");
    }

    let log_latency = config.log_latency;
    let state = AppState::new(config).await;

    // Apply pending migrations against the live PG pool. Idempotent —
    // sqlx tracks applied versions in `_sqlx_migrations`. We do this
    // once at boot rather than via the orchestrator so a fresh PG
    // droplet self-bootstraps on the first server-rs start. Panics on
    // failure: a server without its schema applied is worse than no
    // server at all.
    let exe_migrations_dir = std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|parent| parent.join("migrations")));
    let manifest_migrations_dir =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("migrations");
    let migrations_dir = exe_migrations_dir
        .filter(|p| p.is_dir())
        .unwrap_or(manifest_migrations_dir);
    let migrator = sqlx::migrate::Migrator::new(migrations_dir)
        .await
        .expect("sqlx migrations failed to load");
    if let Some(migration_database_url) = state.config.migration_database_url.as_deref() {
        tracing::info!("Applying Postgres migrations via MIGRATION_DATABASE_URL");
        let migration_connect_opts: sqlx::postgres::PgConnectOptions = migration_database_url
            .parse()
            .expect("invalid MIGRATION_DATABASE_URL");
        let migration_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_secs(30))
            .connect_with(migration_connect_opts)
            .await
            .expect("MIGRATION_DATABASE_URL connection failed");
        migrator
            .run(&migration_pool)
            .await
            .expect("sqlx migrations failed to apply");
        migration_pool.close().await;
    } else {
        tracing::warn!(
            "MIGRATION_DATABASE_URL is not set; applying migrations through DATABASE_URL. \
             Do not use a PgBouncer/managed pooler URL for DATABASE_URL in this mode."
        );
        migrator
            .run(&state.pg)
            .await
            .expect("sqlx migrations failed to apply");
    }
    tracing::info!("Postgres migrations applied");
    services::field_encryption_backfill::spawn_field_encryption_backfill_task(state.clone());
    verdant_server::federation::outbox::spawn_outbox_dispatch_task(state.clone());
    verdant_server::federation::maintenance::spawn_replay_nonce_cleanup_task(state.clone());

    // Public routes (no auth)
    let password_reset = Router::new()
        .route(
            "/request",
            post(handlers::password_reset::request_password_reset),
        )
        .route(
            "/confirm",
            post(handlers::password_reset::confirm_password_reset),
        );

    let updates = Router::new()
        .route("/latest", get(handlers::updates::get_latest_update))
        .route("/download", get(handlers::updates::download_update));

    let mut admin = Router::new().route("/notify-update", post(handlers::admin::notify_update));
    if state.config.federation_registry_admin_enabled
        && state.config.instance_mode == config::InstanceMode::Official
    {
        let federation_admin = Router::new()
            .route(
                "/instances",
                post(handlers::federation::admin_create_instance),
            )
            .route(
                "/instances/{instanceId}",
                patch(handlers::federation::admin_update_instance),
            );
        admin = admin.nest("/federation", federation_admin);
    } else {
        tracing::info!("federation registry admin routes disabled");
    }
    if state.config.loadtest_secret.is_some() {
        admin = admin
            .route("/loadtest/setup", post(handlers::admin_loadtest::setup))
            .route(
                "/loadtest/teardown",
                post(handlers::admin_loadtest::teardown),
            )
            .route(
                "/broadcast-stats",
                get(handlers::admin_loadtest::broadcast_stats),
            );
    } else {
        tracing::info!("loadtest admin routes disabled");
    }

    // Start Redis pub/sub bridge for cross-instance WS delivery
    ws::topics::start_redis_subscriber(state.clone()).await;
    ws::topics::start_node_heartbeat(state.clone()).await;

    // Preload Klipy categories so the first media picker open is instant
    handlers::media::spawn_categories_preload(state.clone());

    // Start background purge task (soft-deleted servers & accounts, every 24h)
    services::purge::spawn_purge_task(state.clone());
    services::bot_events::spawn_cleanup_task(state.clone());

    // Start content scan retry task (pending attachments, every 5 min)
    if state.config.content_scan_enabled() {
        services::content_scan_task::spawn_scan_retry_task(state.clone());
        tracing::info!("Content scan retry task started");
    } else if !services::cdn::enabled() {
        tracing::warn!(
            "No content scanning configured (CONTENT_SCAN_PROVIDER=none, no CDN). Uploaded images will NOT be scanned for prohibited content."
        );
    }

    let mut app = Router::new()
        .route("/", get(landing_page))
        .route("/invite/{code}", get(invite_page))
        .route("/status", get(status_page))
        .route("/tos", get(tos_page))
        .route("/privacy", get(privacy_page))
        .route("/docs/bots", get(bot_docs_page))
        .route("/assets/site.css", get(site_css))
        .route("/assets/neon-tree-small.svg", get(tree_icon_svg))
        .route("/assets/verdant-icon.svg", get(downloadable_tree_icon_svg))
        .nest_service("/_next", ServeDir::new(web_dist_file("_next")))
        .route("/robots.txt", get(robots_txt))
        .route("/sitemap.xml", get(sitemap_xml))
        .route("/health", get(health))
        .route("/api/instance", get(handlers::instance::get_instance))
        .route(
            "/api/federation/manifest",
            get(handlers::federation::manifest),
        )
        .route(
            "/api/federation/discovery",
            get(handlers::federation::discovery),
        )
        .route(
            "/api/federation/invites/{code}/preview",
            get(handlers::invites::preview_federated_invite),
        )
        .route(
            "/api/federation/invites/capability",
            post(handlers::invites::issue_federated_invite_capability),
        )
        .route(
            "/api/federation/v1/events",
            post(handlers::federation::receive_event),
        )
        .route(
            "/api/federation/v1/media/custom-expressions/{kind}/{expressionId}",
            get(handlers::uploads::get_federation_custom_expression_media),
        )
        .route(
            "/api/account-link-revocations/status",
            post(handlers::account_links::account_link_revocation_status),
        )
        .route(
            "/verify-email",
            get(handlers::email_verify::verify_email_page),
        )
        .route("/ws", get(ws::upgrade_handler))
        .route("/bot-gateway", get(ws::bot_gateway::upgrade_handler))
        .nest("/api/auth", auth_routes())
        .nest("/api/password-reset", password_reset)
        .nest("/api/updates", updates)
        .nest("/api/admin", admin)
        // Voice webhook disabled until LiveKit HMAC verification is implemented
        // .route("/api/voice/webhook", post(handlers::voice::voice_webhook))
        .merge(protected_routes(state.clone()));

    if config::billing_routes_enabled(state.config.instance_mode, state.config.billing_mode) {
        app = app.route(
            "/api/stripe/webhook",
            post(handlers::stripe_webhook::stripe_webhook),
        );
    }

    // Web SPA disabled; Verdant is Tauri-only.
    // To re-enable: set WEB_DIST_DIR env var to the built SPA directory.
    // if let Some(ref dist_dir) = state.config.web_dist_dir {
    //     ... SPA serving code removed ...
    // }

    // Tag every response with the region that served it. Set at
    // startup from VERDANT_REGION (injected via Doppler per region,
    // e.g. "nyc1" / "ams3"); falls back to "unknown" when absent so
    // misconfiguration is visible in the header instead of crashing.
    // Clients use this to spot-check that geo-routing (DO GLB) sends
    // their traffic to the nearest region.
    let region_label = std::env::var("VERDANT_REGION").unwrap_or_else(|_| "unknown".to_string());
    let region_header_value = axum::http::HeaderValue::from_str(&region_label)
        .unwrap_or_else(|_| axum::http::HeaderValue::from_static("unknown"));
    tracing::info!("VERDANT_REGION={region_label} (stamped on X-Verdant-Region response header)");
    let global_body_limit = global_body_limit_bytes(&state.config.local_capabilities);

    let mut app = app
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::rate_limit_layer::rate_limit_headers,
        ))
        .layer(axum::middleware::from_fn(middleware::csrf::csrf_protection))
        .layer(cors)
        .layer(DefaultBodyLimit::max(global_body_limit))
        .layer(axum::middleware::from_fn(
            middleware::security_headers::security_headers,
        ))
        .layer(SetResponseHeaderLayer::overriding(
            axum::http::HeaderName::from_static("x-verdant-region"),
            region_header_value,
        ));

    // Only expose server-timing header when LOG_LATENCY is enabled (dev/debug)
    if log_latency {
        app = app.layer(axum::middleware::from_fn(middleware::timing::server_timing));
    }

    // Clone state before `.with_state()` consumes it — we need it in
    // the shutdown handler to broadcast close frames and tear down Redis.
    let shutdown_state = state.clone();

    let app = app
        .layer(axum::middleware::from_fn(
            middleware::response_sanitizer::response_sanitizer,
        ))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    tracing::info!("Listening on {addr}");

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(graceful_shutdown(shutdown_state))
    .await
    .unwrap();

    tracing::info!("Graceful shutdown complete");
}

/// Wait for SIGTERM or Ctrl+C, then gracefully tear down WS connections
/// and Redis pub/sub before letting axum finish its shutdown.
async fn graceful_shutdown(state: AppState) {
    // ── 1. Wait for the OS signal ────────────────────────────────────
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("Received Ctrl+C, shutting down..."),
        _ = terminate => tracing::info!("Received SIGTERM, shutting down..."),
    }

    // ── 2. Stop receiving Redis pub/sub before tearing down WS ───────
    // Prevents the race where Redis delivers a message to the dying
    // subscriber but the write loop is already dead.
    {
        use fred::interfaces::ClientLike;
        let _ = state.redis_sub.quit().await;
        tracing::info!("Redis subscriber shut down");
    }

    // ── 3. Set shutting_down flag ─────────────────────────────────────
    // Disconnect handlers check this to skip presence broadcasts during
    // controlled drains.
    state
        .shutting_down
        .store(true, std::sync::atomic::Ordering::Relaxed);
    state
        .draining
        .store(true, std::sync::atomic::Ordering::Relaxed);

    // ── 4. Preserve Redis presence for connected users ────────────────
    // During ZDT/drain the clients reconnect to a replacement app server.
    // Deleting presence here makes everyone briefly appear offline even
    // though no user chose to disconnect. Keep the TTL-backed presence keys
    // alive; the replacement socket refreshes them after IDENTIFY, and truly
    // abandoned sessions naturally expire.
    let connected_users = state.ws.connected_user_ids();
    let user_count = connected_users.len();
    tracing::info!(
        users = user_count,
        "Shutdown: preserving Redis presence for reconnect grace"
    );

    // ── 5. Broadcast close frames to all WS clients ─────────────────
    // Clients that receive a 1001 close frame reconnect immediately
    // instead of waiting for the heartbeat timeout to fire.
    let conn_ids = state.ws.all_conn_ids();
    let n = conn_ids.len();
    for conn_id in conn_ids {
        state.ws.send_to(
            conn_id,
            ws::connection::OutboundMsg::Close(1001, "Server restarting".to_string()),
        );
    }
    tracing::info!(connections = n, "Sent close frames to all WS clients");

    // Returning from this future tells axum to stop accepting new
    // connections and drain in-flight requests.
}
