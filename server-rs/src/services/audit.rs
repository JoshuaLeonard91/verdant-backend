use fred::clients::Client;
use fred::interfaces::StreamsInterface;
use serde_json::Value;
use sqlx::PgPool;

use crate::services::pg::audit as pg_audit;

/// Audit log actions — centralised so grepping for coverage is easy.
#[derive(Debug, Clone, Copy)]
pub enum AuditAction {
    // Moderation
    KickMember,
    BanMember,
    UnbanMember,
    // Roles
    CreateRole,
    UpdateRole,
    DeleteRole,
    AssignRole,
    RemoveRole,
    SetNameColor,
    // Server
    DeleteServer,
    // Account security
    TotpEnable,
    TotpDisable,
    TotpRegenerateBackup,
    PasswordChange,
    EmailChange,
    PasswordReset,
    // Sessions
    SessionRevoke,
    SessionRevokeAll,
    // Account lifecycle
    DeleteAccount,
    // Account linking
    AccountLinkIntent,
    AccountLinkProofIssue,
    AccountLinkComplete,
    AccountLinkRevoke,
    // Content scanning
    ContentFlagged,
    ContentReported,
    ContentDismissed,
}

impl AuditAction {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::KickMember => "KICK_MEMBER",
            Self::BanMember => "BAN_MEMBER",
            Self::UnbanMember => "UNBAN_MEMBER",
            Self::CreateRole => "CREATE_ROLE",
            Self::UpdateRole => "UPDATE_ROLE",
            Self::DeleteRole => "DELETE_ROLE",
            Self::AssignRole => "ASSIGN_ROLE",
            Self::RemoveRole => "REMOVE_ROLE",
            Self::SetNameColor => "SET_NAME_COLOR",
            Self::DeleteServer => "DELETE_SERVER",
            Self::TotpEnable => "TOTP_ENABLE",
            Self::TotpDisable => "TOTP_DISABLE",
            Self::TotpRegenerateBackup => "TOTP_REGENERATE_BACKUP",
            Self::PasswordChange => "PASSWORD_CHANGE",
            Self::EmailChange => "EMAIL_CHANGE",
            Self::PasswordReset => "PASSWORD_RESET",
            Self::SessionRevoke => "SESSION_REVOKE",
            Self::SessionRevokeAll => "SESSION_REVOKE_ALL",
            Self::DeleteAccount => "DELETE_ACCOUNT",
            Self::AccountLinkIntent => "ACCOUNT_LINK_INTENT",
            Self::AccountLinkProofIssue => "ACCOUNT_LINK_PROOF_ISSUE",
            Self::AccountLinkComplete => "ACCOUNT_LINK_COMPLETE",
            Self::AccountLinkRevoke => "ACCOUNT_LINK_REVOKE",
            Self::ContentFlagged => "CONTENT_FLAGGED",
            Self::ContentReported => "CONTENT_REPORTED",
            Self::ContentDismissed => "CONTENT_DISMISSED",
        }
    }
}

pub struct AuditEntry {
    pub id: i64,
    pub actor_id: i64,
    pub action: AuditAction,
    pub target_type: &'static str,
    pub target_id: i64,
    pub server_id: Option<i64>,
    pub metadata: Option<Value>,
    pub ip: Option<String>,
}

/// Stream key for audit log. A per-server index stream
/// `audit-log:{server_id}` is also populated so get_audit_log can
/// scope the listing to one server without full-stream XRANGE.
const AUDIT_LOG_STREAM: &str = "audit-log";

/// Fire-and-forget audit log insert. Redis stream is the live tail
/// (admin UI tails it for real-time display); PG is the durability
/// archive. Both writes happen here; errors log but never propagate.
pub async fn log(redis: &Client, entry: AuditEntry, pg: PgPool) {
    let meta_value = entry
        .metadata
        .clone()
        .unwrap_or_else(|| Value::Object(Default::default()));
    let meta_str = meta_value.to_string();
    let action = entry.action.as_str().to_string();
    let ip_str = entry.ip.as_deref().unwrap_or_default().to_string();
    let now_ms = chrono::Utc::now().timestamp_millis();
    let fields: Vec<(&str, String)> = vec![
        ("id", entry.id.to_string()),
        ("actor_id", entry.actor_id.to_string()),
        ("action", action.clone()),
        ("target_type", entry.target_type.to_string()),
        ("target_id", entry.target_id.to_string()),
        ("metadata", meta_str.clone()),
        ("ip", ip_str.clone()),
        (
            "server_id",
            entry.server_id.map(|v| v.to_string()).unwrap_or_default(),
        ),
    ];

    let result: Result<String, _> = redis
        .xadd(AUDIT_LOG_STREAM, false, None, "*", fields.clone())
        .await;
    if let Err(e) = result {
        tracing::error!(error = %e, action = %action, "Failed to XADD audit_log entry");
    }

    // Per-server index so the admin UI can `audit-log:{server_id}`
    // without scanning the global stream.
    if let Some(sid) = entry.server_id {
        let server_stream = format!("{AUDIT_LOG_STREAM}:{sid}");
        let _: Result<String, _> = redis.xadd(&server_stream, false, None, "*", fields).await;
    }

    // PG durability tier — fire-and-forget. Errors don't propagate
    // because audit is async and the Redis stream is the live tail.
    let row = pg_audit::AuditRow {
        id: entry.id,
        actor_id: entry.actor_id,
        action,
        target_type: entry.target_type.to_string(),
        target_id: entry.target_id,
        server_id: entry.server_id,
        metadata: meta_value,
        ip: entry.ip.clone(),
        created_at_ms: now_ms,
    };
    tokio::spawn(async move {
        if let Err(e) = pg_audit::insert(&pg, &row).await {
            tracing::warn!(error = %e, "audit PG dual-write failed");
        }
        if let Some(server_id) = row.server_id {
            let payload = serde_json::json!({
                "id": row.id.to_string(),
                "actorId": row.actor_id.to_string(),
                "action": row.action,
                "targetType": row.target_type,
                "targetId": row.target_id.to_string(),
                "serverId": server_id.to_string(),
                "metadata": row.metadata,
                "createdAtMs": row.created_at_ms,
            });
            if let Err(e) = crate::services::pg::bot_outbox::insert(
                &pg,
                crate::services::pg::bot_outbox::NewBotOutboxEvent {
                    id: row.id,
                    event_type: crate::services::bot_events::EVENT_AUDIT_LOG_CREATE,
                    server_id: Some(server_id),
                    channel_id: None,
                    feed_id: None,
                    actor_user_id: Some(row.actor_id),
                    actor_bot_id: None,
                    payload: &payload,
                    created_at_ms: row.created_at_ms,
                },
            )
            .await
            {
                tracing::warn!(error = %e, "audit bot outbox insert failed");
            }
        }
    });
}

/// Convenience: spawn a fire-and-forget audit log on the tokio runtime.
pub fn log_async(redis: Client, entry: AuditEntry, pg: PgPool) {
    tokio::spawn(async move {
        log(&redis, entry, pg).await;
    });
}
