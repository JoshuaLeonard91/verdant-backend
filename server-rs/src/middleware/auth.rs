use axum::{
    body::Body,
    extract::{ConnectInfo, FromRequestParts, Request},
    http::{Method, StatusCode, request::Parts},
    middleware::Next,
    response::Response,
};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;

use crate::error::AppError;
use crate::services::banner_crop::BannerCrop;
use crate::services::crypto::{self, VerifiedToken, VerifiedTokenKind};
use crate::state::AppState;

fn unverified_access_allowed(method: &Method, path: &str) -> bool {
    (method == Method::GET && path == "/api/users/me")
        || (method == Method::POST && path == "/api/users/me/resend-verification")
        || (method == Method::POST && path == "/api/users/me/delete")
}

/// Extension type for the authenticated user's ID.
#[derive(Debug, Clone, Copy)]
pub struct UserId(pub i64);

/// Extension type for the session ID from the JWT `sid` claim (optional).
#[derive(Debug, Clone, Copy)]
pub struct SessionId(pub Option<i64>);

/// Identity for a short-lived federated client capability token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederatedClientIdentity {
    pub home_peer_id: String,
    pub remote_user_id: String,
    pub server_ids: Vec<i64>,
}

/// Identity for an authenticated bot.
#[derive(Debug, Clone)]
pub struct BotIdentity {
    pub bot_id: i64,
    pub token_id: i64,
    pub server_id: i64,
    pub name: String,
    pub description: Option<String>,
    pub avatar_url: Option<String>,
    pub banner_url: Option<String>,
    pub banner_crop: Option<BannerCrop>,
    pub avatar_preset: Option<String>,
    pub banner_preset: Option<String>,
    pub role_ids: Vec<i64>,
    pub scopes: Vec<String>,
    pub allowed_feed_ids: Vec<i64>,
    pub allowed_channel_ids: Vec<i64>,
}

/// Optional extractor yields `None` when the request is not bot-authenticated.
pub struct OptionalBot(pub Option<BotIdentity>);

/// Allow `UserId` to be extracted directly from request extensions.
/// The auth middleware must have run first to populate this.
impl<S: Send + Sync> FromRequestParts<S> for UserId {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<UserId>()
            .copied()
            .ok_or(AppError::TokenRequired)
    }
}

/// Allow `SessionId` to be extracted directly from request extensions.
impl<S: Send + Sync> FromRequestParts<S> for SessionId {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(parts
            .extensions
            .get::<SessionId>()
            .copied()
            .unwrap_or(SessionId(None)))
    }
}

/// Optional extractor yields `None` for normal local sessions.
pub struct OptionalFederatedClient(pub Option<FederatedClientIdentity>);

impl<S: Send + Sync> FromRequestParts<S> for OptionalFederatedClient {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(OptionalFederatedClient(
            parts.extensions.get::<FederatedClientIdentity>().cloned(),
        ))
    }
}

/// Allow `OptionalBot` to be extracted directly from request extensions.
impl<S: Send + Sync> FromRequestParts<S> for OptionalBot {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        Ok(OptionalBot(parts.extensions.get::<BotIdentity>().cloned()))
    }
}

pub async fn authenticate_bot_token(
    state: &AppState,
    raw_token: &str,
) -> Result<BotIdentity, AppError> {
    let hash = hex::encode(Sha256::digest(raw_token.as_bytes()));

    let token = crate::services::pg::bots::token_by_hash(&state.pg, &hash)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Bot token lookup failed");
            AppError::Internal
        })?;
    let token = match token {
        Some(t) if t.revoked_at_ms.is_none() => t,
        _ => return Err(AppError::TokenInvalid),
    };

    let bot = crate::services::pg::bots::by_id(&state.pg, token.bot_id)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Bot lookup failed");
            AppError::Internal
        })?;
    let bot = match bot {
        Some(b) => b,
        None => return Err(AppError::TokenInvalid),
    };
    let role_ids =
        match crate::services::pg::bots::list_role_ids(&state.pg, bot.id, bot.server_id).await {
            Ok(ids) => ids,
            Err(e) => {
                tracing::warn!(
                    bot_id = bot.id,
                    server_id = bot.server_id,
                    error = %e,
                    "Bot role lookup failed; continuing with no assigned bot roles"
                );
                Vec::new()
            }
        };

    let banner_crop = bot.banner_crop();
    let identity = BotIdentity {
        bot_id: bot.id,
        token_id: token.id,
        server_id: bot.server_id,
        name: bot.name,
        description: bot.description,
        avatar_url: bot.avatar_url,
        banner_url: bot.banner_url,
        banner_crop,
        avatar_preset: bot.avatar_preset,
        banner_preset: bot.banner_preset,
        role_ids,
        scopes: token.scopes,
        allowed_feed_ids: token.allowed_feed_ids,
        allowed_channel_ids: token.allowed_channel_ids,
    };

    let pg_task = state.pg.clone();
    let token_id = identity.token_id;
    let now_ms = chrono::Utc::now().timestamp_millis();
    tokio::spawn(async move {
        if let Err(e) =
            crate::services::pg::bots::token_touch_last_used(&pg_task, token_id, now_ms).await
        {
            tracing::warn!(error = %e, "Bot token last_used_at bump failed");
        }
    });

    Ok(identity)
}

pub async fn federated_client_identity_for_token(
    state: &AppState,
    verified: &VerifiedToken,
) -> Result<Option<FederatedClientIdentity>, AppError> {
    let VerifiedTokenKind::FederatedClient {
        home_peer_id,
        remote_user_id,
        server_ids,
    } = &verified.kind
    else {
        return Ok(None);
    };

    let local_user_id = crate::federation::storage::local_user_id_for_remote_principal(
        &state.pg,
        home_peer_id,
        remote_user_id,
    )
    .await
    .map_err(|error| {
        tracing::warn!(
            home_peer_id = %home_peer_id,
            remote_user_id = %remote_user_id,
            error = %error,
            "Federated client token projection lookup failed"
        );
        AppError::Internal
    })?;
    if local_user_id != Some(verified.user_id) {
        tracing::warn!(
            home_peer_id = %home_peer_id,
            remote_user_id = %remote_user_id,
            token_user_id = verified.user_id,
            projected_user_id = ?local_user_id,
            "Federated client token projection mismatch"
        );
        return Err(AppError::TokenInvalid);
    }

    Ok(Some(FederatedClientIdentity {
        home_peer_id: home_peer_id.clone(),
        remote_user_id: remote_user_id.clone(),
        server_ids: server_ids.clone(),
    }))
}

pub fn federated_client_allows_server_id(
    identity: Option<&FederatedClientIdentity>,
    server_id: i64,
) -> bool {
    identity
        .map(|identity| identity.server_ids.contains(&server_id))
        .unwrap_or(true)
}

pub fn require_federated_client_server_scope(
    identity: Option<&FederatedClientIdentity>,
    server_id: i64,
) -> Result<(), AppError> {
    if federated_client_allows_server_id(identity, server_id) {
        return Ok(());
    }

    if let Some(identity) = identity {
        tracing::warn!(
            home_peer_id = %identity.home_peer_id,
            remote_user_id = %identity.remote_user_id,
            server_id,
            allowed_server_ids = ?identity.server_ids,
            "Federated client token rejected outside claimed server scope"
        );
    }
    Err(AppError::NotFound("server"))
}

pub fn require_federated_client_channel_scope(
    identity: Option<&FederatedClientIdentity>,
    server_id: Option<i64>,
) -> Result<(), AppError> {
    let Some(identity) = identity else {
        return Ok(());
    };
    let Some(server_id) = server_id else {
        tracing::warn!(
            home_peer_id = %identity.home_peer_id,
            remote_user_id = %identity.remote_user_id,
            "Federated client token rejected for non-server channel scope"
        );
        return Err(AppError::NotFound("channel"));
    };

    require_federated_client_server_scope(Some(identity), server_id)
        .map_err(|_| AppError::NotFound("channel"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederatedClientRequestRoute {
    ServerList,
    Server { server_id: i64 },
    Channel { channel_id: i64 },
    CurrentUser,
    Deny,
}

fn parse_positive_i64(value: &str) -> Option<i64> {
    let parsed = value.parse::<i64>().ok()?;
    (parsed > 0).then_some(parsed)
}

pub fn classify_federated_client_request_route(
    method: &Method,
    path: &str,
) -> FederatedClientRequestRoute {
    let mut segments = path.trim_matches('/').split('/');
    match (segments.next(), segments.next(), segments.next()) {
        (Some("api"), Some("servers"), None) if method == Method::GET => {
            FederatedClientRequestRoute::ServerList
        }
        (Some("api"), Some("servers"), Some(server_id)) => parse_positive_i64(server_id)
            .map(|server_id| FederatedClientRequestRoute::Server { server_id })
            .unwrap_or(FederatedClientRequestRoute::Deny),
        (Some("api"), Some("channels"), Some(channel_id)) => parse_positive_i64(channel_id)
            .map(|channel_id| FederatedClientRequestRoute::Channel { channel_id })
            .unwrap_or(FederatedClientRequestRoute::Deny),
        (Some("api"), Some("users"), Some("me"))
            if method == Method::GET && segments.next().is_none() =>
        {
            FederatedClientRequestRoute::CurrentUser
        }
        _ => FederatedClientRequestRoute::Deny,
    }
}

pub async fn require_federated_client_request_scope(
    state: &AppState,
    identity: &FederatedClientIdentity,
    method: &Method,
    path: &str,
) -> Result<(), AppError> {
    match classify_federated_client_request_route(method, path) {
        FederatedClientRequestRoute::ServerList | FederatedClientRequestRoute::CurrentUser => {
            Ok(())
        }
        FederatedClientRequestRoute::Server { server_id } => {
            require_federated_client_server_scope(Some(identity), server_id)
        }
        FederatedClientRequestRoute::Channel { channel_id } => {
            let channel = crate::services::pg::channels::by_id(&state.pg, channel_id)
                .await
                .map_err(|error| {
                    tracing::warn!(
                        channel_id,
                        error = %error,
                        "Federated client token channel scope lookup failed"
                    );
                    AppError::Internal
                })?;
            let server_id = channel.and_then(|channel| channel.server_id);
            require_federated_client_channel_scope(Some(identity), server_id)
        }
        FederatedClientRequestRoute::Deny => {
            tracing::warn!(
                home_peer_id = %identity.home_peer_id,
                remote_user_id = %identity.remote_user_id,
                method = %method,
                path,
                "Federated client token rejected for unsupported REST path"
            );
            Err(AppError::Forbidden)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        FederatedClientIdentity, FederatedClientRequestRoute,
        classify_federated_client_request_route, federated_client_allows_server_id,
        require_federated_client_channel_scope, require_federated_client_server_scope,
    };
    use axum::http::Method;

    fn federated_identity(server_ids: Vec<i64>) -> FederatedClientIdentity {
        FederatedClientIdentity {
            home_peer_id: "host:home.example.com".to_string(),
            remote_user_id: "remote-user-1".to_string(),
            server_ids,
        }
    }

    #[test]
    fn federated_client_scope_allows_only_claimed_server_ids() {
        let identity = federated_identity(vec![10, 20]);

        assert!(federated_client_allows_server_id(Some(&identity), 10));
        assert!(federated_client_allows_server_id(Some(&identity), 20));
        assert!(!federated_client_allows_server_id(Some(&identity), 30));
        assert!(federated_client_allows_server_id(None, 30));
    }

    #[test]
    fn federated_client_scope_guard_hides_unclaimed_servers() {
        let identity = federated_identity(vec![10]);

        require_federated_client_server_scope(Some(&identity), 10)
            .expect("claimed server should be allowed");
        assert!(require_federated_client_server_scope(None, 999).is_ok());

        let error = require_federated_client_server_scope(Some(&identity), 11)
            .expect_err("unclaimed server should fail closed");
        assert!(matches!(error, crate::error::AppError::NotFound("server")));
    }

    #[test]
    fn federated_client_channel_scope_rejects_dm_and_unclaimed_server_channels() {
        let identity = federated_identity(vec![10]);

        require_federated_client_channel_scope(Some(&identity), Some(10))
            .expect("claimed server channel should be allowed");

        let dm_error = require_federated_client_channel_scope(Some(&identity), None)
            .expect_err("server capability should not allow DMs");
        assert!(matches!(
            dm_error,
            crate::error::AppError::NotFound("channel")
        ));

        let channel_error = require_federated_client_channel_scope(Some(&identity), Some(11))
            .expect_err("unclaimed server channel should fail closed");
        assert!(matches!(
            channel_error,
            crate::error::AppError::NotFound("channel")
        ));
    }

    #[test]
    fn classifies_federated_client_rest_routes_as_an_allowlist() {
        assert_eq!(
            classify_federated_client_request_route(&Method::GET, "/api/servers"),
            FederatedClientRequestRoute::ServerList
        );
        assert_eq!(
            classify_federated_client_request_route(&Method::POST, "/api/servers"),
            FederatedClientRequestRoute::Deny
        );
        assert_eq!(
            classify_federated_client_request_route(&Method::GET, "/api/servers/10/roles"),
            FederatedClientRequestRoute::Server { server_id: 10 }
        );
        assert_eq!(
            classify_federated_client_request_route(&Method::POST, "/api/channels/20/messages"),
            FederatedClientRequestRoute::Channel { channel_id: 20 }
        );
        assert_eq!(
            classify_federated_client_request_route(&Method::GET, "/api/users/me"),
            FederatedClientRequestRoute::CurrentUser
        );
        assert_eq!(
            classify_federated_client_request_route(&Method::GET, "/api/dms"),
            FederatedClientRequestRoute::Deny
        );
        assert_eq!(
            classify_federated_client_request_route(&Method::GET, "/api/servers/not-a-number"),
            FederatedClientRequestRoute::Deny
        );
    }
}

/// Middleware that extracts a Bearer user token or Bot token and injects
/// identity extensions into the request.
/// Security invariant: this is the only path that populates `UserId`.
/// Handlers must treat request bodies and path IDs as untrusted subject data.
pub async fn auth_middleware(
    axum::extract::State(state): axum::extract::State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    if let Some(connect_info) = req.extensions().get::<ConnectInfo<SocketAddr>>() {
        let ip = crate::handlers::extract_client_ip(req.headers(), connect_info);
        crate::services::app_bans::ensure_ip_not_banned(&state, &ip).await?;
    }

    let auth_header = req
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let auth_header = match auth_header {
        Some(h) => h,
        None => {
            tracing::warn!(path = %req.uri().path(), "Auth failed: missing token");
            return Err(AppError::TokenRequired);
        }
    };

    if let Some(raw_token) = auth_header.strip_prefix("Bot ") {
        // Bot tokens keep their scoped BotIdentity alongside UserId so bot-aware
        // handlers can enforce token scopes instead of treating them as users.
        let bot = match authenticate_bot_token(&state, raw_token).await {
            Ok(bot) => bot,
            Err(AppError::TokenInvalid) => {
                tracing::warn!(path = %req.uri().path(), "Auth failed: invalid or revoked bot token");
                return Err(AppError::TokenInvalid);
            }
            Err(e) => return Err(e),
        };
        let bot_id = bot.bot_id;
        let server_id = bot.server_id;
        tracing::debug!(bot_id, server_id, path = %req.uri().path(), "Bot auth successful");
        req.extensions_mut().insert(bot);
        req.extensions_mut().insert(UserId(bot_id));
        req.extensions_mut().insert(SessionId(None));
        return Ok(next.run(req).await);
    }

    let token = match auth_header.strip_prefix("Bearer ") {
        Some(t) => t,
        None => {
            tracing::warn!(path = %req.uri().path(), "Auth failed: malformed Authorization header");
            return Err(AppError::TokenRequired);
        }
    };

    let verified = match crypto::verify_access_token_for_instance(
        token,
        &state.config.jwt_secret,
        &state.redis,
        Some(&state.config.instance_id),
    )
    .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(path = %req.uri().path(), error = %e, "Auth failed: invalid/expired token");
            return Err(e);
        }
    };
    let federated_client_identity = federated_client_identity_for_token(&state, &verified).await?;
    if let Some(identity) = federated_client_identity.as_ref() {
        require_federated_client_request_scope(&state, identity, req.method(), req.uri().path())
            .await?;
    }

    let is_deleted = state
        .user_profiles
        .is_deleted_vdb(&state, verified.user_id)
        .await;

    if is_deleted {
        tracing::warn!(
            user_id = verified.user_id,
            "Auth rejected: account is soft-deleted"
        );
        return Err(AppError::WithCode {
            status: axum::http::StatusCode::UNAUTHORIZED,
            code: "AUTH_TOKEN_INVALID",
            message: "Your session has expired. Please sign in again.".into(),
        });
    }

    crate::services::app_bans::ensure_user_not_banned(&state, verified.user_id).await?;

    if matches!(verified.kind, VerifiedTokenKind::UserSession)
        && state.config.email_verification_required()
        && !unverified_access_allowed(req.method(), req.uri().path())
    {
        let email_verified =
            crate::services::pg::users::email_verified_by_id(&state.pg, verified.user_id)
                .await
                .map_err(|e| {
                    tracing::error!(
                        user_id = verified.user_id,
                        error = %e,
                        "Auth failed: email verification check failed"
                    );
                    AppError::Internal
                })?
                .unwrap_or(false);

        if !email_verified {
            tracing::warn!(
                user_id = verified.user_id,
                path = %req.uri().path(),
                "Auth rejected: email verification required"
            );
            return Err(AppError::WithCode {
                status: StatusCode::FORBIDDEN,
                code: "EMAIL_VERIFICATION_REQUIRED",
                message: "Please verify your email address to continue.".into(),
            });
        }
    }

    tracing::debug!(user_id = verified.user_id, path = %req.uri().path(), "Auth successful");
    req.extensions_mut().insert(UserId(verified.user_id));
    req.extensions_mut().insert(SessionId(verified.session_id));
    if let Some(identity) = federated_client_identity {
        req.extensions_mut().insert(identity);
    }
    Ok(next.run(req).await)
}
