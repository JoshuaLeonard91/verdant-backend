use axum::{
    Json,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
};
use chrono::{Duration, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::LazyLock,
    time::Duration as StdDuration,
};

use crate::config::InstanceMode;
use crate::error::{AppError, AppResult};
use crate::middleware::{auth::UserId, rate_limit};
use crate::services::{
    audit::{self, AuditAction, AuditEntry},
    crypto,
    pg::{self, account_links as pg_account_links, federation as pg_federation},
};
use crate::state::AppState;

const ACCOUNT_LINK_INTENT_TTL_MS: i64 = 10 * 60 * 1000;
const ACCOUNT_LINK_PROOF_TTL_SECS: i64 = 5 * 60;
const MAX_LINK_SCOPES: usize = 8;
const MAX_INSTANCE_ID_CHARS: usize = 128;
const MAX_STATE_CHARS: usize = 256;
const MAX_PROOF_TOKEN_CHARS: usize = 8192;
const MAX_REVOCATION_HASHES: usize = 50;
const PROVIDER_OFFICIAL: &str = "official";
const DEFAULT_ISSUER_INSTANCE_ID: &str = "host:api.verdant.chat";
const IDENTITY_BASIC_SCOPE: &str = "identity.basic";
const ALLOWED_LINK_SCOPES: &[&str] = &[IDENTITY_BASIC_SCOPE];
const ACCOUNT_LINK_REVOCATION_STATUS_PATH: &str = "/api/account-link-revocations/status";
const REVOCATION_STATUS_ACTIVE: &str = "active";
const REVOCATION_STATUS_REVOKED: &str = "revoked";
const REVOCATION_STATUS_UNKNOWN: &str = "unknown";

static REVOCATION_HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(StdDuration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("account-link revocation HTTP client")
});

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountLinkResponse {
    pub id: String,
    pub provider: String,
    pub issuer_instance_id: String,
    pub issuer_user_id: String,
    pub issuer_username: Option<String>,
    pub issuer_display_name: Option<String>,
    pub scopes: Value,
    pub status: String,
    pub linked_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
    pub revocation_checked_at_ms: Option<i64>,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountLinksResponse {
    pub links: Vec<AccountLinkResponse>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuedAccountLinkGrantResponse {
    pub id: String,
    pub audience_instance_id: String,
    pub audience_api_origin: String,
    pub scopes: Value,
    pub status: String,
    pub issued_at_ms: i64,
    pub revoked_at_ms: Option<i64>,
    pub updated_at_ms: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuedAccountLinkGrantsResponse {
    pub grants: Vec<IssuedAccountLinkGrantResponse>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountLinkIntentRequest {
    pub issuer_instance_id: Option<String>,
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAccountLinkIntentResponse {
    pub intent_id: String,
    pub issuer_instance_id: String,
    pub audience_instance_id: String,
    pub state: String,
    pub scopes: Value,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueAccountLinkProofRequest {
    pub audience_instance_id: String,
    pub audience_api_origin: String,
    pub state: String,
    pub scopes: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssueAccountLinkProofResponse {
    pub proof_token: String,
    pub token_type: &'static str,
    pub proof_algorithm: &'static str,
    pub expires_at_ms: i64,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CompleteAccountLinkRequest {
    pub state: String,
    pub proof_token: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountLinkRevocationStatusRequest {
    pub proof_jti_hashes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountLinkRevocationStatusItem {
    pub proof_jti_hash: String,
    pub status: String,
    pub revoked_at_ms: Option<i64>,
    pub updated_at_ms: Option<i64>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountLinkRevocationStatusResponse {
    pub statuses: Vec<AccountLinkRevocationStatusItem>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountLinkRevocationSyncResponse {
    pub links: Vec<AccountLinkResponse>,
    pub checked: usize,
    pub revoked: usize,
    pub stale: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountLinkProofClaims {
    iss: String,
    sub: String,
    aud: String,
    exp: i64,
    iat: i64,
    jti: String,
    state_hash: String,
    scopes: Vec<String>,
    username: Option<String>,
    display_name: Option<String>,
}

fn link_response(row: pg_account_links::AccountLinkRow) -> AccountLinkResponse {
    AccountLinkResponse {
        id: row.id.to_string(),
        provider: row.provider,
        issuer_instance_id: row.issuer_instance_id,
        issuer_user_id: row.issuer_user_id,
        issuer_username: row.issuer_username,
        issuer_display_name: row.issuer_display_name,
        scopes: pg_account_links::scopes_to_json(&row.scopes),
        status: row.status,
        linked_at_ms: row.linked_at_ms,
        revoked_at_ms: row.revoked_at_ms,
        revocation_checked_at_ms: row.revocation_checked_at_ms,
        updated_at_ms: row.updated_at_ms,
    }
}

fn issued_grant_response(
    row: pg_account_links::IssuedAccountLinkGrantRow,
) -> IssuedAccountLinkGrantResponse {
    IssuedAccountLinkGrantResponse {
        id: row.id.to_string(),
        audience_instance_id: row.audience_instance_id,
        audience_api_origin: row.audience_api_origin,
        scopes: pg_account_links::scopes_to_json(&row.scopes),
        status: row.status,
        issued_at_ms: row.issued_at_ms,
        revoked_at_ms: row.revoked_at_ms,
        updated_at_ms: row.updated_at_ms,
    }
}

fn account_linking_not_configured() -> AppError {
    AppError::WithCode {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: "ACCOUNT_LINKING_NOT_CONFIGURED",
        message: "Account linking is not configured on this instance".into(),
    }
}

fn account_linking_disabled() -> AppError {
    AppError::WithCode {
        status: StatusCode::FORBIDDEN,
        code: "ACCOUNT_LINKING_DISABLED",
        message: "Account linking is not enabled on this instance".into(),
    }
}

fn invalid_link_proof() -> AppError {
    AppError::WithCode {
        status: StatusCode::UNAUTHORIZED,
        code: "ACCOUNT_LINK_PROOF_INVALID",
        message: "Account link proof is invalid or expired".into(),
    }
}

fn invalid_link_state() -> AppError {
    AppError::WithCode {
        status: StatusCode::BAD_REQUEST,
        code: "ACCOUNT_LINK_STATE_INVALID",
        message: "Account link state is invalid or expired".into(),
    }
}

fn untrusted_link_audience() -> AppError {
    AppError::WithCode {
        status: StatusCode::FORBIDDEN,
        code: "ACCOUNT_LINK_AUDIENCE_UNTRUSTED",
        message: "Account link audience is not verified by the official registry".into(),
    }
}

fn ensure_link_consumer(state: &AppState) -> AppResult<&str> {
    match state.config.instance_mode {
        InstanceMode::Linked | InstanceMode::Federated => {}
        InstanceMode::Official | InstanceMode::Standalone => return Err(account_linking_disabled()),
    }

    state
        .config
        .federation_link_verify_key_pem
        .as_deref()
        .filter(|key| !key.trim().is_empty())
        .ok_or_else(account_linking_not_configured)
}

fn ensure_link_issuer(state: &AppState) -> AppResult<&str> {
    if state.config.instance_mode != InstanceMode::Official {
        return Err(account_linking_disabled());
    }

    state
        .config
        .federation_link_signing_key_pem
        .as_deref()
        .filter(|key| !key.trim().is_empty())
        .ok_or_else(account_linking_not_configured)
}

fn normalize_instance_id(raw: &str, field: &str) -> AppResult<String> {
    let value = crate::services::sanitize::sanitize_text(raw);
    if value.is_empty() || value.chars().count() > MAX_INSTANCE_ID_CHARS {
        return Err(AppError::Validation(format!("{field} is invalid")));
    }
    if value
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '/' | '\\' | '?' | '#' | '@'))
    {
        return Err(AppError::Validation(format!("{field} is invalid")));
    }
    Ok(value)
}

fn normalize_state(raw: &str) -> AppResult<String> {
    let value = raw.trim();
    if value.is_empty()
        || value.chars().count() > MAX_STATE_CHARS
        || value.chars().any(|c| !c.is_ascii() || c.is_control())
    {
        return Err(invalid_link_state());
    }
    Ok(value.to_string())
}

fn normalize_proof_jti_hashes(raw: Vec<String>) -> AppResult<Vec<String>> {
    if raw.is_empty() || raw.len() > MAX_REVOCATION_HASHES {
        return Err(AppError::Validation(
            "Account link revocation status request is invalid".into(),
        ));
    }

    let mut seen = HashSet::with_capacity(raw.len());
    let mut hashes = Vec::with_capacity(raw.len());
    for value in raw {
        let hash = value.trim().to_ascii_lowercase();
        if hash.len() != 64 || !hash.chars().all(|ch| ch.is_ascii_hexdigit()) {
            return Err(AppError::Validation(
                "Account link revocation status request is invalid".into(),
            ));
        }
        if seen.insert(hash.clone()) {
            hashes.push(hash);
        }
    }
    Ok(hashes)
}

fn audience_host_from_instance_id(instance_id: &str) -> AppResult<String> {
    let Some(host) = instance_id.strip_prefix("host:") else {
        return Err(untrusted_link_audience());
    };
    super::federation::normalize_registry_domain(host)
}

fn normalize_audience_api_origin(raw: &str) -> AppResult<String> {
    super::federation::normalize_registry_origin(raw).map_err(|_| untrusted_link_audience())
}

fn registry_api_origin_matches(row_api_url: &str, audience_api_origin: &str) -> bool {
    match (
        normalize_audience_api_origin(row_api_url),
        normalize_audience_api_origin(audience_api_origin),
    ) {
        (Ok(row_api_origin), Ok(audience_api_origin)) => row_api_origin == audience_api_origin,
        _ => false,
    }
}

fn normalize_scopes(input: Option<Vec<String>>) -> AppResult<Vec<String>> {
    let raw = input.unwrap_or_else(|| vec![IDENTITY_BASIC_SCOPE.to_string()]);
    if raw.is_empty() || raw.len() > MAX_LINK_SCOPES {
        return Err(AppError::Validation("Invalid account link scopes".into()));
    }

    let mut scopes = Vec::with_capacity(raw.len());
    for scope in raw {
        let scope = scope.trim().to_ascii_lowercase();
        if !ALLOWED_LINK_SCOPES.contains(&scope.as_str()) {
            return Err(AppError::Validation("Invalid account link scope".into()));
        }
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
    scopes.sort();
    Ok(scopes)
}

fn proof_scopes_match_request(proof_scopes: &[String], requested_scopes: &[String]) -> bool {
    !proof_scopes.is_empty()
        && proof_scopes
            .iter()
            .all(|scope| requested_scopes.iter().any(|requested| requested == scope))
}

async fn ensure_trusted_link_audience(
    state: &AppState,
    audience_instance_id: &str,
    audience_api_origin: &str,
) -> AppResult<pg_federation::FederationInstanceRow> {
    let audience_host = audience_host_from_instance_id(audience_instance_id)?;
    let audience_api_origin = normalize_audience_api_origin(audience_api_origin)?;
    let row = pg_federation::verified_by_audience_host(&state.pg, &audience_host)
        .await
        .map_err(|e| {
            tracing::error!(
                audience_host = %audience_host,
                error = %e,
                "Account link audience registry lookup failed"
            );
            AppError::Internal
        })?
        .ok_or_else(untrusted_link_audience)?;
    if !registry_api_origin_matches(&row.api_url, &audience_api_origin) {
        tracing::warn!(
            audience_host = %audience_host,
            requested_api_origin = %audience_api_origin,
            registry_api_url = %row.api_url,
            "Account link audience API origin did not match registry"
        );
        return Err(untrusted_link_audience());
    }
    Ok(row)
}

fn generate_state() -> String {
    crypto::generate_session_token()
}

fn revocation_status_url(official_api_origin: &str) -> String {
    format!(
        "{}{}",
        official_api_origin.trim_end_matches('/'),
        ACCOUNT_LINK_REVOCATION_STATUS_PATH
    )
}

async fn fetch_official_revocation_statuses(
    official_api_origin: &str,
    proof_jti_hashes: &[String],
) -> AppResult<HashMap<String, AccountLinkRevocationStatusItem>> {
    if proof_jti_hashes.is_empty() {
        return Ok(HashMap::new());
    }

    let url = revocation_status_url(official_api_origin);
    let response = REVOCATION_HTTP_CLIENT
        .post(url)
        .json(&AccountLinkRevocationStatusRequest {
            proof_jti_hashes: proof_jti_hashes.to_vec(),
        })
        .send()
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "Official account-link revocation status request failed");
            AppError::WithCode {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "ACCOUNT_LINK_REVOCATION_SYNC_UNAVAILABLE",
                message: "Could not check official account link revocation status".into(),
            }
        })?;

    if !response.status().is_success() {
        tracing::warn!(
            status = response.status().as_u16(),
            "Official account-link revocation status request returned an error"
        );
        return Err(AppError::WithCode {
            status: StatusCode::SERVICE_UNAVAILABLE,
            code: "ACCOUNT_LINK_REVOCATION_SYNC_UNAVAILABLE",
            message: "Could not check official account link revocation status".into(),
        });
    }

    let body = response
        .json::<AccountLinkRevocationStatusResponse>()
        .await
        .map_err(|error| {
            tracing::warn!(error = %error, "Official account-link revocation status response was invalid");
            AppError::WithCode {
                status: StatusCode::SERVICE_UNAVAILABLE,
                code: "ACCOUNT_LINK_REVOCATION_SYNC_INVALID",
                message: "Official account link revocation status response was invalid".into(),
            }
        })?;

    let mut statuses = HashMap::with_capacity(body.statuses.len());
    for item in body.statuses {
        let hash = item.proof_jti_hash.trim().to_ascii_lowercase();
        if proof_jti_hashes.iter().any(|requested| requested == &hash) {
            statuses.insert(hash, item);
        }
    }
    Ok(statuses)
}

fn signed_proof(private_key_pem: &str, claims: &AccountLinkProofClaims) -> AppResult<String> {
    let key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes()).map_err(|e| {
        tracing::error!(error = %e, "Account link signing key is invalid");
        account_linking_not_configured()
    })?;
    let header = Header::new(Algorithm::RS256);
    encode(&header, claims, &key).map_err(|e| {
        tracing::error!(error = %e, "Account link proof signing failed");
        AppError::Internal
    })
}

fn verify_proof(
    public_key_pem: &str,
    proof_token: &str,
    audience_instance_id: &str,
) -> AppResult<AccountLinkProofClaims> {
    if proof_token.trim().is_empty() || proof_token.chars().count() > MAX_PROOF_TOKEN_CHARS {
        return Err(invalid_link_proof());
    }

    let key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes()).map_err(|e| {
        tracing::error!(error = %e, "Account link verify key is invalid");
        account_linking_not_configured()
    })?;
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[audience_instance_id]);
    validation.leeway = 30;

    decode::<AccountLinkProofClaims>(proof_token, &key, &validation)
        .map(|data| data.claims)
        .map_err(|e| {
            tracing::warn!(error = %e, "Account link proof verification failed");
            invalid_link_proof()
        })
}

fn map_link_insert_error(error: sqlx::Error) -> AppError {
    if let sqlx::Error::Database(db) = &error
        && db.is_unique_violation()
    {
        return AppError::WithCode {
            status: StatusCode::CONFLICT,
            code: "ACCOUNT_LINK_CONFLICT",
            message: "That official account is already linked".into(),
        };
    }
    tracing::error!(error = %error, "Account link database write failed");
    AppError::Internal
}

pub async fn list_account_links(
    State(state): State<AppState>,
    user_id: UserId,
) -> AppResult<Json<AccountLinksResponse>> {
    rate_limit::enforce(&state, &rate_limit::API_LIMIT, &user_id.0.to_string()).await?;
    let rows = pg_account_links::list_for_user(&state.pg, user_id.0)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "Account link list failed");
            AppError::Internal
        })?;

    Ok(Json(AccountLinksResponse {
        links: rows.into_iter().map(link_response).collect(),
    }))
}

pub async fn list_issued_account_link_grants(
    State(state): State<AppState>,
    user_id: UserId,
) -> AppResult<Json<IssuedAccountLinkGrantsResponse>> {
    let _signing_key = ensure_link_issuer(&state)?;
    rate_limit::enforce(&state, &rate_limit::API_LIMIT, &user_id.0.to_string()).await?;
    let rows = pg_account_links::list_issued_grants_for_user(&state.pg, user_id.0)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "Issued account link grants list failed");
            AppError::Internal
        })?;

    Ok(Json(IssuedAccountLinkGrantsResponse {
        grants: rows.into_iter().map(issued_grant_response).collect(),
    }))
}

pub async fn create_account_link_intent(
    State(state): State<AppState>,
    user_id: UserId,
    Json(body): Json<CreateAccountLinkIntentRequest>,
) -> AppResult<Json<CreateAccountLinkIntentResponse>> {
    let _verify_key = ensure_link_consumer(&state)?;
    rate_limit::enforce(&state, &rate_limit::AUTH_LIMIT, &user_id.0.to_string()).await?;

    let issuer_instance_id = match body.issuer_instance_id {
        Some(value) => normalize_instance_id(&value, "issuerInstanceId")?,
        None => DEFAULT_ISSUER_INSTANCE_ID.to_string(),
    };
    let audience_instance_id = normalize_instance_id(&state.config.instance_id, "instanceId")?;
    let scopes = normalize_scopes(body.scopes)?;
    let state_value = generate_state();
    let state_hash = crypto::hash_token(&state_value);
    let now_ms = pg::now_ms();
    let expires_at_ms = now_ms + ACCOUNT_LINK_INTENT_TTL_MS;
    let row = pg_account_links::create_intent(
        &state.pg,
        pg_account_links::InsertAccountLinkIntent {
            id: state.snowflake.next_id(),
            local_user_id: user_id.0,
            issuer_instance_id: &issuer_instance_id,
            audience_instance_id: &audience_instance_id,
            state_hash: &state_hash,
            requested_scopes: &scopes,
            expires_at_ms,
            now_ms,
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(user_id = user_id.0, error = %e, "Account link intent create failed");
        AppError::Internal
    })?;

    tracing::info!(
        user_id = user_id.0,
        intent_id = row.id,
        issuer_instance_id = %row.issuer_instance_id,
        audience_instance_id = %row.audience_instance_id,
        "Account link intent created"
    );
    audit::log_async(
        state.redis.clone(),
        AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id.0,
            action: AuditAction::AccountLinkIntent,
            target_type: "account_link_intent",
            target_id: row.id,
            server_id: None,
            metadata: Some(serde_json::json!({
                "issuerInstanceId": &row.issuer_instance_id,
                "audienceInstanceId": &row.audience_instance_id,
                "expiresAtMs": row.expires_at_ms,
            })),
            ip: None,
        },
        state.pg.clone(),
    );

    Ok(Json(CreateAccountLinkIntentResponse {
        intent_id: row.id.to_string(),
        issuer_instance_id: row.issuer_instance_id,
        audience_instance_id: row.audience_instance_id,
        state: state_value,
        scopes: pg_account_links::scopes_to_json(&row.requested_scopes),
        expires_at_ms: row.expires_at_ms,
    }))
}

pub async fn issue_account_link_proof(
    State(state): State<AppState>,
    user_id: UserId,
    Json(body): Json<IssueAccountLinkProofRequest>,
) -> AppResult<Json<IssueAccountLinkProofResponse>> {
    let signing_key = ensure_link_issuer(&state)?;
    rate_limit::enforce(&state, &rate_limit::AUTH_LIMIT, &user_id.0.to_string()).await?;

    let audience_instance_id =
        normalize_instance_id(&body.audience_instance_id, "audienceInstanceId")?;
    let audience_api_origin = normalize_audience_api_origin(&body.audience_api_origin)?;
    let audience =
        ensure_trusted_link_audience(&state, &audience_instance_id, &audience_api_origin).await?;
    let state_value = normalize_state(&body.state)?;
    let scopes = normalize_scopes(body.scopes)?;
    let user = pg::users::by_id(&state.pg, user_id.0)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "Account link proof user lookup failed");
            AppError::Internal
        })?
        .ok_or(AppError::TokenInvalid)?;

    let now = Utc::now();
    let expires = now + Duration::seconds(ACCOUNT_LINK_PROOF_TTL_SECS);
    let claims = AccountLinkProofClaims {
        iss: normalize_instance_id(&state.config.instance_id, "instanceId")?,
        sub: user_id.0.to_string(),
        aud: audience_instance_id,
        exp: expires.timestamp(),
        iat: now.timestamp(),
        jti: uuid::Uuid::new_v4().to_string(),
        state_hash: crypto::hash_token(&state_value),
        scopes,
        username: Some(user.username),
        display_name: user.display_name,
    };
    let proof_jti_hash = crypto::hash_token(&claims.jti);
    let proof_token = signed_proof(signing_key, &claims)?;
    let grant = pg_account_links::insert_issued_grant(
        &state.pg,
        pg_account_links::InsertIssuedAccountLinkGrant {
            id: state.snowflake.next_id(),
            issuer_user_id: user_id.0,
            audience_instance_id: &claims.aud,
            audience_api_origin: &audience_api_origin,
            proof_jti_hash: &proof_jti_hash,
            scopes: &claims.scopes,
            now_ms: now.timestamp_millis(),
        },
    )
    .await
    .map_err(|e| {
        tracing::error!(user_id = user_id.0, error = %e, "Issued account link grant insert failed");
        AppError::Internal
    })?;

    tracing::info!(
        user_id = user_id.0,
        grant_id = grant.id,
        audience_instance_id = %claims.aud,
        audience_domain = %audience.domain,
        "Account link proof issued"
    );
    audit::log_async(
        state.redis.clone(),
        AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id.0,
            action: AuditAction::AccountLinkProofIssue,
            target_type: "account_link_audience",
            target_id: audience.id,
            server_id: None,
            metadata: Some(serde_json::json!({
                "audienceInstanceId": claims.aud,
                "audienceDomain": audience.domain,
                "audienceApiUrl": audience.api_url,
                "grantId": grant.id.to_string(),
                "proofAlgorithm": "RS256",
                "expiresAtMs": expires.timestamp_millis(),
            })),
            ip: None,
        },
        state.pg.clone(),
    );

    Ok(Json(IssueAccountLinkProofResponse {
        proof_token,
        token_type: "account_link_proof",
        proof_algorithm: "RS256",
        expires_at_ms: expires.timestamp_millis(),
    }))
}

pub async fn revoke_issued_account_link_grant(
    State(state): State<AppState>,
    user_id: UserId,
    Path(grant_id): Path<String>,
) -> AppResult<Json<IssuedAccountLinkGrantResponse>> {
    let _signing_key = ensure_link_issuer(&state)?;
    rate_limit::enforce(&state, &rate_limit::AUTH_LIMIT, &user_id.0.to_string()).await?;
    let id = super::parse_id(&grant_id)?;
    let now_ms = pg::now_ms();
    let row = pg_account_links::revoke_issued_grant_for_user(&state.pg, id, user_id.0, now_ms)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, grant_id = id, error = %e, "Issued account link grant revoke failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("account link grant"))?;

    audit::log_async(
        state.redis.clone(),
        AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id.0,
            action: AuditAction::AccountLinkRevoke,
            target_type: "account_link_issued_grant",
            target_id: row.id,
            server_id: None,
            metadata: Some(serde_json::json!({
                "audienceInstanceId": &row.audience_instance_id,
                "audienceApiOrigin": &row.audience_api_origin,
            })),
            ip: None,
        },
        state.pg.clone(),
    );

    Ok(Json(issued_grant_response(row)))
}

pub async fn complete_account_link(
    State(state): State<AppState>,
    user_id: UserId,
    Json(body): Json<CompleteAccountLinkRequest>,
) -> AppResult<Json<AccountLinkResponse>> {
    let verify_key = ensure_link_consumer(&state)?;
    rate_limit::enforce(&state, &rate_limit::AUTH_LIMIT, &user_id.0.to_string()).await?;

    let state_value = normalize_state(&body.state)?;
    let state_hash = crypto::hash_token(&state_value);
    let audience_instance_id = normalize_instance_id(&state.config.instance_id, "instanceId")?;
    let proof = verify_proof(verify_key, &body.proof_token, &audience_instance_id)?;

    if proof.state_hash != state_hash {
        tracing::warn!(user_id = user_id.0, "Account link proof state mismatch");
        return Err(invalid_link_proof());
    }
    let issuer_instance_id = normalize_instance_id(&proof.iss, "issuer")?;
    let issuer_user_id = normalize_instance_id(&proof.sub, "issuerUserId")?;
    let issuer_username = proof
        .username
        .map(|value| crate::services::sanitize::sanitize_text(&value))
        .filter(|value| !value.is_empty());
    let issuer_display_name = proof
        .display_name
        .map(|value| crate::services::sanitize::sanitize_text(&value))
        .filter(|value| !value.is_empty());
    let now_ms = pg::now_ms();

    let mut tx = state.pg.begin().await.map_err(|e| {
        tracing::error!(user_id = user_id.0, error = %e, "Account link transaction begin failed");
        AppError::Internal
    })?;

    let Some(intent) = pg_account_links::pending_intent_by_state_for_update(
        &mut tx,
        user_id.0,
        &state_hash,
    )
    .await
    .map_err(|e| {
        tracing::error!(user_id = user_id.0, error = %e, "Account link intent lookup failed");
        AppError::Internal
    })?
    else {
        let _ = tx.rollback().await;
        return Err(invalid_link_state());
    };

    if intent.expires_at_ms <= now_ms {
        let _ = pg_account_links::mark_intent_expired(&mut tx, intent.id, now_ms).await;
        let _ = tx.commit().await;
        return Err(invalid_link_state());
    }
    if intent.audience_instance_id != audience_instance_id
        || intent.issuer_instance_id != issuer_instance_id
    {
        let _ = tx.rollback().await;
        return Err(invalid_link_proof());
    }
    if !proof_scopes_match_request(&proof.scopes, &intent.requested_scopes) {
        let _ = tx.rollback().await;
        return Err(AppError::Validation(
            "Account link proof scopes do not match the request".into(),
        ));
    }

    pg_account_links::revoke_active_conflicts(
        &mut tx,
        user_id.0,
        PROVIDER_OFFICIAL,
        &issuer_instance_id,
        now_ms,
    )
    .await
    .map_err(map_link_insert_error)?;

    let proof_jti_hash = crypto::hash_token(&proof.jti);
    let link = pg_account_links::insert_link(
        &mut tx,
        pg_account_links::InsertAccountLink {
            id: state.snowflake.next_id(),
            local_user_id: user_id.0,
            provider: PROVIDER_OFFICIAL,
            issuer_instance_id: &issuer_instance_id,
            issuer_user_id: &issuer_user_id,
            issuer_username: issuer_username.as_deref(),
            issuer_display_name: issuer_display_name.as_deref(),
            scopes: &proof.scopes,
            proof_jti_hash: Some(&proof_jti_hash),
            now_ms,
        },
    )
    .await
    .map_err(map_link_insert_error)?;

    pg_account_links::mark_intent_completed(&mut tx, intent.id, now_ms)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, intent_id = intent.id, error = %e, "Account link intent complete failed");
            AppError::Internal
        })?;

    tx.commit().await.map_err(|e| {
        tracing::error!(user_id = user_id.0, error = %e, "Account link transaction commit failed");
        AppError::Internal
    })?;

    tracing::info!(
        user_id = user_id.0,
        link_id = link.id,
        issuer_instance_id = %link.issuer_instance_id,
        "Account link completed"
    );
    audit::log_async(
        state.redis.clone(),
        AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id.0,
            action: AuditAction::AccountLinkComplete,
            target_type: "account_link",
            target_id: link.id,
            server_id: None,
            metadata: Some(serde_json::json!({
                "issuerInstanceId": &link.issuer_instance_id,
                "issuerUserId": &link.issuer_user_id,
                "provider": &link.provider,
            })),
            ip: None,
        },
        state.pg.clone(),
    );

    Ok(Json(link_response(link)))
}

pub async fn account_link_revocation_status(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(body): Json<AccountLinkRevocationStatusRequest>,
) -> AppResult<Json<AccountLinkRevocationStatusResponse>> {
    let _signing_key = ensure_link_issuer(&state)?;
    let ip = super::extract_client_ip(&headers, &ConnectInfo(addr));
    rate_limit::enforce(&state, &rate_limit::API_LIMIT, &ip).await?;
    let proof_jti_hashes = normalize_proof_jti_hashes(body.proof_jti_hashes)?;
    let rows = pg_account_links::issued_grants_by_proof_hashes(&state.pg, &proof_jti_hashes)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "Issued account link grant status lookup failed");
            AppError::Internal
        })?;
    let rows_by_hash: HashMap<String, pg_account_links::IssuedAccountLinkGrantRow> = rows
        .into_iter()
        .map(|row| (row.proof_jti_hash.clone(), row))
        .collect();
    let statuses = proof_jti_hashes
        .into_iter()
        .map(|proof_jti_hash| {
            let Some(row) = rows_by_hash.get(&proof_jti_hash) else {
                return AccountLinkRevocationStatusItem {
                    proof_jti_hash,
                    status: REVOCATION_STATUS_UNKNOWN.to_string(),
                    revoked_at_ms: None,
                    updated_at_ms: None,
                };
            };
            AccountLinkRevocationStatusItem {
                proof_jti_hash,
                status: if row.status == REVOCATION_STATUS_REVOKED {
                    REVOCATION_STATUS_REVOKED.to_string()
                } else {
                    REVOCATION_STATUS_ACTIVE.to_string()
                },
                revoked_at_ms: row.revoked_at_ms,
                updated_at_ms: Some(row.updated_at_ms),
            }
        })
        .collect();

    Ok(Json(AccountLinkRevocationStatusResponse { statuses }))
}

pub async fn sync_account_link_revocations(
    State(state): State<AppState>,
    user_id: UserId,
) -> AppResult<Json<AccountLinkRevocationSyncResponse>> {
    let _verify_key = ensure_link_consumer(&state)?;
    rate_limit::enforce(&state, &rate_limit::AUTH_LIMIT, &user_id.0.to_string()).await?;
    let candidates = pg_account_links::list_revocation_sync_candidates_for_user(
        &state.pg,
        user_id.0,
        PROVIDER_OFFICIAL,
    )
    .await
    .map_err(|e| {
        tracing::error!(user_id = user_id.0, error = %e, "Account link revocation sync candidate lookup failed");
        AppError::Internal
    })?;

    let proof_jti_hashes: Vec<String> = candidates
        .iter()
        .filter_map(|link| link.proof_jti_hash.clone())
        .collect();
    let statuses = fetch_official_revocation_statuses(
        &state.config.account_link_official_api_origin,
        &proof_jti_hashes,
    )
    .await?;
    let now_ms = pg::now_ms();
    let mut revoked = 0usize;
    let mut stale = 0usize;

    for link in candidates {
        let Some(proof_jti_hash) = link.proof_jti_hash.as_deref() else {
            continue;
        };
        let status = statuses
            .get(proof_jti_hash)
            .map(|item| item.status.as_str())
            .unwrap_or(REVOCATION_STATUS_UNKNOWN);
        match status {
            REVOCATION_STATUS_ACTIVE => {
                let _ = pg_account_links::mark_link_revocation_checked(
                    &state.pg, link.id, user_id.0, now_ms,
                )
                .await
                .map_err(|e| {
                    tracing::error!(user_id = user_id.0, link_id = link.id, error = %e, "Account link revocation check update failed");
                    AppError::Internal
                })?;
            }
            REVOCATION_STATUS_REVOKED => {
                let revoked_at_ms = statuses
                    .get(proof_jti_hash)
                    .and_then(|item| item.revoked_at_ms)
                    .unwrap_or(now_ms);
                let row = pg_account_links::mark_link_revoked_from_official_sync(
                    &state.pg,
                    link.id,
                    user_id.0,
                    revoked_at_ms,
                    now_ms,
                )
                .await
                .map_err(|e| {
                    tracing::error!(user_id = user_id.0, link_id = link.id, error = %e, "Account link official revocation update failed");
                    AppError::Internal
                })?;
                if let Some(row) = row {
                    revoked += 1;
                    audit::log_async(
                        state.redis.clone(),
                        AuditEntry {
                            id: state.snowflake.next_id(),
                            actor_id: user_id.0,
                            action: AuditAction::AccountLinkRevoke,
                            target_type: "account_link",
                            target_id: row.id,
                            server_id: None,
                            metadata: Some(serde_json::json!({
                                "issuerInstanceId": &row.issuer_instance_id,
                                "issuerUserId": &row.issuer_user_id,
                                "provider": &row.provider,
                                "source": "official_revocation_sync",
                            })),
                            ip: None,
                        },
                        state.pg.clone(),
                    );
                }
            }
            _ => {
                let row = pg_account_links::mark_link_stale_from_official_sync(
                    &state.pg, link.id, user_id.0, now_ms,
                )
                .await
                .map_err(|e| {
                    tracing::error!(user_id = user_id.0, link_id = link.id, error = %e, "Account link stale update failed");
                    AppError::Internal
                })?;
                if row.is_some() {
                    stale += 1;
                }
            }
        }
    }

    let rows = pg_account_links::list_for_user(&state.pg, user_id.0)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, error = %e, "Account link list after revocation sync failed");
            AppError::Internal
        })?;

    Ok(Json(AccountLinkRevocationSyncResponse {
        links: rows.into_iter().map(link_response).collect(),
        checked: proof_jti_hashes.len(),
        revoked,
        stale,
    }))
}

pub async fn revoke_account_link(
    State(state): State<AppState>,
    user_id: UserId,
    Path(link_id): Path<String>,
) -> AppResult<Json<AccountLinkResponse>> {
    rate_limit::enforce(&state, &rate_limit::AUTH_LIMIT, &user_id.0.to_string()).await?;
    let id = super::parse_id(&link_id)?;
    let now_ms = pg::now_ms();
    let row = pg_account_links::revoke_for_user(&state.pg, id, user_id.0, now_ms)
        .await
        .map_err(|e| {
            tracing::error!(user_id = user_id.0, link_id = id, error = %e, "Account link revoke failed");
            AppError::Internal
        })?
        .ok_or(AppError::NotFound("account link"))?;

    tracing::info!(user_id = user_id.0, link_id = id, "Account link revoked");
    audit::log_async(
        state.redis.clone(),
        AuditEntry {
            id: state.snowflake.next_id(),
            actor_id: user_id.0,
            action: AuditAction::AccountLinkRevoke,
            target_type: "account_link",
            target_id: row.id,
            server_id: None,
            metadata: Some(serde_json::json!({
                "issuerInstanceId": &row.issuer_instance_id,
                "issuerUserId": &row.issuer_user_id,
                "provider": &row.provider,
            })),
            ip: None,
        },
        state.pg.clone(),
    );
    Ok(Json(link_response(row)))
}

#[cfg(test)]
mod tests {
    use super::{
        AccountLinkProofClaims, IDENTITY_BASIC_SCOPE, audience_host_from_instance_id,
        normalize_instance_id, normalize_proof_jti_hashes, normalize_scopes, normalize_state,
        proof_scopes_match_request, registry_api_origin_matches, signed_proof, verify_proof,
    };
    use chrono::Utc;

    const TEST_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDpNoqvas4Zu1YZ
xYNWt9tCTKUzSeW7UnWsWMjvBbEiX3u5FQbBiAQzCzaNJ5D7dVcCZ2DbhRI7oCCU
9ufyD/iYRinuBQTuzZ7wkaD3KkbMzALsJHUcwofHnQNS2zzQezvvkuTws0rWUOA0
SjO4QWPxNC5vfcxmlid53PjF9uSicV7AFqwncfDdSM6Y7EnnHhr1mewS+Gxa5Agl
K+yTmp1jxQ6t48C8c+mNVW8zQriyzKSn/P8i+yLgmW4JxxDRxKO5pW6W2NAcOmeY
o2chIBgIs6jlN91g50MxUHMf1sU2KKdG/MEjnqNBKQPyrnUEHWDM9DIpWHtpAk5N
bfo6Xm3DAgMBAAECggEAL/Ea7Hm/2bFVv2GHoO2V4NjBwzvnQq1ubFoqIFzir6bC
V+d3JpTQDDA7bCQcnVzfYKqg0i/WcjR2Tjk9sFjRKXiPCRO2EmNpz5mYZgcmW9Z6
qVHLU3i4EfR4qPFR3Kfgx9zCPKsW8NzaYlV4sWGb6otoGlpZiSNIBTjEWWnqUWwp
XYfd/2xpxiuCF5DDJtLkzmNUeU06Q3bpm8hvG882xruRgsRFNx7ZxHxAr4nJdFkd
6vGxaa8RZA2xaZ67sZVmpzv/nC63MyoRfZR2sXZ7SvCqXtZQj5HWAbxcq62ujwsc
RFzJKbNHnAHsiht1wtO1p4VeTeZz12foQlbQ33zkRQKBgQD+A1PJ8HGNOFe/tPD3
YeUsdS6sgDqF3R0H7MtZqNKi8G1rBHTQTPikxRvL+030xhvtNGmeyqHg+83AyzeC
HYVtw75QzV1g5fFw1hDjjkMyZMSCXP+K6RCSW1vqb93n9nm1r5PEdL9S+7ZRr0L2
fPZwFcLdmvMq9A4CvQ/2bkERfwKBgQDrCY/ExCg49JnMKi+oh6J+MkgPU1HkxJy6
8iff/iWxY+DAL73HCGy5m4X5OV9MX3zO+XC6weTQUYWF8WbXJFYCHxYGYg80AVAR
TXTWcP00WzTB2gmlf4Rr7MJ8PZNLus0t0VhenjMOuqPkCaLFycqhatCnMuq1/rYv
YTkBSvb9vQKBgHD0W9Ml5+jLkEHAnZL0ZmuxpFKzJtMWM22tv/Ob3ib00UNQlP13
7O2gdS7tDop1ej+uGfWx1/BrKOC9vW5P4GCiNcRKvmZzej0aBCKcxYboRnZOEpjb
8TGUDLigjEY1VYQUkpo+7EFji3yheh6QDSpkkuXmnJGSO5S+LBYCi07TAoGBANzq
/9dTCPt/7Y+Zl3IxCurTGChPiIoew7J0Kka/+23hEz+RoC+UG53aMPMwmgKPPiDN
FMh1tzyXY4mifad639zemzUktmWLVlbtFwT47wZnNA+Bgc+tLCrFP4jH18s2qeSH
ASjuSc9uXt3YsMZ4BZ3zaGu/0B2AbH3cRFiSvdWBAoGBALZj4kB+mzgsjmmDfkMy
pP6HNbyxva4J/F8blYCSs+aq23D+oqf6/V8GC/bGaS+28b15mR5VIwfycEbLdKo6
zkwmacSSpZvdhGJ90cNMfEIJoVjgm9VlefIpgG+opoHXqT3xdY7+dKsmhvz8IoFe
WsIonFZX6q7G7qgY+090HaA+
-----END PRIVATE KEY-----"#;

    const TEST_PUBLIC_KEY: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6TaKr2rOGbtWGcWDVrfb
QkylM0nlu1J1rFjI7wWxIl97uRUGwYgEMws2jSeQ+3VXAmdg24USO6AglPbn8g/4
mEYp7gUE7s2e8JGg9ypGzMwC7CR1HMKHx50DUts80Hs775Lk8LNK1lDgNEozuEFj
8TQub33MZpYnedz4xfbkonFewBasJ3Hw3UjOmOxJ5x4a9ZnsEvhsWuQIJSvsk5qd
Y8UOrePAvHPpjVVvM0K4ssykp/z/Ivsi4JluCccQ0cSjuaVultjQHDpnmKNnISAY
CLOo5TfdYOdDMVBzH9bFNiinRvzBI56jQSkD8q51BB1gzPQyKVh7aQJOTW36Ol5t
wwIDAQAB
-----END PUBLIC KEY-----"#;

    #[test]
    fn instance_ids_reject_transport_shapes() {
        assert_eq!(
            normalize_instance_id("official", "issuer").unwrap(),
            "official"
        );
        for raw in [
            "",
            "https://api.verdant.chat",
            "official/../admin",
            "official?x=1",
            "official account",
            "official\naccount",
        ] {
            assert!(
                normalize_instance_id(raw, "issuer").is_err(),
                "{raw} accepted"
            );
        }
    }

    #[test]
    fn state_accepts_only_small_ascii_tokens() {
        assert!(normalize_state("abc_123-xyz").is_ok());
        assert!(normalize_state("").is_err());
        assert!(normalize_state("abc\n123").is_err());
        assert!(normalize_state(&"a".repeat(super::MAX_STATE_CHARS + 1)).is_err());
    }

    #[test]
    fn account_link_audience_requires_host_instance_id() {
        assert_eq!(
            audience_host_from_instance_id("host:api.community.dev").unwrap(),
            "api.community.dev"
        );
        assert!(audience_host_from_instance_id("selfhost-1").is_err());
        assert!(audience_host_from_instance_id("host:localhost").is_err());
        assert!(audience_host_from_instance_id("host:https://api.community.dev").is_err());
    }

    #[test]
    fn account_link_audience_api_origin_must_match_registry_api_url() {
        assert!(registry_api_origin_matches(
            "https://api.community.dev",
            "https://api.community.dev/"
        ));
        assert!(registry_api_origin_matches(
            "https://api.community.dev:8443",
            "https://api.community.dev:8443"
        ));
        assert!(!registry_api_origin_matches(
            "https://api.community.dev",
            "https://attacker.dev"
        ));
        assert!(!registry_api_origin_matches(
            "https://api.community.dev",
            "http://api.community.dev"
        ));
        assert!(!registry_api_origin_matches(
            "https://api.community.dev",
            "https://api.community.dev/path"
        ));
    }

    #[test]
    fn link_scopes_are_whitelisted_and_deduped() {
        assert_eq!(
            normalize_scopes(None).unwrap(),
            vec![IDENTITY_BASIC_SCOPE.to_string()]
        );
        assert_eq!(
            normalize_scopes(Some(vec![
                "IDENTITY.BASIC".to_string(),
                "identity.basic".to_string()
            ]))
            .unwrap(),
            vec![IDENTITY_BASIC_SCOPE.to_string()]
        );
        assert!(normalize_scopes(Some(vec!["admin".to_string()])).is_err());
    }

    #[test]
    fn proof_scopes_must_be_subset_of_requested_scopes() {
        let requested = vec![IDENTITY_BASIC_SCOPE.to_string()];
        assert!(proof_scopes_match_request(
            &[IDENTITY_BASIC_SCOPE.to_string()],
            &requested
        ));
        assert!(!proof_scopes_match_request(&[], &requested));
        assert!(!proof_scopes_match_request(
            &["admin".to_string()],
            &requested
        ));
    }

    #[test]
    fn proof_jti_hashes_are_strict_opaque_sha256_hashes() {
        let hashes =
            normalize_proof_jti_hashes(vec!["A".repeat(64), "a".repeat(64), "b".repeat(64)])
                .unwrap();

        assert_eq!(hashes, vec!["a".repeat(64), "b".repeat(64)]);
        assert!(normalize_proof_jti_hashes(vec![]).is_err());
        assert!(normalize_proof_jti_hashes(vec!["g".repeat(64)]).is_err());
        assert!(normalize_proof_jti_hashes(vec!["a".repeat(63)]).is_err());
        assert!(normalize_proof_jti_hashes(vec!["a".repeat(64); 51]).is_err());
    }

    #[test]
    fn rs256_proofs_are_audience_bound() {
        let now = Utc::now().timestamp();
        let claims = AccountLinkProofClaims {
            iss: "official".to_string(),
            sub: "42".to_string(),
            aud: "selfhost-1".to_string(),
            exp: now + 300,
            iat: now,
            jti: "proof-1".to_string(),
            state_hash: "state-hash".to_string(),
            scopes: vec![IDENTITY_BASIC_SCOPE.to_string()],
            username: Some("joshy".to_string()),
            display_name: Some("Joshy".to_string()),
        };
        let token = signed_proof(TEST_PRIVATE_KEY, &claims).expect("proof signs");
        let verified = verify_proof(TEST_PUBLIC_KEY, &token, "selfhost-1").expect("proof verifies");

        assert_eq!(verified.sub, "42");
        assert_eq!(verified.aud, "selfhost-1");
        assert!(verify_proof(TEST_PUBLIC_KEY, &token, "other-selfhost").is_err());
    }
}
