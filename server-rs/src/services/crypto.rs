use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{SaltString, rand_core::OsRng as ArgonOsRng},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{Duration, Utc};
use fred::interfaces::KeysInterface;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{AppError, AppResult};

// ─── Argon2id ───────────────────────────────────────────────────────

/// Hash a password with Argon2id (64 MiB, t=3, p=4).
pub fn hash_password(password: &str) -> AppResult<String> {
    let salt = SaltString::generate(&mut ArgonOsRng);
    let params = argon2::Params::new(65536, 3, 4, None).map_err(|_| AppError::Internal)?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|_| AppError::Internal)?;
    Ok(hash.to_string())
}

/// Verify a password against a PHC hash string.
pub fn verify_password(hash: &str, password: &str) -> bool {
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

// ─── JWT ────────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    #[serde(rename = "userId")]
    user_id: String,
    iss: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    typ: Option<String>,
    jti: String,
    exp: i64,
    iat: i64,
    /// Session ID — additive field, old JWTs without it still work.
    #[serde(skip_serializing_if = "Option::is_none")]
    sid: Option<i64>,
    #[serde(rename = "homePeerId", skip_serializing_if = "Option::is_none")]
    home_peer_id: Option<String>,
    #[serde(rename = "remoteUserId", skip_serializing_if = "Option::is_none")]
    remote_user_id: Option<String>,
    #[serde(rename = "serverIds", skip_serializing_if = "Option::is_none")]
    server_ids: Option<Vec<String>>,
}

/// Generate a 15-minute HS256 access token with an embedded session ID.
pub fn generate_access_token(
    user_id: i64,
    secret: &str,
    session_id: Option<i64>,
) -> AppResult<String> {
    generate_access_token_with_ttl(user_id, secret, session_id, Duration::minutes(15))
}

/// Generate an HS256 access token with a caller-controlled lifetime.
/// Used by the loadtest admin route to mint long-lived tokens for
/// synthetic users. The claim shape is identical to
/// `generate_access_token` so the normal auth middleware accepts it.
pub fn generate_access_token_with_ttl(
    user_id: i64,
    secret: &str,
    session_id: Option<i64>,
    ttl: Duration,
) -> AppResult<String> {
    let now = Utc::now();
    let jti = uuid::Uuid::new_v4().to_string();
    let claims = Claims {
        user_id: user_id.to_string(),
        iss: "verdant".to_string(),
        aud: None,
        typ: None,
        jti,
        iat: now.timestamp(),
        exp: (now + ttl).timestamp(),
        sid: session_id,
        home_peer_id: None,
        remote_user_id: None,
        server_ids: None,
    };
    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|_| AppError::Internal)?;
    Ok(token)
}

pub fn generate_federated_client_access_token(
    local_user_id: i64,
    secret: &str,
    audience_instance_id: &str,
    home_peer_id: &str,
    remote_user_id: &str,
    server_ids: &[i64],
    ttl: Duration,
) -> AppResult<String> {
    if local_user_id <= 0
        || !valid_token_peer_id(audience_instance_id)
        || !valid_token_peer_id(home_peer_id)
        || !valid_token_remote_user_id(remote_user_id)
        || server_ids.is_empty()
        || server_ids.len() > 64
        || server_ids.iter().any(|server_id| *server_id <= 0)
    {
        return Err(AppError::Internal);
    }
    let now = Utc::now();
    let claims = Claims {
        user_id: local_user_id.to_string(),
        iss: "verdant".to_string(),
        aud: Some(audience_instance_id.to_string()),
        typ: Some("federated_client".to_string()),
        jti: uuid::Uuid::new_v4().to_string(),
        iat: now.timestamp(),
        exp: (now + ttl).timestamp(),
        sid: None,
        home_peer_id: Some(home_peer_id.to_string()),
        remote_user_id: Some(remote_user_id.to_string()),
        server_ids: Some(server_ids.iter().map(ToString::to_string).collect()),
    };
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|_| AppError::Internal)
}

/// Decoded access token result.
pub struct VerifiedToken {
    pub user_id: i64,
    pub jti: Option<String>,
    /// Session ID (additive — None for old JWTs before this field was added).
    pub session_id: Option<i64>,
    pub kind: VerifiedTokenKind,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifiedTokenKind {
    UserSession,
    FederatedClient {
        home_peer_id: String,
        remote_user_id: String,
        server_ids: Vec<i64>,
    },
}

/// Decode an access token without checking blacklist. Returns user_id (sub).
/// Used for logout validation where we just need the user identity.
pub fn decode_access_token(token: &str, secret: &str) -> Result<DecodedToken, ()> {
    let mut validation = Validation::default();
    validation.set_issuer(&["verdant"]);

    let data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .map_err(|_| ())?;

    let sub: i64 = data.claims.user_id.parse().map_err(|_| ())?;
    Ok(DecodedToken { sub })
}

/// Minimal decoded token (no blacklist check).
pub struct DecodedToken {
    pub sub: i64,
}

/// Verify an access token. Checks signature, expiry, issuer, and blacklist.
pub async fn verify_access_token(
    token: &str,
    secret: &str,
    redis: &fred::clients::Client,
) -> AppResult<VerifiedToken> {
    verify_access_token_for_instance(token, secret, redis, None).await
}

pub async fn verify_access_token_for_instance(
    token: &str,
    secret: &str,
    redis: &fred::clients::Client,
    audience_instance_id: Option<&str>,
) -> AppResult<VerifiedToken> {
    let mut validation = Validation::default();
    validation.set_issuer(&["verdant"]);
    validation.validate_aud = false;

    let data = match decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    ) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error = %e, kind = ?e.kind(), "JWT decode failed");
            return Err(AppError::TokenInvalid);
        }
    };

    let user_id: i64 = match data.claims.user_id.parse() {
        Ok(id) => id,
        Err(_) => {
            tracing::warn!(sub = %data.claims.user_id, "JWT has unparseable user_id");
            return Err(AppError::TokenInvalid);
        }
    };
    let kind = verified_token_kind(&data.claims, audience_instance_id)?;

    // Reject tokens without a JTI (defense-in-depth: all server-generated tokens have one)
    if data.claims.jti.is_empty() {
        tracing::warn!(user_id, "JWT missing JTI");
        return Err(AppError::TokenInvalid);
    }

    // Check blacklist — fail CLOSED on any error. If Redis is unreachable,
    // reject the token rather than allowing a potentially revoked session
    // through. This prioritizes security over availability: a Redis outage
    // forces re-authentication, but prevents banned/compromised accounts
    // from retaining access.
    let key = format!("blacklist:{}", data.claims.jti);
    match redis.exists::<bool, _>(&key).await {
        Ok(true) => return Err(AppError::TokenRevoked),
        Ok(false) => {}
        Err(e) => {
            tracing::error!(error = %e, "Redis blacklist check failed — rejecting token (fail-closed)");
            return Err(AppError::TokenRevoked);
        }
    }

    Ok(VerifiedToken {
        user_id,
        jti: Some(data.claims.jti),
        session_id: data.claims.sid,
        kind,
    })
}

/// Blacklist an access token's JTI for its remaining TTL. Best-effort.
pub async fn blacklist_access_token(token: &str, secret: &str, redis: &fred::clients::Client) {
    let mut validation = Validation::default();
    validation.set_issuer(&["verdant"]);
    validation.validate_exp = false; // Allow blacklisting expired tokens

    let Ok(data) = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    ) else {
        return;
    };

    if data.claims.jti.is_empty() {
        return;
    }
    let ttl = data.claims.exp - Utc::now().timestamp();
    if ttl <= 0 {
        return;
    }

    let key = format!("blacklist:{}", data.claims.jti);
    let _: Result<(), _> = KeysInterface::set(
        redis,
        &key,
        "1",
        Some(fred::types::Expiration::EX(ttl)),
        None,
        false,
    )
    .await;
}

// ─── Token Hashing ──────────────────────────────────────────────────

/// SHA-256 hash of a token, hex-encoded.
pub fn hash_token(token: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// HMAC-SHA256 hash of a value, keyed with a secret. Hex-encoded.
/// Used for backup codes so a DB dump alone cannot reverse them.
pub fn hmac_hash(value: &str, key: &str) -> String {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(key.as_bytes()).expect("HMAC accepts any key length");
    mac.update(value.as_bytes());
    format!("{:x}", mac.finalize().into_bytes())
}

// ─── Random Tokens ──────────────────────────────────────────────────

/// Generate a cryptographically random session token (32 bytes, base64url).
pub fn generate_session_token() -> String {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("getrandom failed");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Generate a 6-digit verification code.
pub fn generate_verification_code() -> String {
    let mut buf = [0u8; 4];
    getrandom::fill(&mut buf).expect("getrandom failed");
    let num = u32::from_le_bytes(buf) % 1_000_000;
    format!("{num:06}")
}

/// Generate a cryptographically random bot API token.
/// Returns (plaintext_token, sha256_hex_hash).
/// The plaintext is shown to the user once; the hash is stored in bot_tokens.
///
/// The `vbot_` prefix enables GitHub/GitLab secret scanning to detect
/// accidentally committed tokens. The hash is computed on the full
/// prefixed string, so lookups hash the token as-is from the Authorization
/// header (after stripping the `Bot ` scheme prefix).
pub fn generate_bot_token() -> (String, String) {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("Failed to generate random bytes");

    let plaintext = format!("vbot_{}", URL_SAFE_NO_PAD.encode(bytes));
    let hash = hex::encode(Sha256::digest(plaintext.as_bytes()));

    (plaintext, hash)
}

fn verified_token_kind(
    claims: &Claims,
    audience_instance_id: Option<&str>,
) -> AppResult<VerifiedTokenKind> {
    match claims.typ.as_deref() {
        None | Some("") => {
            if claims.aud.is_some()
                || claims.home_peer_id.is_some()
                || claims.remote_user_id.is_some()
                || claims.server_ids.is_some()
            {
                return Err(AppError::TokenInvalid);
            }
            Ok(VerifiedTokenKind::UserSession)
        }
        Some("federated_client") => {
            let expected_audience = audience_instance_id.ok_or(AppError::TokenInvalid)?;
            if claims.aud.as_deref() != Some(expected_audience) || claims.sid.is_some() {
                return Err(AppError::TokenInvalid);
            }
            let home_peer_id = claims
                .home_peer_id
                .as_deref()
                .filter(|value| valid_token_peer_id(value))
                .ok_or(AppError::TokenInvalid)?
                .to_string();
            let remote_user_id = claims
                .remote_user_id
                .as_deref()
                .filter(|value| valid_token_remote_user_id(value))
                .ok_or(AppError::TokenInvalid)?
                .to_string();
            let server_ids = claims
                .server_ids
                .as_ref()
                .filter(|values| !values.is_empty() && values.len() <= 64)
                .ok_or(AppError::TokenInvalid)?
                .iter()
                .map(|value| {
                    value
                        .parse::<i64>()
                        .ok()
                        .filter(|server_id| *server_id > 0)
                        .ok_or(AppError::TokenInvalid)
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok(VerifiedTokenKind::FederatedClient {
                home_peer_id,
                remote_user_id,
                server_ids,
            })
        }
        Some(_) => Err(AppError::TokenInvalid),
    }
}

fn valid_token_peer_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}

fn valid_token_remote_user_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':'))
}
