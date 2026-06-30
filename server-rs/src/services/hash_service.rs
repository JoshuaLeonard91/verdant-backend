use crate::error::{AppError, AppResult};
use crate::state::AppState;

/// Dummy hash for timing-safe "user not found" path during login.
/// Valid PHC string with current params (m=65536, t=3, p=4) — verifying against it
/// takes the same time as a real hash, preventing timing-based user enumeration.
pub const DUMMY_HASH: &str = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Hash a password with local Argon2 on the blocking thread pool.
pub async fn hash_password(_state: &AppState, password: String) -> AppResult<String> {
    let hash =
        tokio::task::spawn_blocking(move || crate::services::crypto::hash_password(&password))
            .await
            .map_err(|_| {
                tracing::error!("hash_service: password hash task panicked");
                AppError::Internal
            })?
            .map_err(|_| {
                tracing::error!("hash_service: password hashing failed");
                AppError::Internal
            })?;
    Ok(hash)
}

/// Verify a password against a PHC hash with local Argon2 on the blocking thread pool.
pub async fn verify_password(_state: &AppState, hash: String, password: String) -> AppResult<bool> {
    let valid = tokio::task::spawn_blocking(move || {
        crate::services::crypto::verify_password(&hash, &password)
    })
    .await
    .map_err(|_| {
        tracing::error!("hash_service: password verify task panicked");
        AppError::Internal
    })?;
    Ok(valid)
}
