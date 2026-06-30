use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use base64::Engine;
use totp_rs::{Algorithm, Secret, TOTP};

/// Security invariant: raw TOTP secrets are transient. Persist encrypted
/// secrets only; backup codes are hashed by the handler before storage.
/// Derive the AES-256-GCM key from the hex-encoded encryption key.
/// The key is used directly (parsed from hex), matching the Bun server's approach.
fn derive_key(hex_key: &str) -> Result<Key<Aes256Gcm>, String> {
    let key_bytes = hex::decode(hex_key).map_err(|e| format!("Invalid hex key: {e}"))?;
    if key_bytes.len() != 32 {
        return Err(format!("Key must be 32 bytes, got {}", key_bytes.len()));
    }
    Ok(*Key::<Aes256Gcm>::from_slice(&key_bytes))
}

/// Encrypt a TOTP secret with AES-256-GCM.
/// Format: base64(iv[12] || ciphertext || authTag[16])
/// Compatible with the Bun server's `encryptTotpSecret`.
pub fn encrypt_secret(secret: &str, hex_key: &str) -> Result<String, String> {
    let key = derive_key(hex_key)?;
    let cipher = Aes256Gcm::new(&key);

    let mut nonce_bytes = [0u8; 12];
    getrandom::fill(&mut nonce_bytes).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    // aes_gcm appends the 16-byte auth tag to the ciphertext
    let ciphertext_with_tag = cipher
        .encrypt(nonce, secret.as_bytes())
        .map_err(|e| e.to_string())?;

    // Combine: iv || ciphertext || authTag (same as Bun's format)
    let mut combined = Vec::with_capacity(12 + ciphertext_with_tag.len());
    combined.extend_from_slice(&nonce_bytes);
    combined.extend_from_slice(&ciphertext_with_tag);

    let engine = base64::engine::general_purpose::STANDARD;
    Ok(engine.encode(&combined))
}

/// Decrypt a TOTP secret.
/// Handles the Bun server's format: base64(iv[12] || ciphertext || authTag[16])
pub fn decrypt_secret(encrypted: &str, hex_key: &str) -> Result<String, String> {
    let key = derive_key(hex_key)?;
    let cipher = Aes256Gcm::new(&key);

    let engine = base64::engine::general_purpose::STANDARD;
    let combined = engine
        .decode(encrypted)
        .map_err(|e| format!("Base64 decode failed: {e}"))?;

    // Minimum: 12 (IV) + 1 (ciphertext) + 16 (auth tag) = 29 bytes
    if combined.len() < 29 {
        return Err("Encrypted data too short".into());
    }

    let nonce_bytes = &combined[..12];
    // aes_gcm expects ciphertext || authTag concatenated
    let ciphertext_with_tag = &combined[12..];

    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext_with_tag)
        .map_err(|_| "Decryption failed (wrong key or corrupted data)".to_string())?;

    String::from_utf8(plaintext).map_err(|e| e.to_string())
}

/// Generate a new TOTP secret (base32-encoded).
pub fn generate_secret() -> String {
    let secret = Secret::generate_secret();
    secret.to_encoded().to_string()
}

/// Build a TOTP instance from a base32-encoded secret.
pub fn build_totp(secret_b32: &str, username: &str) -> Result<TOTP, String> {
    let secret = Secret::Encoded(secret_b32.to_string())
        .to_bytes()
        .map_err(|e| e.to_string())?;

    TOTP::new(
        Algorithm::SHA1,
        6,
        1,
        30,
        secret,
        Some("Verdant".to_string()),
        username.to_string(),
    )
    .map_err(|e| e.to_string())
}

/// Verify a TOTP code against a secret.
pub fn verify_code(secret_b32: &str, code: &str, username: &str) -> Result<bool, String> {
    let totp = build_totp(secret_b32, username)?;
    Ok(totp.check_current(code).unwrap_or(false))
}

/// Generate a QR code as a data URL (PNG base64).
pub fn generate_qr_data_url(secret_b32: &str, username: &str) -> Result<String, String> {
    let totp = build_totp(secret_b32, username)?;
    totp.get_qr_base64().map_err(|e| e.to_string())
}

/// Generate backup codes (8 codes, 8 chars each).
pub fn generate_backup_codes() -> Vec<String> {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let mut codes = Vec::with_capacity(8);
    for _ in 0..8 {
        let mut bytes = [0u8; 8];
        getrandom::fill(&mut bytes).expect("getrandom failed");
        let code: String = bytes
            .iter()
            .map(|b| CHARS[(*b as usize) % CHARS.len()] as char)
            .collect();
        codes.push(code);
    }
    codes
}
