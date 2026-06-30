use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Sign an outgoing request with HMAC-SHA256.
///
/// Returns `(signature_hex, timestamp_str, nonce_hex)`.
///
/// The HMAC payload is: `{method}\n{path}\n{timestamp}\n{nonce}\n{body}`.
pub fn sign_request(
    secret: &str,
    method: &str,
    path: &str,
    body: &[u8],
) -> (String, String, String) {
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock before epoch")
        .as_secs()
        .to_string();

    let mut nonce_bytes = [0u8; 16];
    getrandom::fill(&mut nonce_bytes).expect("getrandom failed");
    let nonce = hex::encode(nonce_bytes);

    let payload = format!(
        "{method}\n{path}\n{timestamp}\n{nonce}\n{}",
        std::str::from_utf8(body).unwrap_or("")
    );

    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key length");
    mac.update(payload.as_bytes());
    let signature = hex::encode(mac.finalize().into_bytes());

    (signature, timestamp, nonce)
}
