//! Stripe webhook signature helpers.

use hmac::{Hmac, Mac};
use sha2::Sha256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StripeSignatureError {
    MissingHeader,
    InvalidHeader,
    TimestampOutsideTolerance,
    SignatureMismatch,
}

pub fn verify_signature(
    payload: &[u8],
    signature_header: &str,
    webhook_secret: &str,
    now_secs: i64,
    tolerance_secs: i64,
) -> Result<(), StripeSignatureError> {
    if signature_header.trim().is_empty() {
        return Err(StripeSignatureError::MissingHeader);
    }

    let mut timestamp: Option<i64> = None;
    let mut signatures: Vec<&str> = Vec::new();
    for part in signature_header.split(',') {
        let Some((key, value)) = part.split_once('=') else {
            return Err(StripeSignatureError::InvalidHeader);
        };
        match key.trim() {
            "t" => {
                timestamp = value.trim().parse::<i64>().ok();
            }
            "v1" => signatures.push(value.trim()),
            _ => {}
        }
    }

    let timestamp = timestamp.ok_or(StripeSignatureError::InvalidHeader)?;
    if signatures.is_empty() {
        return Err(StripeSignatureError::InvalidHeader);
    }

    if (now_secs - timestamp).abs() > tolerance_secs {
        return Err(StripeSignatureError::TimestampOutsideTolerance);
    }

    for sig in signatures {
        let Ok(provided) = hex::decode(sig) else {
            continue;
        };
        let mut mac = Hmac::<Sha256>::new_from_slice(webhook_secret.as_bytes())
            .map_err(|_| StripeSignatureError::InvalidHeader)?;
        mac.update(format!("{timestamp}.").as_bytes());
        mac.update(payload);
        if mac.verify_slice(&provided).is_ok() {
            return Ok(());
        }
    }

    Err(StripeSignatureError::SignatureMismatch)
}

#[cfg(test)]
mod tests {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    use super::*;

    fn signed_header(payload: &[u8], secret: &str, timestamp: i64) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(format!("{timestamp}.").as_bytes());
        mac.update(payload);
        let sig = hex::encode(mac.finalize().into_bytes());
        format!("t={timestamp},v1={sig}")
    }

    #[test]
    fn accepts_valid_stripe_signature() {
        let payload = br#"{"id":"evt_123","type":"checkout.session.completed"}"#;
        let secret = "whsec_test_secret";
        let header = signed_header(payload, secret, 1_000);

        assert_eq!(
            verify_signature(payload, &header, secret, 1_100, 300),
            Ok(())
        );
    }

    #[test]
    fn rejects_modified_payload_and_old_timestamp() {
        let payload = br#"{"id":"evt_123","type":"checkout.session.completed"}"#;
        let secret = "whsec_test_secret";
        let header = signed_header(payload, secret, 1_000);

        assert_eq!(
            verify_signature(
                br#"{"id":"evt_123","type":"customer.subscription.deleted"}"#,
                &header,
                secret,
                1_100,
                300
            ),
            Err(StripeSignatureError::SignatureMismatch),
        );
        assert_eq!(
            verify_signature(payload, &header, secret, 1_500, 300),
            Err(StripeSignatureError::TimestampOutsideTolerance),
        );
    }
}
