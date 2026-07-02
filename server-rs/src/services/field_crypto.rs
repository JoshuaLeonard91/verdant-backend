use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

const AEAD_LABEL: &[u8] = b"verdant:field-encryption:v1:aead";
const BLIND_INDEX_LABEL: &[u8] = b"verdant:field-encryption:v1:blind-index";
const BLIND_INDEX_VALUE_LABEL: &[u8] = b"verdant:blind-index:value:v1";
const AAD_LABEL: &[u8] = b"verdant:field-aad:v1";

#[derive(Debug, thiserror::Error)]
pub enum FieldCryptoError {
    #[error("field encryption key must be a 64-character hex-encoded 32-byte value")]
    InvalidKey,
    #[error("field encryption key version must be positive")]
    InvalidKeyVersion,
    #[error("could not generate field encryption nonce")]
    Random,
    #[error("field encryption failed")]
    Encrypt,
    #[error("field decryption failed")]
    Decrypt,
}

#[derive(Debug, Clone)]
pub struct FieldEncryptionKeyring {
    key_version: i16,
    aead_key: [u8; 32],
    blind_index_key: [u8; 32],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldAad {
    table: String,
    column: String,
    row_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncryptedField {
    key_version: i16,
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl FieldEncryptionKeyring {
    pub fn from_hex_secret(hex_secret: &str, key_version: i16) -> Result<Self, FieldCryptoError> {
        if key_version <= 0 {
            return Err(FieldCryptoError::InvalidKeyVersion);
        }
        let secret = parse_hex_secret(hex_secret)?;
        Ok(Self {
            key_version,
            aead_key: derive_key(&secret, AEAD_LABEL),
            blind_index_key: derive_key(&secret, BLIND_INDEX_LABEL),
        })
    }

    pub fn encrypt_bytes(
        &self,
        plaintext: &[u8],
        aad: &FieldAad,
    ) -> Result<EncryptedField, FieldCryptoError> {
        let mut nonce = [0u8; 12];
        getrandom::fill(&mut nonce).map_err(|_| FieldCryptoError::Random)?;
        let cipher =
            Aes256Gcm::new_from_slice(&self.aead_key).map_err(|_| FieldCryptoError::InvalidKey)?;
        let aad_bytes = aad.to_bytes(self.key_version);
        let ciphertext = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: &aad_bytes,
                },
            )
            .map_err(|_| FieldCryptoError::Encrypt)?;
        Ok(EncryptedField {
            key_version: self.key_version,
            nonce,
            ciphertext,
        })
    }

    pub fn decrypt_bytes(
        &self,
        field: &EncryptedField,
        aad: &FieldAad,
    ) -> Result<Vec<u8>, FieldCryptoError> {
        if field.key_version != self.key_version {
            return Err(FieldCryptoError::Decrypt);
        }
        let cipher =
            Aes256Gcm::new_from_slice(&self.aead_key).map_err(|_| FieldCryptoError::InvalidKey)?;
        let aad_bytes = aad.to_bytes(field.key_version);
        cipher
            .decrypt(
                Nonce::from_slice(&field.nonce),
                Payload {
                    msg: &field.ciphertext,
                    aad: &aad_bytes,
                },
            )
            .map_err(|_| FieldCryptoError::Decrypt)
    }

    pub fn blind_index_hex(&self, normalized_value: &str) -> String {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.blind_index_key)
            .expect("HMAC accepts any key length");
        mac.update(BLIND_INDEX_VALUE_LABEL);
        mac.update(&[0]);
        mac.update(normalized_value.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    pub fn blind_index_for_field_hex(
        &self,
        table: &str,
        column: &str,
        normalized_value: &str,
    ) -> String {
        let mut mac = <HmacSha256 as Mac>::new_from_slice(&self.blind_index_key)
            .expect("HMAC accepts any key length");
        mac.update(BLIND_INDEX_VALUE_LABEL);
        push_component(&mut mac, table.as_bytes());
        push_component(&mut mac, column.as_bytes());
        push_component(&mut mac, normalized_value.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }
}

impl FieldAad {
    pub fn new(table: &str, column: &str, row_id: impl ToString) -> Self {
        Self {
            table: table.to_string(),
            column: column.to_string(),
            row_id: row_id.to_string(),
        }
    }

    fn to_bytes(&self, key_version: i16) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(
            AAD_LABEL.len() + self.table.len() + self.column.len() + self.row_id.len() + 24,
        );
        bytes.extend_from_slice(AAD_LABEL);
        bytes.extend_from_slice(&key_version.to_be_bytes());
        append_component(&mut bytes, self.table.as_bytes());
        append_component(&mut bytes, self.column.as_bytes());
        append_component(&mut bytes, self.row_id.as_bytes());
        bytes
    }
}

impl EncryptedField {
    pub fn from_parts(
        key_version: i16,
        nonce: [u8; 12],
        ciphertext: Vec<u8>,
    ) -> Result<Self, FieldCryptoError> {
        if key_version <= 0 {
            return Err(FieldCryptoError::InvalidKeyVersion);
        }
        Ok(Self {
            key_version,
            nonce,
            ciphertext,
        })
    }

    pub fn key_version(&self) -> i16 {
        self.key_version
    }

    pub fn nonce(&self) -> &[u8; 12] {
        &self.nonce
    }

    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

fn parse_hex_secret(hex_secret: &str) -> Result<[u8; 32], FieldCryptoError> {
    let value = hex_secret.trim();
    if value.len() != 64 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(FieldCryptoError::InvalidKey);
    }
    let decoded = hex::decode(value).map_err(|_| FieldCryptoError::InvalidKey)?;
    decoded.try_into().map_err(|_| FieldCryptoError::InvalidKey)
}

fn derive_key(root_secret: &[u8; 32], label: &[u8]) -> [u8; 32] {
    let mut mac =
        <HmacSha256 as Mac>::new_from_slice(root_secret).expect("HMAC accepts any key length");
    mac.update(label);
    let bytes = mac.finalize().into_bytes();
    let mut output = [0u8; 32];
    output.copy_from_slice(&bytes);
    output
}

fn append_component(output: &mut Vec<u8>, value: &[u8]) {
    let length = u32::try_from(value.len()).expect("field encryption AAD component too large");
    output.extend_from_slice(&length.to_be_bytes());
    output.extend_from_slice(value);
}

fn push_component(mac: &mut HmacSha256, value: &[u8]) {
    let length =
        u32::try_from(value.len()).expect("field encryption blind index component too large");
    mac.update(&length.to_be_bytes());
    mac.update(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_A: &str = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const KEY_B: &str = "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

    #[test]
    fn encrypt_decrypt_round_trip_uses_associated_data() {
        let keyring = FieldEncryptionKeyring::from_hex_secret(KEY_A, 3).expect("valid key");
        let aad = FieldAad::new("users", "email", 42);

        let encrypted = keyring
            .encrypt_bytes(b"josh@example.com", &aad)
            .expect("encrypt");
        let decrypted = keyring.decrypt_bytes(&encrypted, &aad).expect("decrypt");

        assert_eq!(encrypted.key_version(), 3);
        assert_eq!(decrypted, b"josh@example.com");
    }

    #[test]
    fn random_nonces_make_same_plaintext_ciphertexts_different() {
        let keyring = FieldEncryptionKeyring::from_hex_secret(KEY_A, 1).expect("valid key");
        let aad = FieldAad::new("users", "email", 42);

        let first = keyring.encrypt_bytes(b"same", &aad).expect("encrypt");
        let second = keyring.encrypt_bytes(b"same", &aad).expect("encrypt");

        assert_ne!(first.nonce(), second.nonce());
        assert_ne!(first.ciphertext(), second.ciphertext());
    }

    #[test]
    fn wrong_associated_data_fails_decryption() {
        let keyring = FieldEncryptionKeyring::from_hex_secret(KEY_A, 1).expect("valid key");
        let encrypted = keyring
            .encrypt_bytes(b"secret", &FieldAad::new("users", "email", 42))
            .expect("encrypt");

        assert!(
            keyring
                .decrypt_bytes(&encrypted, &FieldAad::new("users", "email", 43))
                .is_err()
        );
    }

    #[test]
    fn wrong_key_fails_decryption() {
        let keyring = FieldEncryptionKeyring::from_hex_secret(KEY_A, 1).expect("valid key");
        let wrong_keyring = FieldEncryptionKeyring::from_hex_secret(KEY_B, 1).expect("valid key");
        let aad = FieldAad::new("users", "email", 42);
        let encrypted = keyring.encrypt_bytes(b"secret", &aad).expect("encrypt");

        assert!(wrong_keyring.decrypt_bytes(&encrypted, &aad).is_err());
    }

    #[test]
    fn blind_index_is_stable_and_keyed() {
        let keyring = FieldEncryptionKeyring::from_hex_secret(KEY_A, 1).expect("valid key");
        let other_keyring = FieldEncryptionKeyring::from_hex_secret(KEY_B, 1).expect("valid key");

        let first = keyring.blind_index_hex("josh@example.com");
        let second = keyring.blind_index_hex("josh@example.com");
        let other = other_keyring.blind_index_hex("josh@example.com");

        assert_eq!(first, second);
        assert_ne!(first, other);
        assert_eq!(first.len(), 64);
    }

    #[test]
    fn blind_index_for_field_is_field_separated() {
        let keyring = FieldEncryptionKeyring::from_hex_secret(KEY_A, 1).expect("valid key");

        let email_index = keyring.blind_index_for_field_hex("users", "email", "same-value");
        let username_index = keyring.blind_index_for_field_hex("users", "username", "same-value");

        assert_ne!(email_index, username_index);
    }
}
