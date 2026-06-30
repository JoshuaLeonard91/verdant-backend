use sha2::{Digest, Sha256};

use super::auth::VerifiedFederationRequest;
use super::ownership::runtime_propagation_allowed;
use super::protocol::{FederationEventKind, ParsedFederationEnvelope};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FederationIngressDecision {
    pub source_peer_id: String,
    pub destination_peer_id: String,
    pub remote_event_id: String,
    pub event_kind: FederationEventKind,
    pub payload_hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FederationIngressError {
    #[error("federation envelope source does not match verified signature source")]
    SourceMismatch,
    #[error("federation envelope destination does not match verified signature destination")]
    DestinationMismatch,
    #[error("federation envelope event kind is not accepted by this ingress")]
    UnsupportedEventKind,
    #[error("federation envelope payload is invalid")]
    InvalidPayload,
}

pub fn validate_ingress_envelope(
    verified: &VerifiedFederationRequest,
    envelope: &ParsedFederationEnvelope,
) -> Result<FederationIngressDecision, FederationIngressError> {
    if envelope.source_peer_id != verified.source_peer_id {
        return Err(FederationIngressError::SourceMismatch);
    }
    if envelope.destination_peer_id != verified.destination_peer_id {
        return Err(FederationIngressError::DestinationMismatch);
    }
    if !runtime_propagation_allowed(envelope.kind) {
        return Err(FederationIngressError::UnsupportedEventKind);
    }
    if !envelope.payload.is_object() {
        return Err(FederationIngressError::InvalidPayload);
    }

    Ok(FederationIngressDecision {
        source_peer_id: envelope.source_peer_id.clone(),
        destination_peer_id: envelope.destination_peer_id.clone(),
        remote_event_id: envelope.event_id.clone(),
        event_kind: envelope.kind,
        payload_hash: payload_hash(&envelope.payload)?,
    })
}

fn payload_hash(payload: &serde_json::Value) -> Result<String, FederationIngressError> {
    let bytes = serde_json::to_vec(payload).map_err(|_| FederationIngressError::InvalidPayload)?;
    let digest = Sha256::digest(bytes);
    Ok(hex::encode(digest))
}
