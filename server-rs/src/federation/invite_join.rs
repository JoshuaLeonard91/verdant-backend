use serde::Serialize;
use url::Url;

use crate::state::AppState;

use super::identity::is_public_federation_host;
use super::producer::{
    FederationLocalEvent, FederationProducerError, FederationProducerSource,
    build_outbound_envelope,
};
use super::storage::{self, EventInsertResult, InsertOutboundFederationEvent};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FederatedInviteJoinError {
    #[error("invalid federated invite target")]
    InvalidTarget,
    #[error("invalid federated invite code")]
    InvalidInviteCode,
    #[error("federated invite outbox enqueue failed")]
    Storage,
    #[error("federated invite event build failed")]
    Producer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum FederatedInviteJoinStatus {
    Queued,
}

pub const FEDERATED_INVITE_CAPABILITY_PATH: &str = "/api/federation/invites/capability";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FederatedInviteJoinReport {
    pub status: FederatedInviteJoinStatus,
    pub queued_events: usize,
    pub duplicate_events: usize,
}

pub fn normalize_federated_invite_target_origin(
    target_peer_id: &str,
    raw_origin: &str,
) -> Result<String, FederatedInviteJoinError> {
    let parsed =
        Url::parse(raw_origin.trim()).map_err(|_| FederatedInviteJoinError::InvalidTarget)?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.path() != "/"
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(FederatedInviteJoinError::InvalidTarget);
    }
    let host = parsed
        .host_str()
        .ok_or(FederatedInviteJoinError::InvalidTarget)?;
    if !peer_identity_allows_origin_host(target_peer_id, host) {
        return Err(FederatedInviteJoinError::InvalidTarget);
    }
    let scheme_allowed = match parsed.scheme() {
        "https" => is_public_federation_host(host),
        "http" => is_loopback_host(host),
        _ => false,
    };
    if !scheme_allowed {
        return Err(FederatedInviteJoinError::InvalidTarget);
    }

    let mut origin = format!("{}://{}", parsed.scheme(), host.to_ascii_lowercase());
    if let Some(port) = parsed.port() {
        origin.push(':');
        origin.push_str(&port.to_string());
    }
    Ok(origin)
}

pub fn federated_invite_code_hash(code: &str) -> String {
    crate::services::pg::server_invites::code_hash(code)
}

pub fn build_federated_invite_join_events(
    user_id: i64,
    server_id: i64,
    invite_code: &str,
    username: Option<String>,
    display_name: Option<String>,
    avatar_url: Option<String>,
) -> Result<Vec<FederationLocalEvent>, FederatedInviteJoinError> {
    if !valid_invite_code(invite_code) {
        return Err(FederatedInviteJoinError::InvalidInviteCode);
    }
    Ok(vec![
        FederationLocalEvent::PrincipalUpsert {
            user_id,
            username,
            display_name,
            avatar_url,
        },
        FederationLocalEvent::MembershipJoin {
            server_id,
            user_id,
            invite_code: None,
            invite_code_hash: Some(federated_invite_code_hash(invite_code)),
        },
    ])
}

pub async fn enqueue_federated_invite_join(
    state: &AppState,
    target_peer_id: &str,
    server_id: i64,
    user_id: i64,
    invite_code: &str,
    username: Option<String>,
    display_name: Option<String>,
    avatar_url: Option<String>,
    now_ms: i64,
) -> Result<FederatedInviteJoinReport, FederatedInviteJoinError> {
    let events = build_federated_invite_join_events(
        user_id,
        server_id,
        invite_code,
        username,
        display_name,
        avatar_url,
    )?;
    let mut report = FederatedInviteJoinReport {
        status: FederatedInviteJoinStatus::Queued,
        queued_events: 0,
        duplicate_events: 0,
    };

    for event in events {
        let produced = build_outbound_envelope(
            &state.config.instance_id,
            target_peer_id,
            &event,
            FederationProducerSource::Local,
            now_ms,
        )
        .map_err(map_producer_error)?;

        let insert = storage::insert_outbound_event(
            &state.pg,
            InsertOutboundFederationEvent {
                id: state.snowflake.next_id(),
                destination_peer_id: &produced.destination_peer_id,
                event_id: &produced.event_id,
                event_kind: produced.kind,
                payload_hash: &produced.payload_hash,
                event_body_json: &produced.body_json,
                now_ms,
            },
        )
        .await
        .map_err(|error| {
            tracing::warn!(
                error = %error,
                destination_peer_id = %target_peer_id,
                event_id = %produced.event_id,
                event_kind = %produced.kind.as_str(),
                "Federated invite join outbox insert failed"
            );
            FederatedInviteJoinError::Storage
        })?;

        match insert {
            EventInsertResult::Inserted => report.queued_events += 1,
            EventInsertResult::Duplicate => report.duplicate_events += 1,
        }
    }

    Ok(report)
}

fn map_producer_error(error: FederationProducerError) -> FederatedInviteJoinError {
    tracing::warn!(error = %error, "Federated invite join event build failed");
    FederatedInviteJoinError::Producer
}

fn valid_invite_code(value: &str) -> bool {
    !value.is_empty() && value.len() <= 64 && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn peer_identity_allows_origin_host(peer_id: &str, origin_host: &str) -> bool {
    let Some(peer_host) = peer_id.strip_prefix("host:") else {
        return !peer_id.trim().is_empty();
    };
    let peer_host = peer_host.trim_end_matches('.').to_ascii_lowercase();
    let origin_host = origin_host.trim_end_matches('.').to_ascii_lowercase();
    !peer_host.is_empty()
        && (origin_host == peer_host || origin_host.ends_with(&format!(".{peer_host}")))
}

fn is_loopback_host(host: &str) -> bool {
    let host = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_ascii_lowercase();
    matches!(host.as_str(), "localhost" | "127.0.0.1" | "::1")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::federation::producer::FederationLocalEvent;

    #[test]
    fn federated_invite_join_events_do_not_retain_raw_invite_code() {
        let events = build_federated_invite_join_events(
            10,
            20,
            "InviteABC123",
            Some("remote-user".to_string()),
            None,
            None,
        )
        .expect("valid invite should build events");

        let join = events
            .iter()
            .find_map(|event| match event {
                FederationLocalEvent::MembershipJoin {
                    invite_code,
                    invite_code_hash,
                    ..
                } => Some((invite_code, invite_code_hash)),
                _ => None,
            })
            .expect("membership join event should be produced");

        assert_eq!(join.0, &None);
        let expected_hash = federated_invite_code_hash("InviteABC123");
        assert_eq!(join.1.as_deref(), Some(expected_hash.as_str()));
        assert_ne!(join.1.as_deref(), Some("InviteABC123"));
    }
}
