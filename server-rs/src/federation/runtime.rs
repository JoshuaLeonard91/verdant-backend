use serde_json::Value;

use super::{
    identity::{RemotePrincipalMetadata, RemotePrincipalProjectionError},
    invite_join::federated_invite_code_hash,
    ownership::runtime_propagation_allowed,
    protocol::{FederationEventKind, ParsedFederationEnvelope},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationRuntimeCommand {
    AuditOnly,
    UpsertRemotePrincipal {
        home_peer_id: String,
        remote_user_id: String,
        username: Option<String>,
        display_name: Option<String>,
        avatar_url: Option<String>,
    },
    MembershipJoin {
        home_peer_id: String,
        remote_user_id: String,
        server_id: i64,
        invite_code: Option<String>,
        invite_code_hash: Option<String>,
    },
    MembershipLeave {
        home_peer_id: String,
        remote_user_id: String,
        server_id: i64,
    },
    MembershipRemove {
        home_peer_id: String,
        remote_user_id: String,
        server_id: i64,
        target_user_id: i64,
        reason: Option<String>,
    },
    MembershipBan {
        home_peer_id: String,
        remote_user_id: String,
        server_id: i64,
        target_user_id: i64,
        reason: Option<String>,
    },
    MembershipUnban {
        home_peer_id: String,
        remote_user_id: String,
        server_id: i64,
        target_user_id: i64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FederationRuntimeError {
    #[error("federation event kind does not have a runtime application path")]
    UnsupportedEventKind,
    #[error("federation event payload is invalid for runtime application")]
    InvalidPayload,
}

pub fn command_from_envelope(
    envelope: &ParsedFederationEnvelope,
) -> Result<FederationRuntimeCommand, FederationRuntimeError> {
    if !runtime_propagation_allowed(envelope.kind) {
        return Err(FederationRuntimeError::UnsupportedEventKind);
    }

    match envelope.kind {
        FederationEventKind::InvitePreview => Ok(FederationRuntimeCommand::AuditOnly),
        FederationEventKind::PrincipalUpsert => remote_principal_command(envelope),
        FederationEventKind::MembershipJoin => membership_join_command(envelope),
        FederationEventKind::MembershipLeave => membership_leave_command(envelope),
        FederationEventKind::MembershipRemove => {
            membership_moderation_command(envelope, MembershipModerationOp::Remove)
        }
        FederationEventKind::MembershipBan => {
            membership_moderation_command(envelope, MembershipModerationOp::Ban)
        }
        FederationEventKind::MembershipUnban => {
            membership_moderation_command(envelope, MembershipModerationOp::Unban)
        }
        _ => Err(FederationRuntimeError::UnsupportedEventKind),
    }
}

fn remote_principal_command(
    envelope: &ParsedFederationEnvelope,
) -> Result<FederationRuntimeCommand, FederationRuntimeError> {
    let remote_user_id = required_str(&envelope.payload, "remoteUserId")?;
    let metadata = RemotePrincipalMetadata::new(
        optional_str(&envelope.payload, "username"),
        optional_str(&envelope.payload, "displayName"),
        optional_str(&envelope.payload, "avatarUrl"),
    )
    .map_err(runtime_metadata_error)?;

    Ok(FederationRuntimeCommand::UpsertRemotePrincipal {
        home_peer_id: envelope.source_peer_id.clone(),
        remote_user_id: remote_user_id.to_string(),
        username: metadata.username,
        display_name: metadata.display_name,
        avatar_url: metadata.avatar_url,
    })
}

fn membership_join_command(
    envelope: &ParsedFederationEnvelope,
) -> Result<FederationRuntimeCommand, FederationRuntimeError> {
    let remote_user_id = required_str(&envelope.payload, "remoteUserId")?;
    let server_id = required_local_id(&envelope.payload, "serverId")?;
    let invite_code = optional_str(&envelope.payload, "inviteCode")
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let invite_code_hash = optional_str(&envelope.payload, "inviteCodeHash")
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .or_else(|| invite_code.as_deref().map(federated_invite_code_hash));
    if invite_code.is_none() && invite_code_hash.is_none() {
        return Err(FederationRuntimeError::InvalidPayload);
    }

    Ok(FederationRuntimeCommand::MembershipJoin {
        home_peer_id: envelope.source_peer_id.clone(),
        remote_user_id: remote_user_id.to_string(),
        server_id,
        invite_code,
        invite_code_hash,
    })
}

fn membership_leave_command(
    envelope: &ParsedFederationEnvelope,
) -> Result<FederationRuntimeCommand, FederationRuntimeError> {
    let remote_user_id = required_str(&envelope.payload, "remoteUserId")?;
    let server_id = required_local_id(&envelope.payload, "serverId")?;

    Ok(FederationRuntimeCommand::MembershipLeave {
        home_peer_id: envelope.source_peer_id.clone(),
        remote_user_id: remote_user_id.to_string(),
        server_id,
    })
}

#[derive(Debug, Clone, Copy)]
enum MembershipModerationOp {
    Remove,
    Ban,
    Unban,
}

fn membership_moderation_command(
    envelope: &ParsedFederationEnvelope,
    op: MembershipModerationOp,
) -> Result<FederationRuntimeCommand, FederationRuntimeError> {
    let remote_user_id = required_str(&envelope.payload, "remoteUserId")?;
    let server_id = required_local_id(&envelope.payload, "serverId")?;
    let target_user_id = required_local_id(&envelope.payload, "targetUserId")?;
    let reason = optional_str(&envelope.payload, "reason")
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let home_peer_id = envelope.source_peer_id.clone();
    let remote_user_id = remote_user_id.to_string();

    Ok(match op {
        MembershipModerationOp::Remove => FederationRuntimeCommand::MembershipRemove {
            home_peer_id,
            remote_user_id,
            server_id,
            target_user_id,
            reason,
        },
        MembershipModerationOp::Ban => FederationRuntimeCommand::MembershipBan {
            home_peer_id,
            remote_user_id,
            server_id,
            target_user_id,
            reason,
        },
        MembershipModerationOp::Unban => FederationRuntimeCommand::MembershipUnban {
            home_peer_id,
            remote_user_id,
            server_id,
            target_user_id,
        },
    })
}

fn required_str<'a>(payload: &'a Value, key: &str) -> Result<&'a str, FederationRuntimeError> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
        .ok_or(FederationRuntimeError::InvalidPayload)
}

fn optional_str<'a>(payload: &'a Value, key: &str) -> Option<&'a str> {
    payload.get(key).and_then(Value::as_str)
}

fn required_local_id(payload: &Value, key: &str) -> Result<i64, FederationRuntimeError> {
    required_str(payload, key)?
        .parse::<i64>()
        .ok()
        .filter(|id| *id > 0)
        .ok_or(FederationRuntimeError::InvalidPayload)
}

fn runtime_metadata_error(error: RemotePrincipalProjectionError) -> FederationRuntimeError {
    match error {
        RemotePrincipalProjectionError::InvalidIdentity
        | RemotePrincipalProjectionError::InvalidMetadata => FederationRuntimeError::InvalidPayload,
    }
}
