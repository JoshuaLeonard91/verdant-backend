use super::protocol::FederationEventKind;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FederationRuntimePropagationScope {
    MetadataHandshake,
    MembershipHandshake,
    CrossBackendRuntimePersistence,
    EphemeralRuntimeSignal,
}

pub fn runtime_propagation_scope(kind: FederationEventKind) -> FederationRuntimePropagationScope {
    match kind {
        FederationEventKind::InvitePreview | FederationEventKind::PrincipalUpsert => {
            FederationRuntimePropagationScope::MetadataHandshake
        }
        FederationEventKind::MembershipJoin
        | FederationEventKind::MembershipLeave
        | FederationEventKind::MembershipRemove
        | FederationEventKind::MembershipBan
        | FederationEventKind::MembershipUnban => {
            FederationRuntimePropagationScope::MembershipHandshake
        }
        FederationEventKind::PresenceUpdate | FederationEventKind::TypingStart => {
            FederationRuntimePropagationScope::EphemeralRuntimeSignal
        }
        FederationEventKind::ReadStateUpdate
        | FederationEventKind::ReactionAdd
        | FederationEventKind::ReactionRemove
        | FederationEventKind::RelationshipRequest
        | FederationEventKind::RelationshipAccept
        | FederationEventKind::RelationshipRemove
        | FederationEventKind::RelationshipBlock
        | FederationEventKind::MessageCreate
        | FederationEventKind::MessageUpdate
        | FederationEventKind::MessageDelete
        | FederationEventKind::MessagePin
        | FederationEventKind::MessageUnpin
        | FederationEventKind::DmCreate
        | FederationEventKind::DmGroupCreate
        | FederationEventKind::RoleCreate
        | FederationEventKind::RoleUpdate
        | FederationEventKind::RoleDelete
        | FederationEventKind::RoleReorder
        | FederationEventKind::CategoryCreate
        | FederationEventKind::CategoryUpdate
        | FederationEventKind::CategoryDelete
        | FederationEventKind::ChannelCreate
        | FederationEventKind::ChannelUpdate
        | FederationEventKind::ChannelDelete
        | FederationEventKind::ChannelReorder
        | FederationEventKind::ChannelOverrideSet
        | FederationEventKind::ChannelOverrideDelete
        | FederationEventKind::MemberRoleAssign
        | FederationEventKind::MemberRoleRemove
        | FederationEventKind::EmojiRename
        | FederationEventKind::EmojiDelete => {
            FederationRuntimePropagationScope::CrossBackendRuntimePersistence
        }
    }
}

pub fn runtime_propagation_allowed(kind: FederationEventKind) -> bool {
    match runtime_propagation_scope(kind) {
        FederationRuntimePropagationScope::MetadataHandshake
        | FederationRuntimePropagationScope::MembershipHandshake => true,
        FederationRuntimePropagationScope::CrossBackendRuntimePersistence
        | FederationRuntimePropagationScope::EphemeralRuntimeSignal => false,
    }
}
