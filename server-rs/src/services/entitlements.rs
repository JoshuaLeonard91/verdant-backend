use chrono::{DateTime, Utc};
use serde::Serialize;
use sqlx::PgPool;

use crate::config::{Config, InstanceMode, LocalCapabilities};
use crate::services::subscription::{
    FREE_MAX_UPLOAD_BYTES, FREE_MAX_VOICE_BITRATE, PREMIUM_MAX_UPLOAD_BYTES,
    PREMIUM_MAX_VOICE_BITRATE, SubscriptionInfo,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Entitlements {
    pub official_subscription_active: bool,
    pub official_subscription_tier: Option<String>,
    pub image_uploads: bool,
    pub file_sharing: bool,
    pub message_attachments: bool,
    pub voice_chat: bool,
    pub video_streaming: bool,
    pub cross_server_emoji: bool,
    pub animated_avatar: bool,
    pub animated_banner: bool,
    pub member_list_banner: bool,
    pub max_upload_bytes: u64,
    pub max_voice_bitrate: u32,
    pub official_badge: bool,
}

impl Entitlements {
    pub fn for_config(config: &Config, subscription: &SubscriptionInfo) -> Self {
        Self::for_instance(
            config.instance_mode,
            &config.local_capabilities,
            subscription,
        )
    }

    pub fn for_instance(
        mode: InstanceMode,
        local: &LocalCapabilities,
        subscription: &SubscriptionInfo,
    ) -> Self {
        if mode != InstanceMode::Official {
            return Self {
                official_subscription_active: false,
                official_subscription_tier: None,
                image_uploads: local.image_uploads,
                file_sharing: local.file_sharing,
                message_attachments: local.message_attachments,
                voice_chat: local.voice_chat,
                video_streaming: local.video_streaming,
                cross_server_emoji: local.cross_server_emoji,
                animated_avatar: local.animated_avatar,
                animated_banner: local.animated_banner,
                member_list_banner: local.member_list_banner,
                max_upload_bytes: local.max_upload_bytes,
                max_voice_bitrate: local.max_voice_bitrate,
                official_badge: false,
            };
        }

        let active = subscription.active;
        Self {
            official_subscription_active: active,
            official_subscription_tier: if active {
                subscription.tier.clone()
            } else {
                None
            },
            image_uploads: local.image_uploads,
            file_sharing: local.file_sharing,
            message_attachments: local.message_attachments,
            voice_chat: local.voice_chat,
            video_streaming: local.video_streaming,
            cross_server_emoji: active,
            animated_avatar: active,
            animated_banner: active,
            member_list_banner: active,
            max_upload_bytes: if active {
                PREMIUM_MAX_UPLOAD_BYTES
            } else {
                FREE_MAX_UPLOAD_BYTES
            },
            max_voice_bitrate: if active {
                PREMIUM_MAX_VOICE_BITRATE as u32
            } else {
                FREE_MAX_VOICE_BITRATE as u32
            },
            official_badge: active,
        }
    }
}

pub async fn current_for_user(pool: &PgPool, config: &Config, user_id: i64) -> Entitlements {
    let subscription = crate::services::subscription::get_subscription_info(pool, user_id).await;
    Entitlements::for_config(config, &subscription)
}

pub fn official_subscription_active_from_db(
    subscribed: bool,
    expires_at: Option<DateTime<Utc>>,
) -> bool {
    subscribed && expires_at.map(|exp| exp > Utc::now()).unwrap_or(false)
}

pub fn member_list_banner_visible(config: &Config, official_subscription_active: bool) -> bool {
    member_list_banner_visible_for(
        config.instance_mode,
        &config.local_capabilities,
        official_subscription_active,
    )
}

pub fn member_list_banner_visible_for(
    mode: InstanceMode,
    local: &LocalCapabilities,
    official_subscription_active: bool,
) -> bool {
    if mode == InstanceMode::Official {
        official_subscription_active
    } else {
        local.member_list_banner
    }
}

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};

    use crate::config::{InstanceMode, LocalCapabilities};
    use crate::services::subscription::{SubscriptionInfo, TIER_PREMIUM};

    fn local_capabilities() -> LocalCapabilities {
        LocalCapabilities {
            image_uploads: true,
            file_sharing: false,
            message_attachments: false,
            voice_chat: true,
            video_streaming: false,
            cross_server_emoji: false,
            animated_avatar: false,
            animated_banner: false,
            member_list_banner: false,
            max_upload_bytes: 13 * 1024 * 1024,
            max_voice_bitrate: 96_000,
        }
    }

    fn active_subscription() -> SubscriptionInfo {
        SubscriptionInfo::from_db(
            Some(TIER_PREMIUM),
            Some(Utc::now() + Duration::days(30)),
            None,
        )
    }

    #[test]
    fn standalone_ignores_active_official_subscription_and_uses_local_limits() {
        let local = LocalCapabilities {
            cross_server_emoji: false,
            max_upload_bytes: 3 * 1024 * 1024,
            ..local_capabilities()
        };

        let entitlements = super::Entitlements::for_instance(
            InstanceMode::Standalone,
            &local,
            &active_subscription(),
        );

        assert!(!entitlements.official_subscription_active);
        assert_eq!(entitlements.official_subscription_tier, None);
        assert!(!entitlements.official_badge);
        assert!(!entitlements.cross_server_emoji);
        assert_eq!(entitlements.max_upload_bytes, 3 * 1024 * 1024);
    }

    #[test]
    fn linked_and_federated_do_not_grant_official_subscription_perks() {
        for mode in [InstanceMode::Linked, InstanceMode::Federated] {
            let local = LocalCapabilities {
                animated_avatar: false,
                animated_banner: false,
                member_list_banner: false,
                cross_server_emoji: false,
                max_upload_bytes: 5 * 1024 * 1024,
                max_voice_bitrate: 72_000,
                ..local_capabilities()
            };

            let entitlements =
                super::Entitlements::for_instance(mode, &local, &active_subscription());

            assert!(!entitlements.official_subscription_active);
            assert_eq!(entitlements.official_subscription_tier, None);
            assert!(!entitlements.official_badge);
            assert!(!entitlements.animated_avatar);
            assert!(!entitlements.animated_banner);
            assert!(!entitlements.member_list_banner);
            assert!(!entitlements.cross_server_emoji);
            assert_eq!(entitlements.max_upload_bytes, 5 * 1024 * 1024);
            assert_eq!(entitlements.max_voice_bitrate, 72_000);
        }
    }

    #[test]
    fn official_mode_uses_active_official_subscription_perks() {
        let local = LocalCapabilities {
            cross_server_emoji: false,
            animated_avatar: false,
            animated_banner: false,
            member_list_banner: false,
            max_upload_bytes: 3 * 1024 * 1024,
            max_voice_bitrate: 64_000,
            ..local_capabilities()
        };

        let entitlements = super::Entitlements::for_instance(
            InstanceMode::Official,
            &local,
            &active_subscription(),
        );

        assert!(entitlements.official_subscription_active);
        assert_eq!(
            entitlements.official_subscription_tier.as_deref(),
            Some(TIER_PREMIUM)
        );
        assert!(entitlements.official_badge);
        assert!(entitlements.cross_server_emoji);
        assert!(entitlements.animated_avatar);
        assert!(entitlements.animated_banner);
        assert!(entitlements.member_list_banner);
        assert_eq!(
            entitlements.max_upload_bytes,
            crate::services::subscription::PREMIUM_MAX_UPLOAD_BYTES
        );
        assert_eq!(
            entitlements.max_voice_bitrate,
            crate::services::subscription::PREMIUM_MAX_VOICE_BITRATE as u32
        );
    }

    #[test]
    fn member_list_banner_visibility_uses_local_capability_for_self_host_modes() {
        let local = LocalCapabilities {
            member_list_banner: true,
            ..local_capabilities()
        };

        for mode in [
            InstanceMode::Standalone,
            InstanceMode::Linked,
            InstanceMode::Federated,
        ] {
            assert!(super::member_list_banner_visible_for(mode, &local, false));
        }
    }

    #[test]
    fn member_list_banner_visibility_keeps_official_subscription_gate() {
        let local = LocalCapabilities {
            member_list_banner: true,
            ..local_capabilities()
        };

        assert!(!super::member_list_banner_visible_for(
            InstanceMode::Official,
            &local,
            false
        ));
        assert!(super::member_list_banner_visible_for(
            InstanceMode::Official,
            &local,
            true
        ));
    }

    #[test]
    fn official_member_list_banner_visibility_treats_expired_subscription_as_inactive() {
        assert!(!super::official_subscription_active_from_db(
            true,
            Some(Utc::now() - Duration::days(1))
        ));
    }

    #[test]
    fn official_member_list_banner_visibility_hides_expired_raw_subscribed_user() {
        let local = LocalCapabilities {
            member_list_banner: true,
            ..local_capabilities()
        };
        let active =
            super::official_subscription_active_from_db(true, Some(Utc::now() - Duration::days(1)));

        assert!(!super::member_list_banner_visible_for(
            InstanceMode::Official,
            &local,
            active
        ));
    }
}
