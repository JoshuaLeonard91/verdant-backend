//! User row/response types and JSON conversions.

use crate::services::banner_crop::BannerCrop;
use crate::services::cdn;

/// Full user row shape used as an intermediate by handlers.
#[derive(Debug)]
pub struct UserRow {
    pub id: i64,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub avatar_url: Option<String>,
    pub status: String,
    pub status_type: String,
    pub subscribed: bool,
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub custom_status_text: Option<String>,
    pub custom_status_emoji: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub totp_secret: Option<String>,
    pub totp_enabled_at: Option<chrono::DateTime<chrono::Utc>>,
    pub banner_url: Option<String>,
    pub banner_base_color: Option<String>,
    pub banner_crop: Option<BannerCrop>,
    pub member_list_banner_url: Option<String>,
    pub member_list_banner_crop: Option<BannerCrop>,
    pub server_order: serde_json::Value,
    pub favorite_order: serde_json::Value,
    pub email_verified: bool,
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
    pub username_set: bool,
    pub preferences: serde_json::Value,
    pub subscription_tier: Option<String>,
    pub subscription_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub subscription_ring_style: Option<String>,
    pub status_auto: bool,
    pub preferred_status: String,
}

/// Safe user info for auth API responses (no password hash, secrets, or email).
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub display_name: Option<String>,
    pub avatar_url: Option<String>,
    pub banner_url: Option<String>,
    pub banner_base_color: Option<String>,
    pub banner_crop: Option<BannerCrop>,
    pub member_list_banner_url: Option<String>,
    pub member_list_banner_crop: Option<BannerCrop>,
    pub bio: Option<String>,
    pub custom_status_text: Option<String>,
    pub custom_status_emoji: Option<String>,
    pub status: String,
    pub subscribed: bool,
    pub email_verified: bool,
    pub username_set: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl From<&UserRow> for UserResponse {
    fn from(u: &UserRow) -> Self {
        Self::from_with_member_list_banner_visibility(u, false)
    }
}

impl UserResponse {
    pub fn from_with_member_list_banner_visibility(
        u: &UserRow,
        member_list_banner_visible: bool,
    ) -> Self {
        Self {
            id: u.id.to_string(),
            username: u.username.clone(),
            display_name: u.display_name.clone(),
            avatar_url: cdn::resolve(u.avatar_url.as_deref()),
            banner_url: cdn::resolve(u.banner_url.as_deref()),
            banner_base_color: empty_to_none(u.banner_base_color.as_deref()),
            banner_crop: u.banner_crop,
            member_list_banner_url: if member_list_banner_visible {
                cdn::resolve(u.member_list_banner_url.as_deref())
            } else {
                None
            },
            member_list_banner_crop: if member_list_banner_visible {
                u.member_list_banner_crop
            } else {
                None
            },
            bio: empty_to_none(u.bio.as_deref()),
            custom_status_text: empty_to_none(u.custom_status_text.as_deref()),
            custom_status_emoji: empty_to_none(u.custom_status_emoji.as_deref()),
            status: u.status_type.clone(),
            subscribed: u.subscribed,
            email_verified: u.email_verified,
            username_set: u.username_set,
            created_at: u.created_at.to_rfc3339(),
            updated_at: u.updated_at.to_rfc3339(),
        }
    }
}

/// Full user response for GET /me and PATCH /me (includes profile fields).
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FullUserResponse {
    pub id: String,
    pub username: String,
    pub avatar_url: Option<String>,
    pub banner_url: Option<String>,
    pub banner_base_color: Option<String>,
    pub banner_crop: Option<BannerCrop>,
    pub member_list_banner_url: Option<String>,
    pub member_list_banner_crop: Option<BannerCrop>,
    pub status: String,
    pub subscribed: bool,
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub custom_status_text: Option<String>,
    pub custom_status_emoji: Option<String>,
    pub email_verified: bool,
    pub username_set: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl From<&UserRow> for FullUserResponse {
    fn from(u: &UserRow) -> Self {
        Self::from_with_member_list_banner_visibility(u, false)
    }
}

impl FullUserResponse {
    pub fn from_with_member_list_banner_visibility(
        u: &UserRow,
        member_list_banner_visible: bool,
    ) -> Self {
        Self {
            id: u.id.to_string(),
            username: u.username.clone(),
            avatar_url: cdn::resolve(u.avatar_url.as_deref()),
            banner_url: cdn::resolve(u.banner_url.as_deref()),
            banner_base_color: empty_to_none(u.banner_base_color.as_deref()),
            banner_crop: u.banner_crop,
            member_list_banner_url: if member_list_banner_visible {
                cdn::resolve(u.member_list_banner_url.as_deref())
            } else {
                None
            },
            member_list_banner_crop: if member_list_banner_visible {
                u.member_list_banner_crop
            } else {
                None
            },
            status: u.status_type.clone(),
            subscribed: u.subscribed,
            display_name: u.display_name.clone(),
            bio: empty_to_none(u.bio.as_deref()),
            custom_status_text: empty_to_none(u.custom_status_text.as_deref()),
            custom_status_emoji: empty_to_none(u.custom_status_emoji.as_deref()),
            email_verified: u.email_verified,
            username_set: u.username_set,
            created_at: u.created_at.to_rfc3339(),
            updated_at: u.updated_at.to_rfc3339(),
        }
    }
}

/// Public user profile (no email, no updatedAt).
#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicUserResponse {
    pub id: String,
    pub username: String,
    pub avatar_url: Option<String>,
    pub banner_url: Option<String>,
    pub banner_base_color: Option<String>,
    pub banner_crop: Option<BannerCrop>,
    pub member_list_banner_url: Option<String>,
    pub member_list_banner_crop: Option<BannerCrop>,
    pub status: String,
    pub display_name: Option<String>,
    pub bio: Option<String>,
    pub custom_status_text: Option<String>,
    pub custom_status_emoji: Option<String>,
    pub created_at: String,
}

fn empty_to_none(value: Option<&str>) -> Option<String> {
    value.and_then(|s| {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed.to_string())
        }
    })
}
