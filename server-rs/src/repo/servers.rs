//! Server row/response types.

use crate::services::banner_crop::BannerCrop;
use crate::services::cdn;

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerRow {
    pub id: i64,
    pub name: String,
    pub icon_url: Option<String>,
    pub owner_id: i64,
    pub voice_bitrate: i32,
    pub welcome_channel_id: Option<i64>,
    pub announce_channel_id: Option<i64>,
    pub welcome_message: Option<String>,
    pub welcome_screen_description: Option<String>,
    pub welcome_screen_channels: Option<serde_json::Value>,
    pub emoji_version: i32,
    pub banner_url: Option<String>,
    pub banner_crop: Option<BannerCrop>,
    pub accent_color: Option<String>,
    /// 0-100 vertical focal point for banner crop (0 = top, 50 = center, 100 = bottom).
    pub banner_offset_y: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ServerResponse {
    pub id: String,
    pub name: String,
    pub icon_url: Option<String>,
    pub owner_id: String,
    pub description: Option<String>,
    pub voice_bitrate: i32,
    pub welcome_channel_id: Option<String>,
    pub announce_channel_id: Option<String>,
    pub banner_url: Option<String>,
    pub banner_crop: Option<BannerCrop>,
    pub accent_color: Option<String>,
    pub banner_offset_y: i32,
    pub created_at: String,
    pub updated_at: String,
}

impl From<&ServerRow> for ServerResponse {
    fn from(s: &ServerRow) -> Self {
        let ts = s.created_at.to_rfc3339();
        Self {
            id: s.id.to_string(),
            name: s.name.clone(),
            icon_url: cdn::resolve(s.icon_url.as_deref()),
            owner_id: s.owner_id.to_string(),
            description: None,
            voice_bitrate: s.voice_bitrate,
            welcome_channel_id: s.welcome_channel_id.map(|id| id.to_string()),
            announce_channel_id: s.announce_channel_id.map(|id| id.to_string()),
            banner_url: cdn::resolve(s.banner_url.as_deref()),
            banner_crop: s.banner_crop,
            accent_color: s.accent_color.clone(),
            banner_offset_y: s.banner_offset_y,
            created_at: ts.clone(),
            updated_at: ts,
        }
    }
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MemberRow {
    pub user_id: i64,
    pub username: String,
    pub avatar_url: Option<String>,
    pub banner_url: Option<String>,
    pub display_name: Option<String>,
    pub status_type: String,
    pub nickname: Option<String>,
    pub joined_at: chrono::DateTime<chrono::Utc>,
}
