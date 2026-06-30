//! Channel row/response types.

#[derive(Debug)]
pub struct ChannelRow {
    pub id: i64,
    pub r#type: i32,
    pub server_id: Option<i64>,
    pub name: Option<String>,
    pub topic: Option<String>,
    pub position: i32,
    pub category_id: Option<i64>,
    pub read_only: bool,
    pub slowmode_seconds: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChannelResponse {
    pub id: String,
    pub r#type: i32,
    pub server_id: Option<String>,
    pub name: Option<String>,
    pub topic: Option<String>,
    pub position: i32,
    pub category_id: Option<String>,
    pub read_only: bool,
    pub slowmode_seconds: i32,
    pub created_at: String,
}

impl From<&ChannelRow> for ChannelResponse {
    fn from(c: &ChannelRow) -> Self {
        Self {
            id: c.id.to_string(),
            r#type: c.r#type,
            server_id: c.server_id.map(|id| id.to_string()),
            name: c.name.clone(),
            topic: c.topic.clone(),
            position: c.position,
            category_id: c.category_id.map(|id| id.to_string()),
            read_only: c.read_only,
            slowmode_seconds: c.slowmode_seconds,
            created_at: c.created_at.to_rfc3339(),
        }
    }
}
