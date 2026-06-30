//! Category row/response types.

#[derive(Debug)]
pub struct CategoryRow {
    pub id: i64,
    pub server_id: i64,
    pub name: String,
    pub position: i32,
    pub emoji: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CategoryResponse {
    pub id: String,
    pub server_id: String,
    pub name: String,
    pub position: i32,
    pub emoji: Option<String>,
    pub created_at: String,
}

impl From<&CategoryRow> for CategoryResponse {
    fn from(c: &CategoryRow) -> Self {
        Self {
            id: c.id.to_string(),
            server_id: c.server_id.to_string(),
            name: c.name.clone(),
            position: c.position,
            emoji: c.emoji.clone(),
            created_at: c.created_at.to_rfc3339(),
        }
    }
}
