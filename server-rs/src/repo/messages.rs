//! Message row/response helper types.

#[derive(Debug)]
pub struct MessageRow {
    pub id: i64,
    pub channel_id: i64,
    pub author_id: Option<i64>,
    pub content: String,
    pub r#type: i32,
    pub edited_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub author_username: Option<String>,
    pub author_avatar_url: Option<String>,
    pub author_display_name: Option<String>,
    // Reply fields (LEFT JOIN on replied message, historically).
    pub reply_to_id: Option<i64>,
    pub reply_author_id: Option<i64>,
    pub reply_author_username: Option<String>,
    pub reply_author_avatar_url: Option<String>,
    pub reply_author_display_name: Option<String>,
    pub reply_content: Option<String>,
}

#[derive(Debug)]
pub struct AttachmentRow {
    pub id: i64,
    pub message_id: i64,
    pub filename: String,
    pub url: String,
    pub content_type: String,
    pub size_bytes: i32,
}

#[derive(Debug)]
pub struct ReactionRow {
    pub message_id: i64,
    pub emoji: String,
    pub emoji_id: Option<i64>,
    pub user_id: i64,
}
