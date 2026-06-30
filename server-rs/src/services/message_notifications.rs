use std::collections::HashSet;

use serde_json::Value;

use crate::state::AppState;
use crate::ws::{events, topics};

const TARGET_CHANNEL: i64 = 2;

#[derive(Debug, Default, Clone, Copy)]
pub struct TargetedNotificationStats {
    pub target_count: usize,
    pub mention_count: usize,
    pub channel_pref_count: usize,
    pub skipped_permission_count: usize,
}

#[derive(Debug, sqlx::FromRow)]
struct CandidateRow {
    id: i64,
    username_lower: String,
    role_ids: Vec<i64>,
    notification_prefs: Value,
}

#[derive(Debug, Default)]
struct MentionTokens {
    user_ids: HashSet<i64>,
    usernames: HashSet<String>,
    role_ids: HashSet<i64>,
}

fn mention_tokens(content: &str) -> MentionTokens {
    let mut tokens = MentionTokens::default();
    let mut chars = content.char_indices().peekable();

    while let Some((idx, ch)) = chars.next() {
        if ch != '@' {
            continue;
        }
        if idx > 0 {
            let prev = content[..idx].chars().next_back().unwrap_or(' ');
            if !prev.is_whitespace() && !matches!(prev, '(' | '[' | '{' | '<' | '"' | '\'') {
                continue;
            }
        }

        let start = idx + ch.len_utf8();
        if matches!(chars.peek(), Some(&(_, '&'))) {
            chars.next();
            let mut role_start = start + '&'.len_utf8();
            if content[role_start..].starts_with("amp;") {
                role_start += "amp;".len();
                while let Some(&(_, next_ch)) = chars.peek() {
                    if next_ch == ';' {
                        chars.next();
                        break;
                    }
                    chars.next();
                }
            }
            let mut role_end = role_start;
            while let Some(&(next_idx, next_ch)) = chars.peek() {
                if !next_ch.is_ascii_digit() {
                    break;
                }
                role_end = next_idx + next_ch.len_utf8();
                chars.next();
            }
            if matches!(chars.peek(), Some(&(_, next_ch)) if next_ch.is_ascii_alphanumeric() || next_ch == '_')
            {
                continue;
            }
            if role_end > role_start {
                if let Ok(id) = content[role_start..role_end].parse::<i64>() {
                    tokens.role_ids.insert(id);
                }
            }
            continue;
        }

        let mut end = start;
        while let Some(&(next_idx, next_ch)) = chars.peek() {
            if !next_ch.is_ascii_alphanumeric() && next_ch != '_' {
                break;
            }
            end = next_idx + next_ch.len_utf8();
            chars.next();
        }

        if end <= start {
            continue;
        }

        let token = &content[start..end];
        if token.eq_ignore_ascii_case("everyone") || token.eq_ignore_ascii_case("here") {
            continue;
        }
        if let Ok(id) = token.parse::<i64>() {
            tokens.user_ids.insert(id);
        }
        if token.len() <= 32 {
            tokens.usernames.insert(token.to_ascii_lowercase());
        }
    }

    tokens
}

fn json_i64(value: &Value) -> Option<i64> {
    value
        .as_i64()
        .or_else(|| value.as_str()?.parse::<i64>().ok())
}

fn json_bool(value: Option<&Value>, default: bool) -> bool {
    value
        .and_then(|v| v.as_bool().or_else(|| v.as_str()?.parse::<bool>().ok()))
        .unwrap_or(default)
}

fn has_channel_notification_pref(prefs: &Value, channel_id: i64) -> bool {
    let Some(items) = prefs.as_array() else {
        return false;
    };

    items.iter().any(|item| {
        let Some(obj) = item.as_object() else {
            return false;
        };
        let target_type = obj.get("target_type").and_then(json_i64).unwrap_or(-1);
        let target_id = obj.get("target_id").and_then(json_i64).unwrap_or(-1);
        target_type == TARGET_CHANNEL
            && target_id == channel_id
            && !json_bool(obj.get("muted"), false)
            && json_bool(obj.get("desktop_enabled"), true)
    })
}

pub async fn publish_targeted_unread_signals(
    state: &AppState,
    channel_id: i64,
    channel_id_str: &str,
    server_id: Option<i64>,
    message_id: &str,
    author_id: i64,
    created_at: &str,
    mention_source: &str,
) -> Result<TargetedNotificationStats, sqlx::Error> {
    let Some(server_id) = server_id else {
        return Ok(TargetedNotificationStats::default());
    };

    let mentions = mention_tokens(mention_source);
    let mention_user_ids: Vec<i64> = mentions.user_ids.iter().copied().collect();
    let mention_usernames: Vec<String> = mentions.usernames.iter().cloned().collect();
    let mention_role_candidates: Vec<i64> = mentions.role_ids.iter().copied().collect();
    let mention_role_ids: Vec<i64> = if mention_role_candidates.is_empty() {
        Vec::new()
    } else {
        sqlx::query_as::<_, (i64,)>(
            r#"
            SELECT id
             FROM roles
             WHERE server_id = $1
               AND id = ANY($2::bigint[])
               AND position > 0
            "#,
        )
        .bind(server_id)
        .bind(&mention_role_candidates)
        .fetch_all(&state.pg)
        .await?
        .into_iter()
        .map(|(id,)| id)
        .collect()
    };

    let candidates = sqlx::query_as::<_, CandidateRow>(
        r#"
        SELECT
            u.id,
            lower(u.username) AS username_lower,
            COALESCE(ARRAY(
                SELECT mr.role_id
                  FROM member_roles mr
                 WHERE mr.user_id = u.id
                   AND mr.server_id = $1
            ), ARRAY[]::bigint[]) AS role_ids,
            COALESCE(u.notification_prefs, '[]'::jsonb) AS notification_prefs
          FROM server_members sm
          JOIN users u ON u.id = sm.user_id
         WHERE sm.server_id = $1
           AND sm.user_id <> $2
           AND u.deleted_at_ms IS NULL
           AND (
                u.id = ANY($3::bigint[])
             OR lower(u.username) = ANY($4::text[])
             OR EXISTS (
                    SELECT 1
                      FROM member_roles mr
                     WHERE mr.user_id = u.id
                       AND mr.server_id = $1
                       AND mr.role_id = ANY($7::bigint[])
                )
             OR EXISTS (
                    SELECT 1
                      FROM jsonb_array_elements(COALESCE(u.notification_prefs, '[]'::jsonb)) pref
                     WHERE (pref->>'target_type')::bigint = $5
                       AND (pref->>'target_id')::bigint = $6
                       AND COALESCE((pref->>'muted')::boolean, false) = false
                       AND COALESCE((pref->>'desktop_enabled')::boolean, true) = true
                )
           )
        "#,
    )
    .bind(server_id)
    .bind(author_id)
    .bind(&mention_user_ids)
    .bind(&mention_usernames)
    .bind(TARGET_CHANNEL)
    .bind(channel_id)
    .bind(&mention_role_ids)
    .fetch_all(&state.pg)
    .await?;

    let mut stats = TargetedNotificationStats::default();
    let server_id_str = server_id.to_string();
    for candidate in candidates {
        let mentioned = mentions.user_ids.contains(&candidate.id)
            || mentions.usernames.contains(&candidate.username_lower)
            || candidate
                .role_ids
                .iter()
                .any(|role_id| mention_role_ids.contains(role_id));
        let channel_pref = has_channel_notification_pref(&candidate.notification_prefs, channel_id);
        if !mentioned && !channel_pref {
            continue;
        }

        if state
            .permissions
            .check_channel_permission(
                candidate.id,
                channel_id,
                server_id,
                crate::services::permissions::bits::VIEW_CHANNEL,
            )
            .await
            .is_err()
        {
            stats.skipped_permission_count += 1;
            continue;
        }

        let target_topic = topics::user_topic(candidate.id);
        let target_user_id = candidate.id.to_string();
        let json = events::channel_unread_signal_json(
            channel_id_str,
            Some(&server_id_str),
            message_id,
            &author_id.to_string(),
            created_at,
            mentioned,
            false,
        );
        let proto = events::channel_unread_signal_proto(
            channel_id_str.to_string(),
            Some(server_id_str.clone()),
            message_id.to_string(),
            author_id.to_string(),
            created_at.to_string(),
            mentioned,
            false,
        );
        crate::realtime_trace!(
            channel_id,
            server_id,
            message_id,
            target_user_id = %target_user_id,
            mentioned,
            channel_pref,
            target_topic = %target_topic,
            "realtime_scope: publishing targeted CHANNEL_UNREAD_SIGNAL to user topic"
        );
        topics::publish(state, &target_topic, &json, &proto).await;
        stats.target_count += 1;
        if mentioned {
            stats.mention_count += 1;
        }
        if channel_pref {
            stats.channel_pref_count += 1;
        }
    }

    Ok(stats)
}

#[cfg(test)]
mod tests {
    use super::{has_channel_notification_pref, mention_tokens};
    use serde_json::json;

    #[test]
    fn mention_tokens_extract_usernames_and_ids() {
        let tokens = mention_tokens("hi @Josh and @1234567890 but not email@test.com");
        assert!(tokens.user_ids.contains(&1_234_567_890));
        assert!(tokens.usernames.contains("josh"));
        assert!(!tokens.usernames.contains("test"));
    }

    #[test]
    fn mention_tokens_ignore_everyone_and_here() {
        let tokens = mention_tokens("@everyone @here @User_1");
        assert!(tokens.user_ids.is_empty());
        assert_eq!(
            tokens.usernames,
            ["user_1".to_string()].into_iter().collect()
        );
    }

    #[test]
    fn mention_tokens_extract_role_ids() {
        let tokens = mention_tokens("ping @&123456789012345678 and @Josh");
        assert!(tokens.role_ids.contains(&123_456_789_012_345_678));
        assert!(tokens.usernames.contains("josh"));
    }

    #[test]
    fn mention_tokens_extract_legacy_escaped_role_ids() {
        let tokens = mention_tokens("ping @&amp;123456789012345678 and @Josh");
        assert!(tokens.role_ids.contains(&123_456_789_012_345_678));
        assert!(tokens.usernames.contains("josh"));
    }

    #[test]
    fn mention_tokens_reject_malformed_role_ids() {
        let tokens = mention_tokens("ignore @&123abc and bare @&");
        assert!(tokens.role_ids.is_empty());
    }

    #[test]
    fn channel_pref_requires_enabled_unmuted_channel_target() {
        let prefs = json!([
            { "target_type": 2, "target_id": 10, "muted": true, "desktop_enabled": true },
            { "target_type": 2, "target_id": 11, "muted": false, "desktop_enabled": false },
            { "target_type": 2, "target_id": 12, "muted": false, "desktop_enabled": true }
        ]);
        assert!(!has_channel_notification_pref(&prefs, 10));
        assert!(!has_channel_notification_pref(&prefs, 11));
        assert!(has_channel_notification_pref(&prefs, 12));
    }
}
