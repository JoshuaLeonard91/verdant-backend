use std::collections::{HashMap, HashSet};

use crate::error::{AppError, AppResult};
use crate::repo::channels::{ChannelResponse, ChannelRow};
use crate::services::permissions::bits;
use crate::state::AppState;
use crate::ws::{events, topics};

const CHANNEL_TYPE_SERVER_VOICE: i32 = 3;

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ChannelVisibilityDelta {
    pub gained: Vec<i64>,
    pub lost: Vec<i64>,
}

pub fn diff_channel_visibility(
    before: &HashSet<i64>,
    after: &HashSet<i64>,
) -> ChannelVisibilityDelta {
    let mut gained: Vec<i64> = after.difference(before).copied().collect();
    let mut lost: Vec<i64> = before.difference(after).copied().collect();
    gained.sort_unstable();
    lost.sort_unstable();
    ChannelVisibilityDelta { gained, lost }
}

fn visibility_update_topic(channel_id: i64) -> String {
    topics::channel_live_topic(channel_id)
}

fn channel_proto(channel: &ChannelRow) -> crate::proto::Channel {
    crate::proto::Channel {
        id: channel.id.to_string(),
        r#type: channel.r#type,
        server_id: channel.server_id.map(|id| id.to_string()),
        name: channel.name.clone(),
        topic: channel.topic.clone(),
        position: channel.position,
        category_id: channel.category_id.map(|id| id.to_string()),
        read_only: channel.read_only,
        slowmode_seconds: channel.slowmode_seconds,
        created_at: channel.created_at.to_rfc3339(),
    }
}

async fn publish_channel_create_to_user(state: &AppState, user_id: i64, channel: &ChannelRow) {
    let ch_json = serde_json::json!(ChannelResponse::from(channel));
    let json_text = events::channel_create_json(&ch_json);
    let proto_msg = events::channel_create_proto(channel_proto(channel));
    crate::realtime_trace!(
        user_id,
        channel_id = channel.id,
        server_id = ?channel.server_id,
        topic = %topics::user_topic(user_id),
        "realtime_scope: publishing targeted CHANNEL_CREATE after visibility gain without auto-subscribing channel topics"
    );
    topics::publish(state, &topics::user_topic(user_id), &json_text, &proto_msg).await;
}

async fn publish_channel_delete_to_user(
    state: &AppState,
    user_id: i64,
    channel_id: i64,
    server_id: i64,
) {
    let json_text = events::channel_delete_json(&channel_id.to_string(), &server_id.to_string());
    let proto_msg = events::channel_delete_proto(channel_id.to_string(), server_id.to_string());
    crate::realtime_trace!(
        user_id,
        channel_id,
        server_id,
        topic = %topics::user_topic(user_id),
        "realtime_scope: publishing targeted CHANNEL_DELETE after visibility loss"
    );
    topics::publish(state, &topics::user_topic(user_id), &json_text, &proto_msg).await;
}

async fn publish_channel_visibility_update(
    state: &AppState,
    server_id: i64,
    channel_id: i64,
    delta: &ChannelVisibilityDelta,
) {
    if delta.gained.is_empty() && delta.lost.is_empty() {
        crate::realtime_trace!(
            server_id,
            channel_id,
            "realtime_scope: CHANNEL_VISIBILITY_UPDATE skipped because delta was empty"
        );
        return;
    }

    let gained_user_ids = delta
        .gained
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let lost_user_ids = delta
        .lost
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let json_text = events::channel_visibility_update_json(
        &server_id.to_string(),
        &channel_id.to_string(),
        &gained_user_ids,
        &lost_user_ids,
    );

    let topic = visibility_update_topic(channel_id);
    let live_local_subscribers = state
        .ws
        .topic_subscribers
        .get(&topic)
        .map(|set| set.len())
        .unwrap_or(0);
    crate::realtime_trace!(
        server_id,
        channel_id,
        gained_count = delta.gained.len(),
        lost_count = delta.lost.len(),
        live_topic = %topic,
        live_local_subscribers,
        "realtime_scope: publishing CHANNEL_VISIBILITY_UPDATE to focused live subscribers"
    );
    topics::publish_json(state, &topic, &json_text).await;
}

pub async fn apply_channel_visibility_delta(
    state: &AppState,
    channel: &ChannelRow,
    delta: &ChannelVisibilityDelta,
) -> AppResult<()> {
    let server_id = channel.server_id.ok_or(AppError::NotFound("channel"))?;
    let channel_id = channel.id;
    crate::realtime_trace!(
        server_id,
        channel_id,
        gained_count = delta.gained.len(),
        lost_count = delta.lost.len(),
        "realtime_scope: applying channel visibility delta"
    );

    for user_id in &delta.lost {
        publish_channel_delete_to_user(state, *user_id, channel_id, server_id).await;
        topics::unsubscribe_user_from_channel(state, *user_id, channel_id).await;
    }

    for user_id in &delta.gained {
        publish_channel_create_to_user(state, *user_id, channel).await;
        if channel.r#type == CHANNEL_TYPE_SERVER_VOICE {
            topics::subscribe_user(state, *user_id, &[topics::voice_topic(channel_id)]).await;
        }
    }

    publish_channel_visibility_update(state, server_id, channel_id, delta).await;

    Ok(())
}

pub async fn reconcile_single_channel_visibility(
    state: &AppState,
    channel: &ChannelRow,
    before_viewers: &HashSet<i64>,
) -> AppResult<ChannelVisibilityDelta> {
    let server_id = channel.server_id.ok_or(AppError::NotFound("channel"))?;
    let after_viewers = state
        .permissions
        .collect_online_channel_viewers(server_id, channel.id);
    let delta = diff_channel_visibility(before_viewers, &after_viewers);
    crate::realtime_trace!(
        server_id,
        channel_id = channel.id,
        before_count = before_viewers.len(),
        after_count = after_viewers.len(),
        gained_count = delta.gained.len(),
        lost_count = delta.lost.len(),
        "realtime_scope: reconciled single channel visibility"
    );
    apply_channel_visibility_delta(state, channel, &delta).await?;
    Ok(delta)
}

pub async fn visible_channel_ids_for_user(
    state: &AppState,
    user_id: i64,
    server_id: i64,
    channels: &[ChannelRow],
) -> AppResult<HashSet<i64>> {
    let mut visible = HashSet::new();
    for channel in channels {
        match state
            .permissions
            .check_channel_permission(user_id, channel.id, server_id, bits::VIEW_CHANNEL)
            .await
        {
            Ok(()) => {
                visible.insert(channel.id);
            }
            Err(AppError::Internal) => return Err(AppError::Internal),
            Err(_) => {}
        }
    }
    Ok(visible)
}

pub async fn snapshot_visible_channels_by_user(
    state: &AppState,
    server_id: i64,
    user_ids: &HashSet<i64>,
    channels: &[ChannelRow],
) -> AppResult<HashMap<i64, HashSet<i64>>> {
    let mut snapshot = HashMap::with_capacity(user_ids.len());
    for user_id in user_ids {
        let visible = visible_channel_ids_for_user(state, *user_id, server_id, channels).await?;
        snapshot.insert(*user_id, visible);
    }
    Ok(snapshot)
}

pub async fn reconcile_visible_channels_by_user(
    state: &AppState,
    server_id: i64,
    channels: &[ChannelRow],
    before_by_user: &HashMap<i64, HashSet<i64>>,
) -> AppResult<()> {
    let mut deltas_by_channel: HashMap<i64, ChannelVisibilityDelta> = HashMap::new();

    for (user_id, before) in before_by_user {
        let after = visible_channel_ids_for_user(state, *user_id, server_id, channels).await?;
        let delta = diff_channel_visibility(before, &after);

        for channel_id in &delta.lost {
            publish_channel_delete_to_user(state, *user_id, *channel_id, server_id).await;
            topics::unsubscribe_user_from_channel(state, *user_id, *channel_id).await;
            deltas_by_channel
                .entry(*channel_id)
                .or_default()
                .lost
                .push(*user_id);
        }

        for channel_id in &delta.gained {
            if let Some(channel) = channels.iter().find(|channel| channel.id == *channel_id) {
                publish_channel_create_to_user(state, *user_id, channel).await;
                if channel.r#type == CHANNEL_TYPE_SERVER_VOICE {
                    topics::subscribe_user(state, *user_id, &[topics::voice_topic(*channel_id)])
                        .await;
                }
                deltas_by_channel
                    .entry(*channel_id)
                    .or_default()
                    .gained
                    .push(*user_id);
            }
        }
    }

    let mut channel_deltas = deltas_by_channel.into_iter().collect::<Vec<_>>();
    channel_deltas.sort_by_key(|(channel_id, _)| *channel_id);
    crate::realtime_trace!(
        server_id,
        checked_users = before_by_user.len(),
        changed_channels = channel_deltas.len(),
        "realtime_scope: reconciled visible channels by user"
    );

    for (channel_id, mut delta) in channel_deltas {
        delta.gained.sort_unstable();
        delta.gained.dedup();
        delta.lost.sort_unstable();
        delta.lost.dedup();
        publish_channel_visibility_update(state, server_id, channel_id, &delta).await;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(ids: &[i64]) -> HashSet<i64> {
        ids.iter().copied().collect()
    }

    #[test]
    fn visibility_diff_reports_gained_and_lost_users() {
        let before = set(&[10, 20, 30]);
        let after = set(&[20, 30, 40]);

        let delta = diff_channel_visibility(&before, &after);

        assert_eq!(delta.gained, vec![40]);
        assert_eq!(delta.lost, vec![10]);
    }

    #[test]
    fn visibility_diff_sorts_results_for_stable_broadcasts() {
        let before = set(&[50, 10, 40]);
        let after = set(&[30, 40, 20]);

        let delta = diff_channel_visibility(&before, &after);

        assert_eq!(delta.gained, vec![20, 30]);
        assert_eq!(delta.lost, vec![10, 50]);
    }

    #[test]
    fn visibility_update_uses_live_topic_for_focused_viewers() {
        assert_eq!(visibility_update_topic(42), "channel_live:42");
    }
}
