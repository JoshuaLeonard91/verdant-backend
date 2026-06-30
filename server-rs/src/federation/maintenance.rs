use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::state::AppState;

use super::storage::{self, REPLAY_NONCE_PRUNE_BATCH_LIMIT};

pub const REPLAY_NONCE_CLEANUP_INTERVAL_SECS: u64 = 60 * 60;

pub fn spawn_replay_nonce_cleanup_task(state: AppState) {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_secs(REPLAY_NONCE_CLEANUP_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!("Federation replay nonce cleanup task started");

        loop {
            interval.tick().await;
            if state.shutting_down.load(Ordering::Relaxed) {
                tracing::info!("Federation replay nonce cleanup task stopped");
                break;
            }

            let now_ms = crate::services::pg::now_ms();
            match storage::prune_expired_replay_nonces(
                &state.pg,
                now_ms,
                REPLAY_NONCE_PRUNE_BATCH_LIMIT,
            )
            .await
            {
                Ok(deleted) if deleted > 0 => {
                    tracing::info!(deleted, "Federation replay nonce cleanup complete")
                }
                Ok(_) => {}
                Err(error) => tracing::warn!(
                    error = %error,
                    "Federation replay nonce cleanup failed"
                ),
            }
        }
    });
}
