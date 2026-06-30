//! Placeholder for the 30-day hard-delete purge task.
//!
//! Soft-deleted users and servers are filtered at read boundaries. Reinstate
//! the durable cascade purge before promising automated hard deletion.
//!
//! TODO(purge): Add durable 30-day hard-delete for expired soft-deletes.

use crate::state::AppState;

pub fn spawn_purge_task(_state: AppState) {
    tracing::info!("purge: no-op; soft-delete still honored at read time");
}
