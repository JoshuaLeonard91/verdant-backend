//! Background content-scan retry task placeholder.
//!
//! Scan-on-upload is the active path. This no-op keeps startup wiring simple.

use crate::state::AppState;

pub fn spawn_scan_retry_task(_state: AppState) {
    tracing::info!("content_scan_task: no-op; scan-on-upload is the only path");
}
