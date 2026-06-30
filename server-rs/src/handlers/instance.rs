use axum::{Json, extract::State};

use crate::services::instance::{InstanceMetadata, metadata};
use crate::state::AppState;

pub async fn get_instance(State(state): State<AppState>) -> Json<InstanceMetadata> {
    Json(metadata(&state.config))
}
