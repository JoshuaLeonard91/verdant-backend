use reqwest::{Method, StatusCode};
use serde_json::Error as JsonError;
use sqlx::PgPool;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::{
    auth::FederationRequestSigner,
    client::{FederationClientError, FederationHttpClient},
    storage::{self, ClaimedOutboundFederationEvent},
};
use crate::state::AppState;

pub const FEDERATION_EVENT_PATH: &str = "/api/federation/v1/events";
pub const MAX_OUTBOUND_EVENT_BODY_BYTES: usize = 128 * 1024;
const DISPATCH_INTERVAL_MS: u64 = 1_000;
const DISPATCH_BATCH_LIMIT: i64 = 25;
const HTTP_TIMEOUT_SECS: u64 = 10;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FederationDeliveryDisposition {
    Sent,
    RetryableFailure(String),
    PermanentFailure(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct FederationOutboxDispatchReport {
    pub claimed: usize,
    pub sent: usize,
    pub failed: usize,
    pub dead: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum FederationOutboxError {
    #[error("failed to read federation outbox")]
    Storage(#[from] sqlx::Error),
    #[error("failed to serialize federation event body")]
    SerializeBody(#[from] JsonError),
    #[error("federation event body is too large")]
    EventBodyTooLarge,
}

pub fn outbound_event_body_bytes(
    event: &ClaimedOutboundFederationEvent,
) -> Result<Vec<u8>, FederationOutboxError> {
    let bytes = serde_json::to_vec(&event.event_body_json)?;
    if bytes.len() > MAX_OUTBOUND_EVENT_BODY_BYTES {
        return Err(FederationOutboxError::EventBodyTooLarge);
    }
    Ok(bytes)
}

pub fn delivery_nonce() -> String {
    format!("fedout-{}", uuid::Uuid::new_v4().simple())
}

pub fn outbox_dispatcher_enabled(key_id: Option<&str>, seed: Option<&[u8; 32]>) -> bool {
    key_id.is_some_and(|value| !value.trim().is_empty()) && seed.is_some()
}

pub fn delivery_status_disposition(status: StatusCode) -> FederationDeliveryDisposition {
    if status.is_success() {
        return FederationDeliveryDisposition::Sent;
    }

    let code = format!("HTTP_{}", status.as_u16());
    if status.is_server_error()
        || matches!(
            status,
            StatusCode::REQUEST_TIMEOUT
                | StatusCode::CONFLICT
                | StatusCode::TOO_EARLY
                | StatusCode::TOO_MANY_REQUESTS
        )
    {
        FederationDeliveryDisposition::RetryableFailure(code)
    } else {
        FederationDeliveryDisposition::PermanentFailure(code)
    }
}

fn client_error_disposition(error: &FederationClientError) -> FederationDeliveryDisposition {
    match error {
        FederationClientError::Delivery(_) => {
            FederationDeliveryDisposition::RetryableFailure("TRANSPORT_ERROR".to_string())
        }
        FederationClientError::InvalidPeerEndpoint
        | FederationClientError::Sign(_)
        | FederationClientError::BuildRequest(_) => {
            FederationDeliveryDisposition::PermanentFailure("INVALID_DELIVERY_REQUEST".to_string())
        }
    }
}

async fn dispatch_claimed_outbound_event(
    pool: &PgPool,
    http: &FederationHttpClient,
    event: ClaimedOutboundFederationEvent,
    now_ms: i64,
) -> Result<FederationDeliveryDisposition, FederationOutboxError> {
    let Some(peer) = storage::peer_endpoint_by_peer_id(pool, &event.destination_peer_id).await?
    else {
        let plan = storage::mark_outbound_event_failed(
            pool,
            event.id,
            now_ms,
            event.attempt_count,
            "UNKNOWN_PEER_ENDPOINT",
        )
        .await?;
        return if plan.status == "dead" {
            Ok(FederationDeliveryDisposition::PermanentFailure(
                plan.last_error_code,
            ))
        } else {
            Ok(FederationDeliveryDisposition::RetryableFailure(
                plan.last_error_code,
            ))
        };
    };

    let body = match outbound_event_body_bytes(&event) {
        Ok(bytes) => bytes,
        Err(error) => {
            storage::mark_outbound_event_dead(
                pool,
                event.id,
                now_ms,
                event.attempt_count,
                "INVALID_EVENT_BODY",
            )
            .await?;
            return Err(error);
        }
    };

    let disposition = match http
        .send_signed_json_request(
            Method::POST,
            &peer,
            FEDERATION_EVENT_PATH,
            body,
            now_ms,
            &delivery_nonce(),
        )
        .await
    {
        Ok(response) => delivery_status_disposition(response.status()),
        Err(error) => client_error_disposition(&error),
    };

    match &disposition {
        FederationDeliveryDisposition::Sent => {
            storage::mark_outbound_event_sent(pool, event.id, now_ms).await?;
            tracing::info!(
                destination_peer_id = %event.destination_peer_id,
                event_id = %event.event_id,
                event_kind = %event.event_kind,
                "Federation outbound event delivered"
            );
        }
        FederationDeliveryDisposition::RetryableFailure(code) => {
            let plan = storage::mark_outbound_event_failed(
                pool,
                event.id,
                now_ms,
                event.attempt_count,
                code,
            )
            .await?;
            tracing::warn!(
                destination_peer_id = %event.destination_peer_id,
                event_id = %event.event_id,
                event_kind = %event.event_kind,
                attempt_count = plan.attempt_count,
                status = plan.status,
                error_code = %plan.last_error_code,
                "Federation outbound event delivery failed"
            );
            if plan.status == "dead" {
                return Ok(FederationDeliveryDisposition::PermanentFailure(
                    plan.last_error_code,
                ));
            }
        }
        FederationDeliveryDisposition::PermanentFailure(code) => {
            let plan = storage::mark_outbound_event_dead(
                pool,
                event.id,
                now_ms,
                event.attempt_count,
                code,
            )
            .await?;
            tracing::warn!(
                destination_peer_id = %event.destination_peer_id,
                event_id = %event.event_id,
                event_kind = %event.event_kind,
                attempt_count = plan.attempt_count,
                error_code = %plan.last_error_code,
                "Federation outbound event dead-lettered"
            );
        }
    }

    Ok(disposition)
}

pub async fn dispatch_due_outbound_events(
    pool: &PgPool,
    http: &FederationHttpClient,
    now_ms: i64,
    limit: i64,
) -> Result<FederationOutboxDispatchReport, FederationOutboxError> {
    let events = storage::claim_due_outbound_events(pool, now_ms, limit).await?;
    let mut report = FederationOutboxDispatchReport {
        claimed: events.len(),
        ..FederationOutboxDispatchReport::default()
    };

    for event in events {
        match dispatch_claimed_outbound_event(pool, http, event, now_ms).await? {
            FederationDeliveryDisposition::Sent => report.sent += 1,
            FederationDeliveryDisposition::RetryableFailure(_) => report.failed += 1,
            FederationDeliveryDisposition::PermanentFailure(_) => report.dead += 1,
        }
    }

    Ok(report)
}

pub fn spawn_outbox_dispatch_task(state: AppState) {
    let key_id = state.config.federation_s2s_key_id.as_deref();
    let seed = state.config.federation_s2s_signing_seed.as_ref();
    if !outbox_dispatcher_enabled(key_id, seed) {
        tracing::info!("Federation outbound dispatcher disabled: S2S signing is not configured");
        return;
    }

    let key_id = key_id.expect("checked above");
    let seed = *seed.expect("checked above");
    let signer = match FederationRequestSigner::from_seed(&state.config.instance_id, key_id, seed) {
        Ok(signer) => signer,
        Err(error) => {
            tracing::error!(
                error = %error,
                "Federation outbound dispatcher disabled: invalid S2S signing config"
            );
            return;
        }
    };
    let http =
        match FederationHttpClient::with_timeout(Duration::from_secs(HTTP_TIMEOUT_SECS), signer) {
            Ok(client) => client,
            Err(error) => {
                tracing::error!(
                    error = %error,
                    "Federation outbound dispatcher disabled: HTTP client build failed"
                );
                return;
            }
        };

    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_millis(DISPATCH_INTERVAL_MS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!("Federation outbound dispatcher started");
        loop {
            interval.tick().await;
            if state.shutting_down.load(Ordering::Relaxed) {
                tracing::info!("Federation outbound dispatcher stopped");
                break;
            }
            let now_ms = crate::services::pg::now_ms();
            match dispatch_due_outbound_events(&state.pg, &http, now_ms, DISPATCH_BATCH_LIMIT).await
            {
                Ok(report) if report.claimed > 0 => tracing::info!(
                    claimed = report.claimed,
                    sent = report.sent,
                    failed = report.failed,
                    dead = report.dead,
                    "Federation outbound dispatch cycle complete"
                ),
                Ok(_) => {}
                Err(error) => tracing::warn!(
                    error = %error,
                    "Federation outbound dispatch cycle failed"
                ),
            }
        }
    });
}
