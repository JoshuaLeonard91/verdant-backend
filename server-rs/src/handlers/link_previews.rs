use axum::{
    Json,
    extract::{Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header, header::HeaderName},
    response::{IntoResponse, Response},
};
use serde::Deserialize;

use crate::error::{AppError, AppResult};
use crate::middleware::{
    auth::{OptionalBot, UserId},
    rate_limit,
};
use crate::services::link_preview::{self, LinkPreviewError};
use crate::state::AppState;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkPreviewRequest {
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct LinkPreviewImageQuery {
    pub url: String,
}

pub async fn create_link_preview(
    State(state): State<AppState>,
    user_id: UserId,
    optional_bot: OptionalBot,
    Json(body): Json<LinkPreviewRequest>,
) -> AppResult<Json<link_preview::LinkPreview>> {
    ensure_user_link_preview_request(optional_bot)?;
    rate_limit::enforce(
        &state,
        &rate_limit::LINK_PREVIEW_LIMIT,
        &user_id.0.to_string(),
    )
    .await?;
    link_preview::fetch_link_preview(&body.url)
        .await
        .map(Json)
        .map_err(link_preview_error)
}

pub async fn get_link_preview_image(
    State(state): State<AppState>,
    user_id: UserId,
    optional_bot: OptionalBot,
    Query(query): Query<LinkPreviewImageQuery>,
) -> AppResult<Response> {
    ensure_user_link_preview_request(optional_bot)?;
    rate_limit::enforce(
        &state,
        &rate_limit::LINK_PREVIEW_LIMIT,
        &user_id.0.to_string(),
    )
    .await?;
    let image = link_preview::fetch_preview_image(&query.url)
        .await
        .map_err(link_preview_error)?;
    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(image.content_type),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, max-age=3600"),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    Ok((StatusCode::OK, headers, image.bytes).into_response())
}

fn ensure_user_link_preview_request(optional_bot: OptionalBot) -> AppResult<()> {
    if optional_bot.0.is_some() {
        return Err(AppError::WithCode {
            status: StatusCode::FORBIDDEN,
            code: "LINK_PREVIEW_BOT_FORBIDDEN",
            message: "Bot tokens cannot request link previews".into(),
        });
    }
    Ok(())
}

fn link_preview_error(error: LinkPreviewError) -> AppError {
    let status = match error {
        LinkPreviewError::InvalidUrl
        | LinkPreviewError::UnsafeTarget
        | LinkPreviewError::UnsupportedContentType
        | LinkPreviewError::TooLarge => StatusCode::BAD_REQUEST,
        LinkPreviewError::NoPreview => StatusCode::NOT_FOUND,
        LinkPreviewError::UpstreamRejected => StatusCode::BAD_GATEWAY,
        LinkPreviewError::UpstreamUnavailable => StatusCode::BAD_GATEWAY,
        LinkPreviewError::Busy => StatusCode::TOO_MANY_REQUESTS,
    };
    AppError::WithCode {
        status,
        code: "LINK_PREVIEW_FAILED",
        message: error.user_message().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::middleware::auth::BotIdentity;

    const SOURCE: &str = include_str!("link_previews.rs");

    #[test]
    fn link_preview_requests_reject_bot_tokens() {
        let err = ensure_user_link_preview_request(OptionalBot(Some(test_bot()))).unwrap_err();

        match err {
            AppError::WithCode { status, code, .. } => {
                assert_eq!(status, StatusCode::FORBIDDEN);
                assert_eq!(code, "LINK_PREVIEW_BOT_FORBIDDEN");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn link_preview_requests_accept_user_tokens() {
        ensure_user_link_preview_request(OptionalBot(None)).unwrap();
    }

    #[test]
    fn link_preview_handlers_apply_dedicated_rate_limit_before_fetch() {
        for handler_name in ["create_link_preview", "get_link_preview_image"] {
            let handler = SOURCE
                .split(&format!("pub async fn {handler_name}"))
                .nth(1)
                .unwrap_or_else(|| panic!("{handler_name} should exist"));
            let handler = handler
                .split("fn ensure_user_link_preview_request")
                .next()
                .expect("handler section should be present");

            let rate_limit = handler
                .find("LINK_PREVIEW_LIMIT")
                .unwrap_or_else(|| panic!("{handler_name} should use LINK_PREVIEW_LIMIT"));
            let fetch = handler
                .find("fetch_")
                .unwrap_or_else(|| panic!("{handler_name} should fetch after limiting"));
            assert!(
                rate_limit < fetch,
                "{handler_name} should rate-limit before fetch"
            );
        }
    }

    #[test]
    fn link_preview_busy_maps_to_rate_limit() {
        match link_preview_error(LinkPreviewError::Busy) {
            AppError::WithCode { status, code, .. } => {
                assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
                assert_eq!(code, "LINK_PREVIEW_FAILED");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    fn test_bot() -> BotIdentity {
        BotIdentity {
            bot_id: 1,
            token_id: 2,
            server_id: 3,
            name: "Preview Bot".to_string(),
            description: None,
            avatar_url: None,
            banner_url: None,
            banner_crop: None,
            avatar_preset: None,
            banner_preset: None,
            role_ids: Vec::new(),
            scopes: Vec::new(),
            allowed_feed_ids: Vec::new(),
            allowed_channel_ids: Vec::new(),
        }
    }
}
