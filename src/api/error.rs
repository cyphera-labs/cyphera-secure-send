//! One error shape for the whole API, and a JSON extractor whose rejections
//! use it too, so a malformed body and a rejected body look the same.

use axum::Json;
use axum::extract::{FromRequest, Request};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;

#[derive(Serialize)]
struct ErrorBody<'a> {
    error: &'a str,
}

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    /// The generic answer for anything that would otherwise reveal whether a
    /// message exists. Always the same status and body.
    Unavailable,
    TooLarge,
    RateLimited,
    Capacity,
    Forbidden,
    Internal,
}

impl ApiError {
    fn status_and_text(&self) -> (StatusCode, &str) {
        match self {
            ApiError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.as_str()),
            ApiError::Unavailable => (StatusCode::NOT_FOUND, "unavailable"),
            ApiError::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "too large"),
            ApiError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate limited"),
            ApiError::Capacity => (StatusCode::SERVICE_UNAVAILABLE, "at capacity"),
            ApiError::Forbidden => (StatusCode::FORBIDDEN, "not permitted"),
            ApiError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal error"),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, text) = self.status_and_text();
        (status, Json(ErrorBody { error: text })).into_response()
    }
}

/// `Json<T>` with every rejection collapsed to a 400 (or 413 for size).
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match Json::<T>::from_request(req, state).await {
            Ok(Json(value)) => Ok(ApiJson(value)),
            Err(rejection) => {
                if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                    Err(ApiError::TooLarge)
                } else {
                    Err(ApiError::BadRequest("malformed request".to_owned()))
                }
            }
        }
    }
}
