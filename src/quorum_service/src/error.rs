use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    Unauthorized,
    Forbidden(String),
    NotFound(String),
    Conflict(String),
    Internal(String),
    /// F-13/F-14: the state change IS committed but its audit entry could not
    /// be appended yet; a durable outbox row will deliver it. HTTP 202.
    AuditPending {
        outbox_id: i64,
        detail: String,
    },
    /// The audit quorum could not record an event for an operation that has no
    /// state change to hold an outbox row (derive-key): denied, fail-closed. HTTP 503.
    AuditUnavailable(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        if let ApiError::AuditPending { outbox_id, detail } = &self {
            return (
                StatusCode::ACCEPTED,
                Json(json!({
                    "state_change": "committed",
                    "audit": "pending",
                    "outbox_id": outbox_id,
                    "detail": detail,
                    "note": "do not retry the operation; the audit entry is queued durably and will be appended automatically",
                })),
            )
                .into_response();
        }
        let (status, message) = match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, m),
            ApiError::Unauthorized => (
                StatusCode::UNAUTHORIZED,
                "missing or invalid API key".to_string(),
            ),
            ApiError::Forbidden(m) => (StatusCode::FORBIDDEN, m),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, m),
            ApiError::Conflict(m) => (StatusCode::CONFLICT, m),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, m),
            ApiError::AuditUnavailable(m) => (StatusCode::SERVICE_UNAVAILABLE, m),
            ApiError::AuditPending { .. } => unreachable_pending(),
        };
        (status, Json(json!({ "error": message }))).into_response()
    }
}

impl From<tokio_postgres::Error> for ApiError {
    fn from(e: tokio_postgres::Error) -> Self {
        ApiError::Internal(format!("database error: {e}"))
    }
}

// `AuditPending` is answered before the match above; this keeps the match
// exhaustive without a panic path (no unwrap/unreachable! on a request path).
fn unreachable_pending() -> (StatusCode, String) {
    (
        StatusCode::ACCEPTED,
        "state change committed; audit pending".to_string(),
    )
}
