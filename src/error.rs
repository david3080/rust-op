//! OAuth/OIDC エラー。RFC 6749 §4.1.2.1 / §5.2 の error code に対応。
//! 描画方法（redirect か JSON か HTML か）は呼び出し側の endpoint が決める。

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error("invalid_request: {0}")]
    InvalidRequest(String),
    #[error("invalid_client: {0}")]
    InvalidClient(String),
    #[error("unauthorized_client: {0}")]
    UnauthorizedClient(String),
    #[error("invalid_grant: {0}")]
    InvalidGrant(String),
    #[error("unsupported_grant_type: {0}")]
    UnsupportedGrantType(String),
    #[error("unsupported_response_type: {0}")]
    UnsupportedResponseType(String),
    #[error("invalid_scope: {0}")]
    InvalidScope(String),
    #[error("invalid_target: {0}")]
    InvalidTarget(String),
    #[error("access_denied: {0}")]
    AccessDenied(String),
    #[error("login_required: {0}")]
    LoginRequired(String),
    #[error("request_uri_not_supported: {0}")]
    RequestUriNotSupported(String),
    #[error("invalid_dpop_proof: {0}")]
    InvalidDpopProof(String),
    #[error("authorization_pending: {0}")]
    AuthorizationPending(String),
    #[error("expired_token: {0}")]
    ExpiredToken(String),
    #[error("server_error: {0}")]
    ServerError(String),
}

impl OAuthError {
    pub fn code(&self) -> &'static str {
        match self {
            OAuthError::InvalidRequest(_) => "invalid_request",
            OAuthError::InvalidClient(_) => "invalid_client",
            OAuthError::UnauthorizedClient(_) => "unauthorized_client",
            OAuthError::InvalidGrant(_) => "invalid_grant",
            OAuthError::UnsupportedGrantType(_) => "unsupported_grant_type",
            OAuthError::UnsupportedResponseType(_) => "unsupported_response_type",
            OAuthError::InvalidScope(_) => "invalid_scope",
            OAuthError::InvalidTarget(_) => "invalid_target",
            OAuthError::AccessDenied(_) => "access_denied",
            OAuthError::LoginRequired(_) => "login_required",
            OAuthError::RequestUriNotSupported(_) => "request_uri_not_supported",
            OAuthError::InvalidDpopProof(_) => "invalid_dpop_proof",
            OAuthError::AuthorizationPending(_) => "authorization_pending",
            OAuthError::ExpiredToken(_) => "expired_token",
            OAuthError::ServerError(_) => "server_error",
        }
    }

    pub fn description(&self) -> String {
        match self {
            OAuthError::InvalidRequest(s)
            | OAuthError::InvalidClient(s)
            | OAuthError::UnauthorizedClient(s)
            | OAuthError::InvalidGrant(s)
            | OAuthError::UnsupportedGrantType(s)
            | OAuthError::UnsupportedResponseType(s)
            | OAuthError::InvalidScope(s)
            | OAuthError::InvalidTarget(s)
            | OAuthError::AccessDenied(s)
            | OAuthError::LoginRequired(s)
            | OAuthError::RequestUriNotSupported(s)
            | OAuthError::InvalidDpopProof(s)
            | OAuthError::AuthorizationPending(s)
            | OAuthError::ExpiredToken(s)
            | OAuthError::ServerError(s) => s.clone(),
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            OAuthError::InvalidClient(_) => StatusCode::UNAUTHORIZED,
            OAuthError::ServerError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::BAD_REQUEST,
        }
    }
}

/// token / userinfo endpoint 用の JSON エラー描画。
/// authorize の redirect エラーは authorize handler 側で組み立てる。
impl IntoResponse for OAuthError {
    fn into_response(self) -> Response {
        let body = Json(serde_json::json!({
            "error": self.code(),
            "error_description": self.description(),
        }));
        (self.status(), body).into_response()
    }
}
