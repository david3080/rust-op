//! 認可レスポンスの返し方。node-oidc-provider の `response_modes/*` 相当。
//! form_post / fragment / jwt を足す時はこの trait に impl を増やす。

use axum::response::{IntoResponse, Redirect, Response};

pub trait ResponseMode: Send + Sync {
    fn name(&self) -> &'static str;
    /// redirect_uri に params を載せて返す Response を組み立てる。
    fn build(&self, redirect_uri: &str, params: &[(String, String)]) -> Response;
}

/// response_mode = query（authorization code flow の既定）。
pub struct QueryMode;
impl ResponseMode for QueryMode {
    fn name(&self) -> &'static str {
        "query"
    }
    fn build(&self, redirect_uri: &str, params: &[(String, String)]) -> Response {
        let qs = serde_urlencoded::to_string(params).unwrap_or_default();
        let sep = if redirect_uri.contains('?') { '&' } else { '?' };
        Redirect::to(&format!("{redirect_uri}{sep}{qs}")).into_response()
    }
}
