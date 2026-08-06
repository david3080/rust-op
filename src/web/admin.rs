use super::*;

/// ログイン済セッションが管理者か確認する。未ログインは 401、非管理者は 403、
/// Firestore 未接続（ローカル既定構成）は 503 で fail-closed にする。
pub(super) async fn require_admin(p: &Provider, jar: &CookieJar) -> Result<String, Response> {
    let account_id = session_account(p, jar)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "login required").into_response())?;
    let fs = p
        .firestore
        .as_ref()
        .ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "admin console unavailable").into_response())?;
    match crate::admin_store::is_admin(fs, &account_id).await {
        Ok(true) => Ok(account_id),
        Ok(false) => Err((StatusCode::FORBIDDEN, "admin only").into_response()),
        Err(e) => {
            tracing::error!("require_admin: is_admin check failed for {account_id}: {e}");
            Err((StatusCode::SERVICE_UNAVAILABLE, "admin check failed").into_response())
        }
    }
}

/// 疎通確認用: 自分が管理者として認識されているかを返す。今後の管理画面ルートの雛形。
pub(super) async fn whoami(State(p): State<Arc<Provider>>, jar: CookieJar) -> Response {
    match require_admin(&p, &jar).await {
        Ok(account_id) => Json(serde_json::json!({ "account_id": account_id })).into_response(),
        Err(r) => r,
    }
}
