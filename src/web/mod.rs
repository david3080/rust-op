//! HTTP レイヤ。axum で各エンドポイントを provider のレジストリに配線する。

use crate::client_auth::ClientAuthInput;
use crate::context::AuthContext;
use crate::error::OAuthError;
use crate::model::{AuthParams, AuthorizationCode, Interaction, Session};
use crate::provider::Provider;
use axum::extract::{Form, Path, Query, RawQuery, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

mod ciba;
mod login;
mod oidc;
mod pages;
mod register;

const SID_COOKIE: &str = "sid";

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

pub fn router(provider: Provider) -> Router {
    let base_path = provider.base_path.clone();
    // FIDO2 Conformance 用エンドポイントは base_path に依らずトップレベル /fido/* に置く。
    let fido = crate::fido::router(Arc::new(crate::fido::FidoState::from_env()));
    let shared = Arc::new(provider);
    let mut inner = Router::new()
        .route("/.well-known/openid-configuration", get(oidc::discovery))
        .route("/jwks", get(oidc::jwks))
        .route("/authorize", get(oidc::authorize))
        .route("/authorize/resume", get(oidc::authorize_resume))
        .route("/interaction/{uid}", get(login::login_form))
        .route("/interaction/{uid}/login", post(login::login_submit))
        .route("/interaction/{uid}/passkey/options", post(login::login_passkey_options))
        .route("/interaction/{uid}/passkey/verify", post(login::login_passkey_verify))
        .route("/token", post(oidc::token))
        .route("/introspect", post(oidc::introspect))
        .route("/end-session", get(oidc::end_session))
        .route("/par", post(oidc::par))
        .route("/userinfo", get(oidc::userinfo_get).post(oidc::userinfo_post))
        .route("/profile", get(oidc::profile_get).put(oidc::profile_put))
        // CIBA
        .route("/backchannel-authentication", post(ciba::backchannel_auth))
        .route("/ciba", get(ciba::ciba_pending))
        .route("/ciba/pending", get(ciba::ciba_pending_list))
        .route("/me/fcm-tokens", post(ciba::fcm_token_register))
        .route("/ciba/{auth_req_id}/passkey-options", post(ciba::ciba_approve_options))
        .route("/ciba/{auth_req_id}/approve", post(ciba::ciba_approve))
        .route("/ciba/{auth_req_id}/reject", post(ciba::ciba_reject))
        // メール確認つきユーザー登録（Web HTML フロー + ネイティブ JSON API）。
        .route("/register", get(register::register_form).post(register::register_submit))
        .route("/register/verify", get(register::verify_form))
        .route("/register/email-challenge", post(register::register_email_challenge))
        .route("/register/verify-email", post(register::register_verify_email))
        .route("/register/passkey/options", post(register::register_passkey_options))
        .route("/register/passkey/verify", post(register::register_passkey_verify))
        // ブラウザで完結する RP デモ。
        .route("/", get(pages::demo_start))
        .route("/callback", get(pages::demo_callback));

    // CIBA Consumption デモ（Web だけで CIBA を体験）。無認証で FCM push を誘発でき、
    // 承認後に email/profile を無認証ポーラへ返すため、本番では既定で無効。
    // デモ時のみ環境変数 CIBA_DEMO_ENABLED=1 で有効化する。
    if std::env::var("CIBA_DEMO_ENABLED").map(|v| v == "1" || v == "true").unwrap_or(false) {
        inner = inner
            .route("/ciba-demo", get(ciba::ciba_demo_page))
            .route("/ciba-demo/start", post(ciba::ciba_demo_start))
            .route("/ciba-demo/poll", get(ciba::ciba_demo_poll));
    }
    let inner = inner.with_state(shared.clone());

    // メールリンク /r はトップレベル（base_path 非依存、AASA の paths と一致）。
    let magic = Router::new()
        .route("/r", get(register::magic_redirect))
        .route(
            "/.well-known/apple-app-site-association",
            get(register::apple_app_site_association),
        )
        .with_state(shared);

    if base_path.is_empty() {
        inner.merge(fido).merge(magic).fallback(log_unmatched)
    } else {
        // ドメイン直下 `/` と末尾スラッシュ `/oidc/` を `/oidc`（サインイン画面）へ寄せる。
        // nest 配下では `/oidc/` が catch-all に一致せず 404 になるため明示リダイレクトする。
        let t_root = base_path.clone();
        let t_slash = base_path.clone();
        Router::new()
            .route(
                "/",
                get(move || {
                    let t = t_root.clone();
                    async move { Redirect::temporary(&t) }
                }),
            )
            .route(
                &format!("{base_path}/"),
                get(move || {
                    let t = t_slash.clone();
                    async move { Redirect::temporary(&t) }
                }),
            )
            .nest(&base_path, inner)
            .merge(fido)
            .merge(magic)
    }
}

/// 未マッチのリクエストをログする（MDS3 等が叩く未実装パスの特定用）。
async fn log_unmatched(method: axum::http::Method, uri: axum::http::Uri) -> impl IntoResponse {
    tracing::info!("UNMATCHED {} {}", method, uri);
    (StatusCode::NOT_FOUND, "not found")
}

fn plain_error(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, msg.to_string()).into_response()
}

/* ===== interaction (login) ===== */

/// b64url <-> ArrayBuffer のブラウザ側ヘルパー（passkey ページ共通）。
const WEBAUTHN_JS: &str = r##"
function b64ToBuf(b){b=b.replace(/-/g,'+').replace(/_/g,'/');while(b.length%4)b+='=';const s=atob(b);const a=new Uint8Array(s.length);for(let i=0;i<s.length;i++)a[i]=s.charCodeAt(i);return a.buffer;}
function bufToB64(buf){const a=new Uint8Array(buf);let s='';for(let i=0;i<a.length;i++)s+=String.fromCharCode(a[i]);return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
"##;

#[derive(serde::Deserialize)]
pub(super) struct AuthResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
    signature: String,
    #[serde(default, rename = "userHandle")]
    user_handle: Option<String>,
}

#[derive(serde::Deserialize)]
pub(super) struct AuthVerifyReq {
    id: String,
    response: AuthResponse,
}

fn dpop_header(headers: &HeaderMap) -> Option<String> {
    // RFC 9449 §4.3: DPoP ヘッダは 1 リクエストに高々 1 つ。複数あれば不正なので
    // 「使用可能な proof 無し」として None を返し、各 endpoint で拒否させる。
    let mut it = headers.get_all("dpop").iter();
    let first = it.next()?;
    if it.next().is_some() {
        return None;
    }
    first.to_str().ok().map(|s| s.to_string())
}

fn parse_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let h = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = h.strip_prefix("Basic ")?;
    let decoded = B64.decode(b64).ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (id, secret) = s.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

/* ===== CIBA ===== */

/// confidential クライアント認証（token/backchannel 共通）。
async fn authenticate_client(
    p: &Provider,
    headers: &HeaderMap,
    form: &HashMap<String, String>,
) -> Result<crate::model::Client, Response> {
    let basic = parse_basic_auth(headers);
    let assertion_is_jwt = form
        .get("client_assertion_type")
        .map(|s| s.contains("jwt-bearer"))
        .unwrap_or(false);
    let method = if assertion_is_jwt {
        "private_key_jwt"
    } else if basic.is_some() {
        "client_secret_basic"
    } else if form.contains_key("client_secret") {
        "client_secret_post"
    } else {
        "none"
    };
    let input = ClientAuthInput {
        basic,
        body_client_id: form.get("client_id").cloned(),
        body_client_secret: form.get("client_secret").cloned(),
        client_assertion: form.get("client_assertion").cloned(),
    };
    let auth = p
        .client_auth
        .get(method)
        .ok_or_else(|| OAuthError::InvalidClient("unsupported auth method".into()).into_response())?;
    auth.authenticate(p, &input).await.map_err(|e| e.into_response())
}

/* ===== userinfo ===== */

/// Authorization ヘッダから (scheme, token) を取り出す（Bearer / DPoP）。
fn auth_scheme_token(headers: &HeaderMap) -> Option<(String, String)> {
    let h = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    // RFC 7235: 認証スキーム名は case-insensitive。スキーム正規化して返す。
    let (scheme, rest) = h.split_once(' ')?;
    if scheme.eq_ignore_ascii_case("bearer") {
        return Some(("Bearer".into(), rest.trim().to_string()));
    }
    if scheme.eq_ignore_ascii_case("dpop") {
        return Some(("DPoP".into(), rest.trim().to_string()));
    }
    None
}

/// Bearer/DPoP の access token を検証して返す。失敗時はエラー Response。
/// path_suffix は DPoP htu 構築用（例 "/userinfo", "/profile"）。
async fn authenticate_token(
    p: &Provider,
    headers: &HeaderMap,
    method: &str,
    path_suffix: &str,
    body_token: Option<String>,
) -> Result<crate::model::AccessToken, Response> {
    let (scheme, token) = match auth_scheme_token(headers) {
        Some(x) => x,
        None => match body_token {
            Some(t) => ("Bearer".into(), t),
            None => {
                return Err((StatusCode::UNAUTHORIZED, "access token required").into_response())
            }
        },
    };
    let at = match p.store.get_access_token(&token).await {
        Some(at) => at,
        None => {
            tracing::warn!("token auth failed [{method} {path_suffix}]: invalid/expired token");
            return Err((StatusCode::UNAUTHORIZED, "invalid token").into_response());
        }
    };
    // DPoP 束縛トークンは DPoP scheme + proof（jkt 一致 / ath 一致）を要求。
    if let Some(jkt) = &at.jkt {
        if scheme != "DPoP" {
            tracing::warn!("token auth failed [{path_suffix}]: DPoP scheme required (got {scheme})");
            return Err((StatusCode::UNAUTHORIZED, "DPoP scheme required").into_response());
        }
        let proof = match dpop_header(headers) {
            Some(p) => p,
            None => {
                tracing::warn!("token auth failed [{path_suffix}]: DPoP proof missing or duplicated");
                return Err((StatusCode::UNAUTHORIZED, "DPoP proof required").into_response());
            }
        };
        let htu = format!("{}{}", p.issuer, path_suffix);
        let want_ath = crate::dpop::ath(&token);
        match p.dpop.verify(&proof, method, &htu, Some(&want_ath)) {
            Ok(got) if &got == jkt => {}
            Ok(_) => {
                tracing::warn!("token auth failed [{path_suffix}]: DPoP jkt mismatch (token bound to different key)");
                return Err((StatusCode::UNAUTHORIZED, "DPoP jkt mismatch").into_response());
            }
            Err(e) => {
                tracing::warn!("token auth failed [{path_suffix}]: DPoP proof invalid: {e}");
                return Err((StatusCode::UNAUTHORIZED, format!("DPoP: {e}")).into_response());
            }
        }
    }
    Ok(at)
}

