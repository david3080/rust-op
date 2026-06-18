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
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::Instrument;
use uuid::Uuid;

mod ciba;
mod login;
mod oidc;
mod pages;
mod register;

const SID_COOKIE: &str = "sid";

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// FIDO2 Conformance 用の /fido/* エンドポイントを公開するか。テスト専用。
/// 本番（環境変数未設定）では無効化し、攻撃面（本番の実フローに非接続なテスト面）を排除する。
/// FIDO2 Conformance を回すときだけ FIDO_CONFORMANCE_ENABLED=1 で有効化する。
fn fido_conformance_enabled() -> bool {
    matches!(
        std::env::var("FIDO_CONFORMANCE_ENABLED").as_deref(),
        Ok("1") | Ok("true")
    )
}

pub fn router(provider: Provider) -> Router {
    let base_path = provider.base_path.clone();
    // FIDO2 Conformance 用エンドポイントは base_path に依らずトップレベル /fido/* に置く。
    // テスト専用面（本番の実 passkey フローは /signup・/login・/ciba 側）なので、
    // 本番（FIDO_CONFORMANCE_ENABLED 未設定）では空 Router にしてマウントしない＝攻撃面を排除。
    let fido = if fido_conformance_enabled() {
        crate::fido::router(Arc::new(crate::fido::FidoState::from_env()))
    } else {
        Router::new()
    };
    let shared = Arc::new(provider);
    let inner = Router::new()
        .route("/.well-known/openid-configuration", get(oidc::discovery))
        .route("/jwks", get(oidc::jwks))
        .route("/authorize", get(oidc::authorize))
        .route("/authorize/resume", get(oidc::authorize_resume))
        .route("/login/{uid}", get(login::login_form))
        .route("/login/{uid}/cancel", get(oidc::authorize_cancel))
        .route("/login/{uid}/passkey/options", post(login::login_passkey_options))
        .route("/login/{uid}/passkey/verify", post(login::login_passkey_verify))
        .route("/token", post(oidc::token))
        .route("/introspect", post(oidc::introspect))
        .route("/oauth/mandate/consume", post(oidc::mandate_consume))
        .route("/oauth/register", post(oidc::register))
        .route("/revoke", post(oidc::revoke))
        .route("/end-session", get(oidc::end_session))
        .route("/par", post(oidc::par))
        .route("/userinfo", get(oidc::userinfo_get).post(oidc::userinfo_post))
        .route("/me/profile", get(oidc::profile_get).put(oidc::profile_put))
        // CIBA
        .route("/backchannel-authentication", post(ciba::backchannel_auth))
        .route("/ciba", get(ciba::ciba_pending))
        .route("/ciba/pending", get(ciba::ciba_pending_list))
        .route("/ciba/history", get(ciba::ciba_history))
        .route("/ciba/fcm-tokens", post(ciba::fcm_token_register))
        .route("/ciba/{auth_req_id}/passkey-options", post(ciba::ciba_approve_options))
        .route("/ciba/{auth_req_id}/approve", post(ciba::ciba_approve))
        .route("/ciba/{auth_req_id}/reject", post(ciba::ciba_reject))
        // メール確認つきユーザー登録（Web HTML フロー + ネイティブ JSON API）。
        // OAuth の「クライアント登録(DCR)」と区別するため /signup/* に置く。
        .route("/signup", get(register::register_form).post(register::register_submit))
        .route("/signup/verify", get(register::verify_form))
        .route("/signup/email-challenge", post(register::register_email_challenge))
        .route("/signup/verify-email", post(register::register_verify_email))
        .route("/signup/passkey/options", post(register::register_passkey_options))
        .route("/signup/passkey/verify", post(register::register_passkey_verify))
        // ブラウザで完結する RP デモ。
        .route("/", get(pages::demo_start))
        .route("/callback", get(pages::demo_callback));

    let inner = inner.with_state(shared.clone());

    // メールリンク /r はトップレベル（base_path 非依存、AASA の paths と一致）。
    let magic = Router::new()
        .route("/r", get(register::magic_redirect))
        .route(
            "/.well-known/apple-app-site-association",
            get(register::apple_app_site_association),
        )
        .with_state(shared);

    let app = if base_path.is_empty() {
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
    };
    // 全リクエストに request_id を付与し、構造化ログを相関させる（ZT Observability Foundation）。
    app.layer(axum::middleware::from_fn(request_trace))
}

/// リクエスト相関ミドルウェア（L4 Observability の Foundation 層）:
/// request_id を採番（または健全な inbound `X-Request-Id` を踏襲）し、span でハンドラを囲んで
/// 既存のドメインログ（`event=token_issued` 等）に request_id を継承させる。応答後に
/// method/path/status/latency を1行記録し、応答ヘッダにも request_id を返す。
///
/// 秘密はログに出さない: **query を含めず path のみ**（query には code 等が乗りうる）、
/// ヘッダ・ボディ・Authorization・DPoP proof・トークン類は一切記録しない。
async fn request_trace(req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string(); // query は付けない（秘密が乗りうる）
    // inbound の X-Request-Id は健全（短い ASCII 図形文字のみ）な場合だけ踏襲。ログ注入を防ぐ。
    let rid = req
        .headers()
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .filter(|s| (1..=200).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_graphic()))
        .map(str::to_owned)
        .unwrap_or_else(|| Uuid::new_v4().to_string());

    let span = tracing::info_span!("http", request_id = %rid);
    let start = Instant::now();
    let mut resp = next.run(req).instrument(span).await;

    tracing::info!(
        event = "http_request",
        request_id = %rid,
        method = %method,
        path = %path,
        status = resp.status().as_u16(),
        latency_ms = start.elapsed().as_millis() as u64,
    );
    if let Ok(v) = axum::http::HeaderValue::from_str(&rid) {
        resp.headers_mut().insert("x-request-id", v);
    }
    resp
}

/// ログ用の sub 擬似化（ZT output-control）。平文 PII（メール）をログに出さず、subject ごとに
/// **安定な相関トークン**（`h:` 接頭辞付き）を返す。`LOG_PSEUDONYM_KEY` が設定されていれば salt として
/// 混ぜ、オフライン推測に耐える。未設定なら平文 SHA256（PII 平文は消えるが、メール空間は列挙可能ゆえ
/// 推測耐性は弱い）。incident 時の逆引きは salt＋候補ハッシュ照合か別の安全な対応表で行う。
pub(crate) fn pseudonymize_sub(sub: &str) -> String {
    let salt = std::env::var("LOG_PSEUDONYM_KEY").unwrap_or_default();
    let digest = Sha256::digest(format!("{salt}\0{sub}").as_bytes());
    format!("h:{}", &crate::es256::b64url_encode(digest)[..16])
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

/// X-Forwarded-For の先頭 IP（Cloud Run の前段が付与）。無ければ "unknown"。
/// 注意: 先頭値はクライアント申告で詐称可能。レート制限の弱いキーにしかならない
/// （素朴な単一 IP からの連発を抑える backstop。詐称ローテーションには無力）。
pub(super) fn client_ip(headers: &HeaderMap) -> String {
    headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
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
    } else {
        "none"
    };
    let input = ClientAuthInput {
        basic,
        body_client_id: form.get("client_id").cloned(),
        client_assertion: form.get("client_assertion").cloned(),
    };
    let auth = p
        .client_auth
        .get(method)
        .ok_or_else(|| OAuthError::InvalidClient("unsupported auth method".into()).into_response())?;
    auth.authenticate(p, &input).await.map_err(|e| {
        tracing::warn!(event = "client_auth_failed", method = method);
        e.into_response()
    })
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
/// path_suffix は DPoP htu 構築用（例 "/userinfo", "/me/profile"）。
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
        match p.dpop.verify(&proof, method, &htu, Some(&want_ath)).await {
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

#[cfg(test)]
mod obs_tests {
    use std::io;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct VecWriter(Arc<Mutex<Vec<u8>>>);
    impl io::Write for VecWriter {
        fn write(&mut self, b: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for VecWriter {
        type Writer = VecWriter;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    /// `request_trace` の肝＝span の request_id が、span 内で出る既存ドメインログ
    /// （`event=token_issued` 等）に**継承される**ことを、本番と同じ `fmt().json()` 構成で確認する。
    /// これは型検査では分からず subscriber 構成依存（http_request 行は明示フィールドなので常に出るが、
    /// 相関先のドメインログが span 継承で出るかは別問題）なので、ここで明示的に検証する。
    #[test]
    fn request_id_span_field_propagates_to_domain_logs() {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(VecWriter(buf.clone()))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("http", request_id = "RID-TEST-123");
            let _g = span.enter();
            tracing::info!(event = "token_issued"); // 既存ドメインログ相当
        });
        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(
            out.contains("RID-TEST-123"),
            "span の request_id がドメインログに継承される必要がある: {out}"
        );
        assert!(out.contains("token_issued"));
    }

    /// sub 擬似化: 同じ sub は安定、異なる sub は別、生メールを含まない。
    #[test]
    fn pseudonymize_sub_is_stable_and_not_plaintext() {
        let a = super::pseudonymize_sub("david3080@gmail.com");
        let b = super::pseudonymize_sub("david3080@gmail.com");
        let c = super::pseudonymize_sub("other@example.com");
        assert_eq!(a, b, "同じ sub は安定な相関トークン");
        assert_ne!(a, c, "異なる sub は異なる");
        assert!(!a.contains("david3080") && !a.contains('@'), "生メールを含まない: {a}");
        assert!(a.starts_with("h:"), "擬似化マーカー h: 付き: {a}");
    }
}

