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
use axum_extra::extract::cookie::{Cookie, CookieJar};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const SID_COOKIE: &str = "sid";

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

pub fn router(provider: Provider) -> Router {
    let base_path = provider.base_path.clone();
    // FIDO2 Conformance 用エンドポイントは base_path に依らずトップレベル /fido/* に置く。
    let fido = crate::fido::router(Arc::new(crate::fido::FidoState::from_env()));
    let shared = Arc::new(provider);
    let inner = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/authorize", get(authorize))
        .route("/authorize/resume", get(authorize_resume))
        .route("/interaction/{uid}", get(login_form))
        .route("/interaction/{uid}/login", post(login_submit))
        .route("/interaction/{uid}/passkey/options", post(login_passkey_options))
        .route("/interaction/{uid}/passkey/verify", post(login_passkey_verify))
        .route("/token", post(token))
        .route("/end-session", get(end_session))
        .route("/par", post(par))
        .route("/userinfo", get(userinfo_get).post(userinfo_post))
        .route("/profile", get(profile_get).put(profile_put))
        // CIBA
        .route("/backchannel-authentication", post(backchannel_auth))
        .route("/ciba", get(ciba_pending))
        .route("/ciba/pending", get(ciba_pending_list))
        .route("/me/fcm-tokens", post(fcm_token_register))
        .route("/ciba/{auth_req_id}/passkey-options", post(ciba_approve_options))
        .route("/ciba/{auth_req_id}/approve", post(ciba_approve))
        .route("/ciba/{auth_req_id}/reject", post(ciba_reject))
        // CIBA Consumption デモ（Web だけで CIBA を体験）。
        .route("/ciba-demo", get(ciba_demo_page))
        .route("/ciba-demo/start", post(ciba_demo_start))
        .route("/ciba-demo/poll", get(ciba_demo_poll))
        // メール確認つきユーザー登録（Web HTML フロー + ネイティブ JSON API）。
        .route("/register", get(register_form).post(register_submit))
        .route("/register/verify", get(verify_form))
        .route("/register/email-challenge", post(register_email_challenge))
        .route("/register/verify-email", post(register_verify_email))
        .route("/register/passkey/options", post(register_passkey_options))
        .route("/register/passkey/verify", post(register_passkey_verify))
        // ブラウザで完結する RP デモ。
        .route("/", get(demo_start))
        .route("/callback", get(demo_callback))
        .with_state(shared.clone());

    // メールリンク /r はトップレベル（base_path 非依存、AASA の paths と一致）。
    let magic = Router::new()
        .route("/r", get(magic_redirect))
        .route(
            "/.well-known/apple-app-site-association",
            get(apple_app_site_association),
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

/* ===== discovery / jwks ===== */

async fn discovery(State(p): State<Arc<Provider>>) -> Json<serde_json::Value> {
    let i = &p.issuer;
    Json(serde_json::json!({
        "issuer": i,
        "authorization_endpoint": format!("{i}/authorize"),
        "token_endpoint": format!("{i}/token"),
        "userinfo_endpoint": format!("{i}/userinfo"),
        "jwks_uri": format!("{i}/jwks"),
        "response_types_supported": ["code"],
        "grant_types_supported": p.grants.keys().collect::<Vec<_>>(),
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": [p.signer.alg()],
        "scopes_supported": ["openid", "profile", "email", "address", "phone", "offline_access"],
        "claims_supported": crate::claims::all_supported_claims(),
        "claims_parameter_supported": false,
        "acr_values_supported": ["0", "1", "urn:mace:incommon:iap:bronze"],
        "token_endpoint_auth_methods_supported": p.client_auth.keys().collect::<Vec<_>>(),
        "code_challenge_methods_supported": ["S256"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
        "pushed_authorization_request_endpoint": format!("{i}/par"),
        "end_session_endpoint": format!("{i}/end-session"),
        "authorization_response_iss_parameter_supported": true,
        "backchannel_authentication_endpoint": format!("{i}/backchannel-authentication"),
        "backchannel_token_delivery_modes_supported": ["poll"],
        "backchannel_user_code_parameter_supported": false,
    }))
}

async fn jwks(State(p): State<Arc<Provider>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({ "keys": [p.signer.public_jwk()] }))
}

/* ===== authorize ===== */

async fn authorize(
    State(p): State<Arc<Provider>>,
    jar: CookieJar,
    RawQuery(raw): RawQuery,
) -> Response {
    let raw = raw.unwrap_or_default();
    // JAR は非対応。inline `request` と非 PAR の `request_uri` は run_checks 後に拒否する
    // (client/redirect_uri を解決してから redirect エラーで返すため)。
    let q0: HashMap<String, String> = serde_urlencoded::from_str(&raw).unwrap_or_default();
    let has_request_param = q0.contains_key("request");
    let has_nonpar_request_uri = q0
        .get("request_uri")
        .map(|u| !u.starts_with(crate::par::URN_PREFIX))
        .unwrap_or(false);
    // PAR: urn 形式の request_uri があれば保存済みパラメータを復元する。
    let mut par_used = false;
    let raw = match q0.get("request_uri") {
        Some(request_uri) if request_uri.starts_with(crate::par::URN_PREFIX) => {
            let fs = match &p.firestore {
                Some(fs) => fs,
                None => return plain_error("PAR unavailable (no Firestore)"),
            };
            match crate::par::consume(fs, request_uri).await {
                Ok(Some((_cid, params))) => {
                    par_used = true;
                    params
                }
                _ => return plain_error("invalid or expired request_uri"),
            }
        }
        _ => raw,
    };
    let params: AuthParams = match serde_urlencoded::from_str(&raw) {
        Ok(p) => p,
        Err(e) => return plain_error(&format!("invalid query: {e}")),
    };
    let mut ctx = AuthContext::new(params);

    if let Err(e) = run_checks(&p, &mut ctx).await {
        return authorize_error(&p, &ctx, e);
    }
    // JAR は非対応（discovery で request_parameter_supported を公告していない）。
    if has_request_param {
        return authorize_error(
            &p,
            &ctx,
            OAuthError::RequestNotSupported("request object (JAR) is not supported".into()),
        );
    }
    if has_nonpar_request_uri {
        return authorize_error(
            &p,
            &ctx,
            OAuthError::RequestUriNotSupported("request_uri is not supported".into()),
        );
    }
    // FAPI: PAR 必須クライアントが request_uri 経由でないなら拒否。
    if ctx.client().require_par && !par_used {
        return authorize_error(
            &p,
            &ctx,
            OAuthError::InvalidRequest("pushed authorization request required".into()),
        );
    }

    // prompt / max_age を解釈して「セッションで進む / 再ログイン / エラー」を判定。
    let session = match jar.get(SID_COOKIE).map(|c| c.value().to_string()) {
        Some(sid) => p.store.get_session(&sid).await,
        None => None,
    };
    match crate::interaction_policy::decide(&ctx.params, session.as_ref(), now()) {
        crate::interaction_policy::AuthDecision::UseSession { account_id, auth_time } => {
            ctx.account_id = Some(account_id);
            ctx.auth_time = Some(auth_time);
            return issue_code(&p, &ctx).await;
        }
        crate::interaction_policy::AuthDecision::Error(e) => {
            return authorize_error(&p, &ctx, e);
        }
        crate::interaction_policy::AuthDecision::Login => { /* fall through to interaction */ }
    }

    // 未ログイン or 再認証要求 → interaction を作って login 画面へ。
    let uid = uuid::Uuid::new_v4().to_string();
    p.store
        .save_interaction(Interaction {
            uid: uid.clone(),
            raw_query: raw,
            account_id: None,
            auth_time: None,
        })
        .await;
    Redirect::to(&p.path(&format!("/interaction/{uid}"))).into_response()
}

async fn authorize_resume(
    State(p): State<Arc<Provider>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let uid = match q.get("uid") {
        Some(u) => u,
        None => return plain_error("uid required"),
    };
    let interaction = match p.store.get_interaction(uid).await {
        Some(i) => i,
        None => return plain_error("interaction not found"),
    };
    let account_id = match interaction.account_id {
        Some(a) => a,
        None => return plain_error("interaction not completed"),
    };

    let params: AuthParams = match serde_urlencoded::from_str(&interaction.raw_query) {
        Ok(p) => p,
        Err(e) => return plain_error(&format!("invalid stored query: {e}")),
    };
    let mut ctx = AuthContext::new(params);
    if let Err(e) = run_checks(&p, &mut ctx).await {
        return authorize_error(&p, &ctx, e);
    }
    ctx.account_id = Some(account_id);
    ctx.auth_time = interaction.auth_time;
    issue_code(&p, &ctx).await
}

async fn run_checks(p: &Provider, ctx: &mut AuthContext) -> Result<(), OAuthError> {
    for check in &p.checks {
        check.check(p, ctx).await?;
    }
    Ok(())
}

/// 検証通過後、認可コードを発行して redirect_uri に返す。
async fn issue_code(p: &Provider, ctx: &AuthContext) -> Response {
    let redirect_uri = ctx.redirect_uri.clone().expect("redirect validated");
    let account_id = ctx.account_id.clone().expect("account present");
    let code = uuid::Uuid::new_v4().simple().to_string();
    p.store
        .save_code(AuthorizationCode {
            code: code.clone(),
            client_id: ctx.client().client_id.clone(),
            account_id,
            redirect_uri: redirect_uri.clone(),
            scope: ctx.params.scope.clone().unwrap_or_default(),
            nonce: ctx.params.nonce.clone(),
            code_challenge: ctx.params.code_challenge.clone(),
            code_challenge_method: ctx.params.code_challenge_method.clone(),
            auth_time: ctx.auth_time.unwrap_or_else(now),
            // 要求された acr_values の先頭を、満たした acr として返す（PoC）。
            acr: ctx
                .params
                .acr_values
                .as_deref()
                .and_then(|s| s.split_whitespace().next())
                .map(|s| s.to_string()),
            expires_at: now() + 60,
        })
        .await;

    let mut out = vec![("code".to_string(), code)];
    if let Some(state) = &ctx.params.state {
        out.push(("state".to_string(), state.clone()));
    }
    // RFC 9207: 認可レスポンスに issuer を付与（FAPI 2.0 必須）。
    out.push(("iss".to_string(), p.issuer.clone()));
    let mode = ctx
        .params
        .response_mode
        .as_deref()
        .and_then(|m| p.response_modes.get(m))
        .unwrap_or_else(|| p.response_modes.get("query").unwrap());
    mode.build(&redirect_uri, &out)
}

/// redirect_uri が確定していれば error を redirect で返す、なければ直接表示。
fn authorize_error(p: &Provider, ctx: &AuthContext, e: OAuthError) -> Response {
    if let Some(ru) = &ctx.redirect_uri {
        let mut out = vec![
            ("error".to_string(), e.code().to_string()),
            ("error_description".to_string(), e.description()),
            ("iss".to_string(), p.issuer.clone()),
        ];
        if let Some(state) = &ctx.params.state {
            out.push(("state".to_string(), state.clone()));
        }
        let qs = serde_urlencoded::to_string(&out).unwrap_or_default();
        let sep = if ru.contains('?') { '&' } else { '?' };
        Redirect::to(&format!("{ru}{sep}{qs}")).into_response()
    } else {
        plain_error(&format!("{}: {}", e.code(), e.description()))
    }
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

async fn login_form(State(p): State<Arc<Provider>>, Path(uid): Path<String>) -> Html<String> {
    let body = r##"<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>ログイン</title>
<style>
:root{--indigo:#3f51b5;--indigo-d:#303f9f}
body{font-family:Roboto,-apple-system,'Helvetica Neue',sans-serif;max-width:360px;margin:0 auto;padding:56px 24px;color:#1a1a1a;text-align:center}
.fp{width:72px;height:72px;color:var(--indigo)}
h1{font-size:1.3rem;font-weight:500;margin:18px 0 28px}
input{display:block;width:100%;box-sizing:border-box;padding:14px;margin:0 0 16px;font-size:16px;border:1px solid #b0b0b0;border-radius:8px}
.filled{width:100%;padding:14px;font-size:16px;font-weight:500;background:var(--indigo);color:#fff;border:0;border-radius:24px;cursor:pointer}
.filled:active{background:var(--indigo-d)}
.outlined{width:100%;padding:12px;font-size:16px;font-weight:500;background:#fff;color:var(--indigo);border:1.5px solid var(--indigo);border-radius:24px;margin-top:12px;cursor:pointer}
#msg{color:#c5221f;font-size:14px;margin-top:14px;min-height:1em}
details{margin-top:36px;color:#9a9a9a;font-size:13px;text-align:left}
summary{cursor:pointer}
details input{font-size:14px;padding:8px;margin-top:8px}</style>
</head><body>
<svg class="fp" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
<path d="M5.5 10a6.5 6.5 0 0 1 13 0v4a8 8 0 0 1-1 3.8"/>
<path d="M8 11a4 4 0 0 1 8 0v3a6 6 0 0 0 .8 3"/>
<path d="M12 11v4a7 7 0 0 0 1.4 4.3"/>
<path d="M12 19v.01"/></svg>
<h1>Passkey でサインイン</h1>
<input id="email" placeholder="メールアドレス（任意）" autocomplete="off">
<button class="filled" onclick="pkLogin()">サインイン</button>
<button class="outlined" onclick="location.href='__REGISTER__'">新規登録 (メアドで)</button>
<p id="msg"></p>
<details><summary>パスワード (テスト用)</summary>
<form method="post" action="__LOGIN__">
<input name="username" placeholder="email"><input name="password" type="password" placeholder="password">
<button class="filled" type="submit" style="margin-top:8px">ログイン</button></form></details>
<script>
__WEBAUTHN_JS__
const OPT="__OPT__",VER="__VER__";
const msgEl=document.getElementById('msg');
// discoverable のモーダル方式のみ。allowCredentials 空で OS の passkey ピッカーに
// 全候補を出して選ばせる。Conditional UI(autofill) は自動起動しない。
// 理由: アプリ webview(ASWebAuthenticationSession)内では autofill が「最近使った1件」
// だけを勝手に提示して紛らわしいため(TS 版も同方針)。userHandle でユーザー解決。
let cachedOpts=null;
async function prefetch(){
  try{const r=await fetch(OPT,{method:'POST',headers:{'content-type':'application/json'},body:'{}'});cachedOpts=r.ok?await r.json():null;}
  catch{cachedOpts=null;}
}
prefetch();
async function pkLogin(){
 msgEl.textContent='';
 if(!window.PublicKeyCredential){msgEl.textContent='このブラウザは passkey 非対応です（標準の Safari / Chrome アプリで開いてください）。';return;}
 try{
  let o=cachedOpts;
  if(!o){const r=await fetch(OPT,{method:'POST',headers:{'content-type':'application/json'},body:'{}'});if(!r.ok){msgEl.textContent=await r.text();return;}o=await r.json();}
  const cred=await navigator.credentials.get({publicKey:{challenge:b64ToBuf(o.challenge),rpId:o.rpId,timeout:o.timeout,userVerification:o.userVerification,allowCredentials:[]}});
  cachedOpts=null;prefetch();
  const body={id:cred.id,response:{clientDataJSON:bufToB64(cred.response.clientDataJSON),authenticatorData:bufToB64(cred.response.authenticatorData),signature:bufToB64(cred.response.signature),userHandle:cred.response.userHandle?bufToB64(cred.response.userHandle):null}};
  const v=await fetch(VER,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
  if(!v.ok){msgEl.textContent=await v.text();return;}
  location.href=(await v.json()).redirect;
 }catch(e){
  if(e.name==='NotAllowedError'){
   msgEl.textContent='passkey を起動できませんでした。標準の Safari / Chrome アプリで開いてください（アプリ内ブラウザでは使えません）。';
  }else{msgEl.textContent=(e.name||'')+': '+(e.message||String(e));}
 }
}
</script></body></html>"##;
    Html(
        body.replace("__WEBAUTHN_JS__", WEBAUTHN_JS)
            .replace("__OPT__", &p.path(&format!("/interaction/{uid}/passkey/options")))
            .replace("__VER__", &p.path(&format!("/interaction/{uid}/passkey/verify")))
            .replace("__LOGIN__", &p.path(&format!("/interaction/{uid}/login")))
            .replace("__REGISTER__", &p.path("/register")),
    )
}

#[derive(serde::Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

async fn login_submit(
    State(p): State<Arc<Provider>>,
    jar: CookieJar,
    Path(uid): Path<String>,
    Form(form): Form<LoginForm>,
) -> Response {
    // conformance/demo 用の固定資格情報バイパス（a/a）。実ユーザーは passkey を使う。
    let raw = form.username.trim();
    if !(raw == p.demo_user && form.password == p.demo_pass) {
        return (StatusCode::UNAUTHORIZED, "invalid credentials").into_response();
    }
    let interaction = match p.store.get_interaction(&uid).await {
        Some(i) => i,
        None => return plain_error("interaction not found"),
    };
    let account = p.store.find_account(&p.demo_user).await;
    let (jar, resume) = finalize_login(&p, jar, interaction, account.sub).await;
    (jar, Redirect::to(&resume)).into_response()
}

/// ログイン確定: interaction にアカウントを書き、SSO セッション cookie を張り、resume パスを返す。
async fn finalize_login(
    p: &Provider,
    jar: CookieJar,
    mut interaction: Interaction,
    account_sub: String,
) -> (CookieJar, String) {
    let auth_time = now();
    let uid = interaction.uid.clone();
    interaction.account_id = Some(account_sub.clone());
    interaction.auth_time = Some(auth_time);
    p.store.save_interaction(interaction).await;
    let sid = uuid::Uuid::new_v4().to_string();
    p.store
        .save_session(Session { sid: sid.clone(), account_id: account_sub, auth_time })
        .await;
    let cookie = Cookie::build((SID_COOKIE, sid)).path("/").http_only(true).build();
    (jar.add(cookie), p.path(&format!("/authorize/resume?uid={uid}")))
}

/* ===== passkey ログイン ===== */

#[derive(serde::Deserialize)]
struct LoginPkOptionsReq {
    #[serde(default)]
    email: String,
}

async fn login_passkey_options(
    State(p): State<Arc<Provider>>,
    Path(uid): Path<String>,
    Json(req): Json<LoginPkOptionsReq>,
) -> Response {
    let fs = match &p.firestore {
        Some(fs) => fs,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let email = req.email.trim().to_lowercase();
    // email 指定があり credential があれば allowCredentials を絞る。無指定/未登録なら
    // discoverable（allowCredentials 空）＝OS の passkey ピッカーに全候補を出す。
    // discoverable のときは verify 時に assertion の userHandle でユーザーを解決する。
    let (allow, chal_email) = if email.is_empty() {
        (serde_json::json!([]), String::new())
    } else {
        match crate::registration::get_credential(fs, &email).await {
            Ok(Some(c)) => (
                serde_json::json!([{ "type": "public-key", "id": c.credential_id, "transports": ["internal", "hybrid"] }]),
                email.clone(),
            ),
            _ => (serde_json::json!([]), String::new()),
        }
    };
    let challenge = match crate::registration::create_webauthn_challenge(fs, &chal_email, crate::registration::ChallengeKind::Auth, &uid).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("create challenge: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
        }
    };
    Json(serde_json::json!({
        "challenge": challenge,
        "rpId": p.rp_id(),
        "timeout": 60000,
        "userVerification": "preferred",
        "allowCredentials": allow,
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
struct AuthResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "authenticatorData")]
    authenticator_data: String,
    signature: String,
    #[serde(default, rename = "userHandle")]
    user_handle: Option<String>,
}

#[derive(serde::Deserialize)]
struct AuthVerifyReq {
    id: String,
    response: AuthResponse,
}

async fn login_passkey_verify(
    State(p): State<Arc<Provider>>,
    jar: CookieJar,
    Path(uid): Path<String>,
    Json(req): Json<AuthVerifyReq>,
) -> Response {
    let fs = match &p.firestore {
        Some(fs) => fs,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let challenge = match crate::webauthn::extract_challenge(&req.response.client_data_json) {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "no challenge").into_response(),
    };
    let (email, kind, uid2) = match crate::registration::consume_webauthn_challenge(fs, &challenge).await {
        Ok(Some(t)) => t,
        Ok(None) => return (StatusCode::BAD_REQUEST, "challenge invalid/expired").into_response(),
        Err(e) => {
            tracing::error!("consume challenge: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
        }
    };
    if kind != crate::registration::ChallengeKind::Auth || uid2 != uid {
        return (StatusCode::BAD_REQUEST, "challenge context mismatch").into_response();
    }
    // discoverable（challenge の email が空）なら assertion の userHandle で解決。
    // userHandle = registration 時の user.id = base64url(email)。
    let email = req
        .response
        .user_handle
        .as_deref()
        .filter(|s| !s.is_empty())
        .and_then(|uh| crate::es256::b64url_decode(uh).ok())
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or(email);
    if email.is_empty() {
        return (StatusCode::BAD_REQUEST, "cannot resolve user").into_response();
    }
    let cred = match crate::registration::get_credential(fs, &email).await {
        Ok(Some(c)) => c,
        _ => return (StatusCode::BAD_REQUEST, "credential not found").into_response(),
    };
    if cred.credential_id != req.id {
        return (StatusCode::BAD_REQUEST, "credential id mismatch").into_response();
    }
    let origin = p.origin();
    let rp_id = p.rp_id();
    match crate::webauthn::verify_authentication(
        &req.response.client_data_json,
        &req.response.authenticator_data,
        &req.response.signature,
        &challenge,
        &origin,
        &rp_id,
        &cred.pub_x,
        &cred.pub_y,
        cred.sign_count,
    ) {
        Ok(new_count) => {
            let _ = crate::registration::update_sign_count(fs, &email, new_count).await;
        }
        Err(e) => {
            tracing::warn!("webauthn auth failed: {e}");
            return (StatusCode::UNAUTHORIZED, format!("passkey verify failed: {e}")).into_response();
        }
    }
    let interaction = match p.store.get_interaction(&uid).await {
        Some(i) => i,
        None => return (StatusCode::BAD_REQUEST, "interaction not found").into_response(),
    };
    let account = p.store.find_account(&email).await;
    let (jar, resume) = finalize_login(&p, jar, interaction, account.sub).await;
    (jar, Json(serde_json::json!({ "redirect": resume }))).into_response()
}

/* ===== token ===== */

async fn token(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let grant_type = match form.get("grant_type") {
        Some(g) => g.clone(),
        None => return OAuthError::InvalidRequest("grant_type required".into()).into_response(),
    };
    let grant = match p.grants.get(&grant_type) {
        Some(g) => g,
        None => return OAuthError::UnsupportedGrantType(grant_type).into_response(),
    };

    // クライアント認証。提示された材料で方式を選ぶ。
    let client = match authenticate_client(&p, &headers, &form).await {
        Ok(c) => c,
        Err(r) => return r,
    };

    if !client.allows_grant(&grant_type) {
        return OAuthError::UnauthorizedClient(format!("grant {grant_type} not allowed"))
            .into_response();
    }

    // DPoP: proof があれば検証して jkt を得る。client が dpop_bound なら必須。
    let dpop_jkt = match dpop_header(&headers) {
        Some(proof) => {
            let htu = format!("{}/token", p.issuer);
            match p.dpop.verify(&proof, "POST", &htu, None) {
                Ok(jkt) => Some(jkt),
                Err(e) => return OAuthError::InvalidDpopProof(e).into_response(),
            }
        }
        None if client.dpop_bound => {
            return OAuthError::InvalidDpopProof("DPoP proof required".into()).into_response();
        }
        None => None,
    };

    match grant.handle(&p, &client, &form, dpop_jkt).await {
        Ok(resp) => ([(header::CACHE_CONTROL, "no-store")], Json(resp)).into_response(),
        Err(e) => e.into_response(),
    }
}

fn dpop_header(headers: &HeaderMap) -> Option<String> {
    headers
        .get("dpop")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string())
}

fn parse_basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let h = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let b64 = h.strip_prefix("Basic ")?;
    let decoded = B64.decode(b64).ok()?;
    let s = String::from_utf8(decoded).ok()?;
    let (id, secret) = s.split_once(':')?;
    Some((id.to_string(), secret.to_string()))
}

/* ===== メール確認つきユーザー登録 ===== */

fn page(title: &str, body: &str) -> Html<String> {
    Html(format!(
        r#"<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title>
<style>body{{font-family:-apple-system,sans-serif;max-width:400px;margin:48px auto;padding:0 16px;line-height:1.7}}
input{{display:block;width:100%;box-sizing:border-box;padding:10px;margin:8px 0;font-size:16px}}
button{{width:100%;padding:12px;font-size:16px;background:#3367d6;color:#fff;border:0;border-radius:6px}}</style>
</head><body>{body}</body></html>"#
    ))
}

async fn register_form(State(p): State<Arc<Provider>>) -> Html<String> {
    let action = p.path("/register");
    page(
        "登録",
        &format!(
            r#"<h1>ユーザー登録</h1><p>メールアドレスに確認リンクを送ります。</p>
<form method="post" action="{action}">
<input name="email" type="email" placeholder="email" autocomplete="email" autofocus>
<button type="submit">確認メールを送信</button></form>"#
        ),
    )
}

#[derive(serde::Deserialize)]
struct RegisterForm {
    email: String,
}

/// メール確認チャレンジを作り確認メールを送る。Web フォーム/ネイティブ JSON 共通。
/// 列挙対策で既登録/未登録に関わらず例外を出さない。メール URL は custom scheme
/// 経由でアプリにも着地できる /r?t= 形式（PC では /r が HTML を返す）。
async fn issue_register_email(
    p: &Provider,
    fs: &crate::firestore::Firestore,
    email: &str,
) -> Result<(), String> {
    if !email.contains('@') || email.len() > 254 {
        return Err("invalid email".into());
    }
    match crate::registration::account_exists(fs, email).await? {
        true => {
            let _ = p.mailer.send_already_registered(email).await;
        }
        false => {
            let token = crate::registration::create_email_challenge(fs, email).await?;
            let url = format!("{}/r?t={}", p.origin(), token);
            if let Err(e) = p.mailer.send_verification(email, &url).await {
                tracing::error!("send_verification failed: {e}");
            }
        }
    }
    Ok(())
}

async fn register_submit(
    State(p): State<Arc<Provider>>,
    Form(form): Form<RegisterForm>,
) -> Response {
    let email = form.email.trim().to_lowercase();
    let fs = match &p.firestore {
        Some(fs) => fs,
        None => return plain_error("registration not available (no Firestore)"),
    };
    match issue_register_email(&p, fs, &email).await {
        Ok(()) => page(
            "送信しました",
            "<h1>確認メールを送信しました</h1><p>メール内のリンクから passkey を作成して登録を完了してください（有効期限15分）。</p>",
        )
        .into_response(),
        Err(e) if e == "invalid email" => plain_error("invalid email"),
        Err(e) => {
            tracing::error!("register_submit: {e}");
            plain_error("internal error")
        }
    }
}

/* ネイティブアプリ向け JSON 登録 API（Web の HTML フローと同じ Firestore を共有） */

#[derive(serde::Deserialize)]
struct EmailChallengeReq {
    email: String,
}

async fn register_email_challenge(
    State(p): State<Arc<Provider>>,
    Json(req): Json<EmailChallengeReq>,
) -> Response {
    let email = req.email.trim().to_lowercase();
    let fs = match &p.firestore {
        Some(fs) => fs,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    match issue_register_email(&p, fs, &email).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) if e == "invalid email" => (StatusCode::BAD_REQUEST, "invalid email").into_response(),
        Err(e) => {
            tracing::error!("email-challenge: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response()
        }
    }
}

#[derive(serde::Deserialize)]
struct VerifyEmailReq {
    token: String,
}

/// メール確認 token を検証して email を返す（token は消費せず passkey-verify で消費）。
async fn register_verify_email(
    State(p): State<Arc<Provider>>,
    Json(req): Json<VerifyEmailReq>,
) -> Response {
    let fs = match &p.firestore {
        Some(fs) => fs,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    match crate::registration::peek_email_challenge(fs, &req.token).await {
        Ok(Some(email)) => match crate::registration::account_exists(fs, &email).await {
            Ok(true) => (StatusCode::CONFLICT, "already registered").into_response(),
            _ => Json(serde_json::json!({ "email": email, "verified_token": req.token }))
                .into_response(),
        },
        Ok(None) => (StatusCode::BAD_REQUEST, "invalid or expired token").into_response(),
        Err(e) => {
            tracing::error!("verify-email: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response()
        }
    }
}

/// passkey 作成（ブラウザ）ページ。メールリンク /r と /register/verify で共用。
/// iPhone は AASA(Universal Link)でアプリが横取りするため通常この HTML は出ず、
/// PC/Mac やアプリ未対応端末ではこのページでブラウザ passkey 登録を完結できる。
fn passkey_register_page(p: &Provider, token: &str) -> Html<String> {
    let token: String = token
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    let body = r##"<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>passkey 登録</title>
<style>body{font-family:-apple-system,sans-serif;max-width:360px;margin:48px auto;padding:0 16px}
button{width:100%;padding:12px;font-size:16px;background:#3367d6;color:#fff;border:0;border-radius:6px}
#msg{font-size:14px}.applink{display:block;margin-top:20px;font-size:13px;text-align:center}</style></head><body>
<h1>passkey を作成</h1>
<p>このデバイスの生体認証等で passkey を作成し、登録を完了します。</p>
<button onclick="reg()">passkey を作成して登録</button>
<p id="msg"></p>
<a class="applink" href="jp.co.sonrisa.fido2demo://r?t=__TOKEN__">iPhone アプリで続ける</a>
<script>
__WEBAUTHN_JS__
const TOKEN="__TOKEN__",OPT="__OPT__",VER="__VER__",LOGIN="__LOGIN__";
async function reg(){
 const msg=document.getElementById('msg');msg.textContent='処理中…';
 try{
  const r=await fetch(OPT,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({token:TOKEN})});
  if(!r.ok){msg.textContent=await r.text();return;}
  const o=await r.json();
  const cred=await navigator.credentials.create({publicKey:{challenge:b64ToBuf(o.challenge),rp:o.rp,user:{id:b64ToBuf(o.user.id),name:o.user.name,displayName:o.user.displayName},pubKeyCredParams:o.pubKeyCredParams,authenticatorSelection:o.authenticatorSelection,attestation:o.attestation,timeout:o.timeout,excludeCredentials:(o.excludeCredentials||[]).map(c=>({type:'public-key',id:b64ToBuf(c.id)}))}});
  const body={token:TOKEN,response:{clientDataJSON:bufToB64(cred.response.clientDataJSON),attestationObject:bufToB64(cred.response.attestationObject)}};
  const v=await fetch(VER,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
  if(!v.ok){msg.textContent=await v.text();return;}
  msg.innerHTML='登録が完了しました。<a href="'+LOGIN+'">ログインへ</a>';
 }catch(e){msg.textContent=e.message;}
}
</script></body></html>"##;
    Html(
        body.replace("__WEBAUTHN_JS__", WEBAUTHN_JS)
            .replace("__TOKEN__", &token)
            .replace("__OPT__", &p.path("/register/passkey/options"))
            .replace("__VER__", &p.path("/register/passkey/verify"))
            .replace("__LOGIN__", &p.path("/")),
    )
}

/// メールリンク /r?t= の着地。iPhone は AASA でアプリ起動、PC/Mac はブラウザ登録。
#[derive(serde::Deserialize)]
struct MagicQuery {
    t: String,
}

async fn magic_redirect(State(p): State<Arc<Provider>>, Query(q): Query<MagicQuery>) -> Html<String> {
    passkey_register_page(&p, &q.t)
}

/// oidc.sonrisa.co.jp は Cloud Run へ直結（Firebase Hosting を経由しない）ため AASA を
/// ここで返す。applinks=Universal Link(/r でアプリ起動)、webcredentials=ネイティブ passkey。
async fn apple_app_site_association() -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"applinks":{"apps":[],"details":[{"appID":"RA5A5W7PJB.jp.co.sonrisa.fido2demo","paths":["/r","/r?*"]}]},"webcredentials":{"apps":["RA5A5W7PJB.jp.co.sonrisa.fido2demo"]}}"#,
    )
        .into_response()
}

#[derive(serde::Deserialize)]
struct VerifyQuery {
    token: String,
}

/// Web フォーム経由（/register/verify?token=）の着地点。
async fn verify_form(State(p): State<Arc<Provider>>, Query(q): Query<VerifyQuery>) -> Html<String> {
    passkey_register_page(&p, &q.token)
}

#[derive(serde::Deserialize)]
struct RegPkOptionsReq {
    token: String,
}

async fn register_passkey_options(
    State(p): State<Arc<Provider>>,
    Json(req): Json<RegPkOptionsReq>,
) -> Response {
    let fs = match &p.firestore {
        Some(fs) => fs,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let email = match crate::registration::peek_email_challenge(fs, &req.token).await {
        Ok(Some(e)) => e,
        Ok(None) => return (StatusCode::BAD_REQUEST, "invalid or expired token").into_response(),
        Err(e) => {
            tracing::error!("peek token: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
        }
    };
    let challenge = match crate::registration::create_webauthn_challenge(fs, &email, crate::registration::ChallengeKind::Reg, "").await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("create challenge: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
        }
    };
    let exclude: Vec<serde_json::Value> = match crate::registration::get_credential(fs, &email).await {
        Ok(Some(c)) => vec![serde_json::json!({"type":"public-key","id":c.credential_id})],
        _ => vec![],
    };
    Json(serde_json::json!({
        "challenge": challenge,
        "rp": { "id": p.rp_id(), "name": "rust-op" },
        "user": {
            "id": crate::webauthn::b64e(email.as_bytes()),
            "name": email,
            "displayName": email,
        },
        "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
        "authenticatorSelection": { "residentKey": "preferred", "userVerification": "preferred" },
        "attestation": "none",
        "timeout": 60000,
        "excludeCredentials": exclude,
    }))
    .into_response()
}

#[derive(serde::Deserialize)]
struct RegResponse {
    #[serde(rename = "clientDataJSON")]
    client_data_json: String,
    #[serde(rename = "attestationObject")]
    attestation_object: String,
}

#[derive(serde::Deserialize)]
struct RegVerifyReq {
    token: String,
    response: RegResponse,
}

async fn register_passkey_verify(
    State(p): State<Arc<Provider>>,
    Json(req): Json<RegVerifyReq>,
) -> Response {
    let fs = match &p.firestore {
        Some(fs) => fs,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let email1 = match crate::registration::consume_email_challenge(fs, &req.token).await {
        Ok(Some(e)) => e,
        Ok(None) => return (StatusCode::BAD_REQUEST, "invalid or expired token").into_response(),
        Err(e) => {
            tracing::error!("consume email token: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
        }
    };
    let challenge = match crate::webauthn::extract_challenge(&req.response.client_data_json) {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "no challenge").into_response(),
    };
    let (email2, kind, _) = match crate::registration::consume_webauthn_challenge(fs, &challenge).await {
        Ok(Some(t)) => t,
        Ok(None) => return (StatusCode::BAD_REQUEST, "challenge invalid/expired").into_response(),
        Err(e) => {
            tracing::error!("consume webauthn challenge: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
        }
    };
    if kind != crate::registration::ChallengeKind::Reg || email2 != email1 {
        return (StatusCode::BAD_REQUEST, "challenge context mismatch").into_response();
    }
    let outcome = match crate::webauthn::verify_registration(
        &req.response.client_data_json,
        &req.response.attestation_object,
        &challenge,
        &p.origin(),
        &p.rp_id(),
    ) {
        Ok(o) => o,
        Err(e) => {
            tracing::warn!("webauthn reg failed: {e}");
            return (StatusCode::BAD_REQUEST, format!("registration failed: {e}")).into_response();
        }
    };
    if let Err(e) = crate::registration::save_credential(fs, &email1, &outcome).await {
        tracing::error!("save_credential: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
    }
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "ok": true, "redirect": p.path("/") })),
    )
        .into_response()
}

/* ===== RP-Initiated Logout (OpenID Connect RP-Initiated Logout 1.0) ===== */

#[derive(serde::Deserialize)]
struct EndSessionQuery {
    id_token_hint: Option<String>,
    post_logout_redirect_uri: Option<String>,
    state: Option<String>,
    client_id: Option<String>,
}

/// JWT(検証なし)の aud を取り出して client を特定する補助。
fn jwt_aud(jwt: &str) -> Option<String> {
    let payload = jwt.split('.').nth(1)?;
    let bytes = crate::es256::b64url_decode(payload).ok()?;
    let v: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    match v.get("aud")? {
        serde_json::Value::String(s) => Some(s.clone()),
        serde_json::Value::Array(a) => a.first().and_then(|x| x.as_str()).map(|s| s.to_string()),
        _ => None,
    }
}

async fn end_session(
    State(p): State<Arc<Provider>>,
    jar: CookieJar,
    Query(q): Query<EndSessionQuery>,
) -> Response {
    // OP セッション破棄（cookie + ストア）。即ログアウト（確認画面なし）。
    if let Some(sid) = jar.get(SID_COOKIE).map(|c| c.value().to_string()) {
        p.store.delete_session(&sid).await;
    }
    let jar = jar.remove(Cookie::build((SID_COOKIE, "")).path("/").build());

    // post_logout_redirect_uri は client 登録値のみ許可（オープンリダイレクト防止）。
    let client_id = q
        .client_id
        .clone()
        .or_else(|| q.id_token_hint.as_deref().and_then(jwt_aud));

    if let Some(uri) = &q.post_logout_redirect_uri {
        let registered = client_id
            .as_deref()
            .and_then(|id| p.clients.get(id))
            .map(|c| c.post_logout_redirect_uris.iter().any(|u| u == uri))
            .unwrap_or(false);
        if !registered {
            return (jar, plain_error("post_logout_redirect_uri not registered")).into_response();
        }
        let mut target = uri.clone();
        if let Some(state) = &q.state {
            let sep = if target.contains('?') { '&' } else { '?' };
            let qs = serde_urlencoded::to_string([("state", state)]).unwrap_or_default();
            target = format!("{target}{sep}{qs}");
        }
        return (jar, Redirect::to(&target)).into_response();
    }

    // リダイレクト先指定なし → 完了ページ。
    let home = p.path("/");
    let html = format!(
        r##"<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>ログアウト</title>
<style>body{{font-family:Roboto,-apple-system,sans-serif;max-width:360px;margin:0 auto;padding:80px 24px;text-align:center;color:#1a1a1a}}
a{{color:#3f51b5}}</style></head><body>
<h1 style="font-size:1.3rem;font-weight:500">ログアウトしました</h1>
<p><a href="{home}">サインインへ</a></p></body></html>"##
    );
    (jar, Html(html)).into_response()
}

/* ===== PAR (RFC 9126) ===== */

async fn par(State(p): State<Arc<Provider>>, headers: HeaderMap, body: String) -> Response {
    let fs = match &p.firestore {
        Some(f) => f,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let form: HashMap<String, String> = serde_urlencoded::from_str(&body).unwrap_or_default();
    let client = match authenticate_client(&p, &headers, &form).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    // PAR 本体の client_id は認証済みクライアントと一致すること。
    if let Some(cid) = form.get("client_id") {
        if cid != &client.client_id {
            return OAuthError::InvalidRequest("client_id mismatch".into()).into_response();
        }
    }
    match crate::par::create(fs, &client.client_id, &body).await {
        Ok(ru) => (
            StatusCode::CREATED,
            [(header::CACHE_CONTROL, "no-store")],
            Json(serde_json::json!({ "request_uri": ru.0, "expires_in": 60 })),
        )
            .into_response(),
        Err(e) => {
            tracing::error!("par create: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response()
        }
    }
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

async fn session_account(p: &Provider, jar: &CookieJar) -> Option<String> {
    let sid = jar.get(SID_COOKIE)?.value().to_string();
    p.store.get_session(&sid).await.map(|s| s.account_id)
}

/// CIBA 操作の主体を特定。access token(Bearer/DPoP)を優先し、無ければ session cookie。
/// access token = プロフィール画面/ネイティブアプリ、cookie = /oidc/ciba HTML 用。
/// path_suffix は DPoP htu 構築用（呼び出し側が auth_req_id 込みで渡す）。
async fn ciba_actor(
    p: &Provider,
    headers: &HeaderMap,
    jar: &CookieJar,
    method: &str,
    path_suffix: &str,
) -> Option<String> {
    if let Ok(at) = authenticate_token(p, headers, method, path_suffix, None).await {
        return Some(at.account_id);
    }
    session_account(p, jar).await
}

/// プロフィール画面のポーリング用: 自分宛の pending CIBA 依頼一覧（access token 認証）。
async fn ciba_pending_list(State(p): State<Arc<Provider>>, headers: HeaderMap) -> Response {
    let at = match authenticate_token(&p, &headers, "GET", "/ciba/pending", None).await {
        Ok(at) => at,
        Err(r) => return r,
    };
    let fs = match &p.firestore {
        Some(f) => f,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let pending = crate::ciba::list_pending(fs, &at.account_id).await.unwrap_or_default();
    let items: Vec<serde_json::Value> = pending
        .iter()
        .map(|r| {
            serde_json::json!({
                "auth_req_id": r.auth_req_id.as_str(),
                "client_id": r.client_id,
                "scope": r.scope,
                "binding_message": r.binding_message,
            })
        })
        .collect();
    Json(items).into_response()
}

#[derive(serde::Deserialize)]
struct FcmTokenReq {
    token: String,
    platform: Option<String>,
}

/// ネイティブアプリの FCM token を登録（access token 認証）。CIBA 通知の宛先になる。
async fn fcm_token_register(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    Json(req): Json<FcmTokenReq>,
) -> Response {
    let at = match authenticate_token(&p, &headers, "POST", "/me/fcm-tokens", None).await {
        Ok(at) => at,
        Err(r) => return r,
    };
    let fs = match &p.firestore {
        Some(f) => f,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    match crate::fcm::save_token(fs, &at.account_id, &req.token, req.platform.as_deref().unwrap_or("ios")).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            tracing::error!("fcm save_token: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response()
        }
    }
}

const CIBA_GRANT: &str = "urn:openid:params:grant-type:ciba";

/// バックチャネル認証要求（Consumption Device が叩く）。
async fn backchannel_auth(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let fs = match &p.firestore {
        Some(f) => f,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let client = match authenticate_client(&p, &headers, &form).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if !client.allows_grant(CIBA_GRANT) {
        return OAuthError::UnauthorizedClient("ciba grant not allowed".into()).into_response();
    }
    let login_hint = match form.get("login_hint") {
        Some(s) => s.trim().to_lowercase(),
        None => return OAuthError::InvalidRequest("login_hint required".into()).into_response(),
    };
    let scope = form.get("scope").cloned().unwrap_or_else(|| "openid".into());
    if !scope.split_whitespace().any(|s| s == "openid") {
        return OAuthError::InvalidScope("openid scope required".into()).into_response();
    }
    let binding = form.get("binding_message").cloned().unwrap_or_default();
    // login_hint は passkey 登録済みアカウントであること（未登録は即拒否）。
    match crate::registration::get_credential(fs, &login_hint).await {
        Ok(Some(_)) => {}
        Ok(None) => return OAuthError::InvalidRequest("unknown user_id".into()).into_response(),
        Err(e) => {
            tracing::error!("get_credential: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
        }
    }
    match crate::ciba::create(fs, &client.client_id, &login_hint, &scope, &binding).await {
        Ok(id) => {
            // FCM で iPhone に承認要求を通知（Cloud Run suspend を避けるため await）。
            // token 未登録/送信失敗でも Web 承認は可能なのでベストエフォート。
            let _ = crate::fcm::send_ciba_request(fs, &login_hint, &client.client_id, &scope, &binding, id.as_str()).await;
            (
                [(header::CACHE_CONTROL, "no-store")],
                Json(serde_json::json!({ "auth_req_id": id.0, "expires_in": 300, "interval": 2 })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("ciba create: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response()
        }
    }
}

/// 承認 UI: ログイン済セッションが自分宛の pending 要求を承認/拒否する。
async fn ciba_pending(State(p): State<Arc<Provider>>, jar: CookieJar) -> Response {
    let fs = match &p.firestore {
        Some(f) => f,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let account = match session_account(&p, &jar).await {
        Some(a) => a,
        None => {
            return Html(format!(
                "<p>承認するにはログインが必要です。<a href=\"{}\">ログイン</a></p>",
                p.path("/")
            ))
            .into_response()
        }
    };
    let pending = crate::ciba::list_pending(fs, &account).await.unwrap_or_default();
    let esc = |s: &str| s.replace('&', "&amp;").replace('<', "&lt;").replace('"', "&quot;");
    let rows: String = pending
        .iter()
        .map(|r| {
            format!(
                "<div class=row><div><b>{}</b><br><small>scope: {}</small></div>\
<button onclick=\"approve('{}')\">承認 (passkey)</button> \
<button class=rej onclick=\"reject('{}')\">拒否</button></div>",
                esc(if r.binding_message.is_empty() { "(no binding message)" } else { &r.binding_message }),
                esc(&r.scope),
                esc(r.auth_req_id.as_str()),
                esc(r.auth_req_id.as_str()),
            )
        })
        .collect();
    let body = r##"<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>CIBA 承認</title>
<style>body{font-family:-apple-system,sans-serif;max-width:480px;margin:32px auto;padding:0 16px}
.row{border:1px solid #ddd;border-radius:8px;padding:12px;margin:12px 0}
button{padding:8px 14px;font-size:15px;background:#3367d6;color:#fff;border:0;border-radius:6px;margin-top:8px}
button.rej{background:#999}#msg{color:#c00}</style></head><body>
<h1>CIBA 承認</h1>
<div id="msg"></div>
__ROWS__
<script>
__WEBAUTHN_JS__
const B="__BASE__";
async function approve(id){
 const msg=document.getElementById('msg');msg.textContent='';window.__busy=true;
 try{
  const r=await fetch(B+'/ciba/'+id+'/passkey-options',{method:'POST',headers:{'content-type':'application/json'},body:'{}'});
  if(!r.ok){msg.textContent=await r.text();window.__busy=false;return;}
  const o=await r.json();
  const cred=await navigator.credentials.get({publicKey:{challenge:b64ToBuf(o.challenge),rpId:o.rpId,timeout:o.timeout,userVerification:'required',allowCredentials:(o.allowCredentials||[]).map(c=>({type:'public-key',id:b64ToBuf(c.id),transports:c.transports}))}});
  const body={id:cred.id,response:{clientDataJSON:bufToB64(cred.response.clientDataJSON),authenticatorData:bufToB64(cred.response.authenticatorData),signature:bufToB64(cred.response.signature)}};
  const v=await fetch(B+'/ciba/'+id+'/approve',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});
  if(!v.ok){msg.textContent=await v.text();window.__busy=false;return;}
  location.reload();
 }catch(e){msg.textContent=e.message;window.__busy=false;}
}
async function reject(id){
 window.__busy=true;
 await fetch(B+'/ciba/'+id+'/reject',{method:'POST'});
 location.reload();
}
// 新着の承認依頼を自動表示（FCM の代わりのポーリング）。承認/拒否操作中は止める。
setInterval(()=>{if(!window.__busy)location.reload();},4000);
</script></body></html>"##;
    Html(
        body.replace("__ROWS__", if rows.is_empty() { "<p>保留中の要求はありません。</p>" } else { &rows })
            .replace("__WEBAUTHN_JS__", WEBAUTHN_JS)
            .replace("__BASE__", &p.base_path),
    )
    .into_response()
}

async fn ciba_approve_options(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(auth_req_id): Path<String>,
) -> Response {
    let fs = match &p.firestore {
        Some(f) => f,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let suffix = format!("/ciba/{auth_req_id}/passkey-options");
    let account = match ciba_actor(&p, &headers, &jar, "POST", &suffix).await {
        Some(a) => a,
        None => return (StatusCode::UNAUTHORIZED, "login required").into_response(),
    };
    let req = match crate::ciba::get(fs, &auth_req_id).await {
        Ok(Some(r)) if r.account == account && !r.expired() => r,
        _ => return (StatusCode::NOT_FOUND, "request not found").into_response(),
    };
    let cred = match crate::registration::get_credential(fs, &req.account).await {
        Ok(Some(c)) => c,
        _ => return (StatusCode::BAD_REQUEST, "no passkey").into_response(),
    };
    let challenge = match crate::registration::create_webauthn_challenge(
        fs,
        &req.account,
        crate::registration::ChallengeKind::CibaApprove,
        &auth_req_id,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("create challenge: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
        }
    };
    Json(serde_json::json!({
        "challenge": challenge,
        "rpId": p.rp_id(),
        "timeout": 60000,
        "allowCredentials": [{ "type": "public-key", "id": cred.credential_id, "transports": ["internal", "hybrid"] }],
    }))
    .into_response()
}

async fn ciba_approve(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(auth_req_id): Path<String>,
    Json(req): Json<AuthVerifyReq>,
) -> Response {
    let fs = match &p.firestore {
        Some(f) => f,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let suffix = format!("/ciba/{auth_req_id}/approve");
    let account = match ciba_actor(&p, &headers, &jar, "POST", &suffix).await {
        Some(a) => a,
        None => return (StatusCode::UNAUTHORIZED, "login required").into_response(),
    };
    let challenge = match crate::webauthn::extract_challenge(&req.response.client_data_json) {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "no challenge").into_response(),
    };
    let (email, kind, uid) = match crate::registration::consume_webauthn_challenge(fs, &challenge).await {
        Ok(Some(t)) => t,
        _ => return (StatusCode::BAD_REQUEST, "challenge invalid/expired").into_response(),
    };
    if kind != crate::registration::ChallengeKind::CibaApprove || uid != auth_req_id || email != account {
        return (StatusCode::BAD_REQUEST, "challenge context mismatch").into_response();
    }
    let ciba_req = match crate::ciba::get(fs, &auth_req_id).await {
        Ok(Some(r)) if r.account == account && !r.expired() => r,
        _ => return (StatusCode::NOT_FOUND, "request not found").into_response(),
    };
    let cred = match crate::registration::get_credential(fs, &account).await {
        Ok(Some(c)) => c,
        _ => return (StatusCode::BAD_REQUEST, "no passkey").into_response(),
    };
    if cred.credential_id != req.id {
        return (StatusCode::BAD_REQUEST, "credential id mismatch").into_response();
    }
    match crate::webauthn::verify_authentication(
        &req.response.client_data_json,
        &req.response.authenticator_data,
        &req.response.signature,
        &challenge,
        &p.origin(),
        &p.rp_id(),
        &cred.pub_x,
        &cred.pub_y,
        cred.sign_count,
    ) {
        Ok(n) => {
            let _ = crate::registration::update_sign_count(fs, &account, n).await;
        }
        Err(e) => return (StatusCode::UNAUTHORIZED, format!("passkey verify failed: {e}")).into_response(),
    }
    let _ = ciba_req; // 検証済み。承認に進む。
    if let Err(e) = crate::ciba::set_status(fs, &auth_req_id, crate::ciba::CibaStatus::Approved).await {
        tracing::error!("set_status: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
    }
    Json(serde_json::json!({ "ok": true })).into_response()
}

async fn ciba_reject(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    jar: CookieJar,
    Path(auth_req_id): Path<String>,
) -> Response {
    let fs = match &p.firestore {
        Some(f) => f,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let suffix = format!("/ciba/{auth_req_id}/reject");
    let account = match ciba_actor(&p, &headers, &jar, "POST", &suffix).await {
        Some(a) => a,
        None => return (StatusCode::UNAUTHORIZED, "login required").into_response(),
    };
    match crate::ciba::get(fs, &auth_req_id).await {
        Ok(Some(r)) if r.account == account => {}
        _ => return (StatusCode::NOT_FOUND, "request not found").into_response(),
    }
    let _ = crate::ciba::set_status(fs, &auth_req_id, crate::ciba::CibaStatus::Denied).await;
    StatusCode::NO_CONTENT.into_response()
}

/* ===== CIBA Consumption デモ（FCM 無しで Web だけで CIBA を体験する） =====
   ブラウザA: /oidc/ciba-demo で login_hint 入力 → start で ciba-rp として要求発行 →
   poll で承認待ち。ブラウザB(ログイン済み): /oidc/ciba で依頼を passkey 承認。 */

#[derive(serde::Deserialize)]
struct CibaDemoStartReq {
    login_hint: String,
}

/// ciba-rp として backchannel 要求を発行（デモなのでクライアント認証は省略）。
async fn ciba_demo_start(State(p): State<Arc<Provider>>, Json(req): Json<CibaDemoStartReq>) -> Response {
    let fs = match &p.firestore {
        Some(f) => f,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let login_hint = req.login_hint.trim().to_lowercase();
    match crate::registration::get_credential(fs, &login_hint).await {
        Ok(Some(_)) => {}
        Ok(None) => return (StatusCode::BAD_REQUEST, "未登録のユーザーです").into_response(),
        Err(e) => {
            tracing::error!("ciba-demo get_credential: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
        }
    }
    let binding = "Web CIBA デモのログインを承認してください";
    match crate::ciba::create(fs, "ciba-rp", &login_hint, "openid", binding).await {
        Ok(id) => {
            let _ = crate::fcm::send_ciba_request(fs, &login_hint, "ciba-rp", "openid", binding, id.as_str()).await;
            Json(serde_json::json!({ "auth_req_id": id.0 })).into_response()
        }
        Err(e) => {
            tracing::error!("ciba-demo create: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response()
        }
    }
}

#[derive(serde::Deserialize)]
struct CibaDemoPollReq {
    auth_req_id: String,
}

async fn ciba_demo_poll(State(p): State<Arc<Provider>>, Query(q): Query<CibaDemoPollReq>) -> Response {
    let fs = match &p.firestore {
        Some(f) => f,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let req = match crate::ciba::get(fs, &q.auth_req_id).await {
        Ok(Some(r)) => r,
        _ => return (StatusCode::NOT_FOUND, "not found").into_response(),
    };
    let status = match req.status {
        crate::ciba::CibaStatus::Pending => "pending",
        crate::ciba::CibaStatus::Approved => "approved",
        crate::ciba::CibaStatus::Denied => "denied",
    };
    let mut body = serde_json::json!({ "status": status });
    // 承認済み = CIBA ログイン成功。同一ページに表示する claims を返す（sub=email、
    // profile は保存済みのみ）。デモのため実トークン発行は省略している。
    if matches!(req.status, crate::ciba::CibaStatus::Approved) {
        let profile = crate::registration::get_profile(fs, &req.account)
            .await
            .unwrap_or_default();
        body["email"] = serde_json::json!(req.account);
        body["profile"] = serde_json::json!(profile);
    }
    Json(body).into_response()
}

async fn ciba_demo_page(State(p): State<Arc<Provider>>) -> Html<String> {
    let body = r##"<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>CIBA デモ (Consumption)</title>
<style>body{font-family:-apple-system,sans-serif;max-width:420px;margin:40px auto;padding:0 16px;color:#222}
input{width:100%;padding:10px;font-size:15px;box-sizing:border-box;margin:8px 0}
button{width:100%;padding:12px;font-size:16px;background:#3367d6;color:#fff;border:0;border-radius:6px}
#st{margin-top:16px;font-size:15px}.ok{color:#137333}.ng{color:#c5221f}
.card{border:1px solid #00000022;border-radius:10px;padding:12px 14px;margin:10px 0}
.lbl{font-size:.8rem;color:#3f51b5;font-weight:600;margin-bottom:4px}.val{font-size:1.05rem}.unset{color:#aaa}
.email{color:#00000088;margin:2px 0 16px}</style></head><body>
<div id="form">
<h1>CIBA ログイン要求 (Consumption Device)</h1>
<p>このブラウザを「ログインしたい端末」に見立てます。承認は別ブラウザ/タブの
<a href="__CIBA__">承認画面</a>（ログイン済み）で行います。</p>
<input id="hint" type="email" placeholder="ログインするメールアドレス" autocomplete="username">
<button id="go" onclick="start()">ログイン要求を送る</button>
<div id="st"></div>
</div>
<div id="out"></div>
<script>
const STARTU="__START__",POLLU="__POLL__";
let timer=null;
function esc(s){return String(s).replace(/[<>&]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));}
const GENDER={male:'男性',female:'女性',other:'その他'};
function field(label,val){return '<div class="card"><div class="lbl">'+label+'</div><div class="val">'+(val?esc(val):'<span class="unset">未設定</span>')+'</div></div>';}
function showProfile(d){
 sessionStorage.setItem('ciba_demo',JSON.stringify(d)); // リロードしても表示継続
 const p=d.profile||{};
 document.getElementById('form').style.display='none';
 document.getElementById('out').innerHTML=
  '<h1>ログイン成功</h1><div class="email">'+esc(d.email||'')+'</div>'
  +field('氏名',p.name)+field('ニックネーム',p.nickname)
  +field('性別',GENDER[p.gender]||p.gender)+field('誕生日',p.birthdate)
  +'<button style="margin-top:16px;background:#fff;color:#c5221f;border:1.5px solid #c5221f" onclick="cibaLogout()">ログアウト</button>';
}
function cibaLogout(){sessionStorage.removeItem('ciba_demo');location.reload();}
async function start(){
 const st=document.getElementById('st');const hint=document.getElementById('hint').value.trim();
 if(!hint){st.textContent='メールアドレスを入力してください';return;}
 document.getElementById('go').disabled=true;st.textContent='要求を送信中…';
 try{
  const r=await fetch(STARTU,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({login_hint:hint})});
  if(!r.ok){st.innerHTML='<span class=ng>'+(await r.text())+'</span>';document.getElementById('go').disabled=false;return;}
  const {auth_req_id}=await r.json();
  st.innerHTML='承認待ち… 別ブラウザの<a href="__CIBA__">承認画面</a>で passkey 承認してください。';
  timer=setInterval(()=>poll(auth_req_id),3000);
 }catch(e){st.innerHTML='<span class=ng>'+e.message+'</span>';document.getElementById('go').disabled=false;}
}
async function poll(id){
 try{
  const r=await fetch(POLLU+'?auth_req_id='+encodeURIComponent(id));
  if(!r.ok)return;
  const d=await r.json();
  const st=document.getElementById('st');
  if(d.status==='approved'){clearInterval(timer);showProfile(d);}
  else if(d.status==='denied'){clearInterval(timer);st.innerHTML='<span class=ng>拒否されました。</span>';document.getElementById('go').disabled=false;}
 }catch(e){}
}
// リロード時: 保存済みのログイン状態があればプロフィールを復元表示する。
(function(){const s=sessionStorage.getItem('ciba_demo');if(s){try{showProfile(JSON.parse(s));}catch(e){}}})();
</script></body></html>"##;
    Html(
        body.replace("__START__", &p.path("/ciba-demo/start"))
            .replace("__POLL__", &p.path("/ciba-demo/poll"))
            .replace("__CIBA__", &p.path("/ciba")),
    )
}

/* ===== RP デモ（ブラウザ完結の authorization code + PKCE） ===== */

async fn demo_start(State(p): State<Arc<Provider>>) -> Html<String> {
    let page = r##"<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>fido2demo</title>
<style>:root{--indigo:#3f51b5;--indigo-d:#303f9f}
body{font-family:Roboto,-apple-system,'Helvetica Neue',sans-serif;max-width:360px;margin:0 auto;padding:56px 24px;color:#1a1a1a;text-align:center}
.fp{width:72px;height:72px;color:var(--indigo)}
h1{font-size:1.3rem;font-weight:500;margin:18px 0 28px}
.filled{width:100%;padding:14px;font-size:16px;font-weight:500;background:var(--indigo);color:#fff;border:0;border-radius:24px;cursor:pointer}
.filled:active{background:var(--indigo-d)}
.hint{color:#9a9a9a;font-size:13px;margin-top:16px}</style></head><body>
<svg class="fp" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
<path d="M5.5 10a6.5 6.5 0 0 1 13 0v4a8 8 0 0 1-1 3.8"/><path d="M8 11a4 4 0 0 1 8 0v3a6 6 0 0 0 .8 3"/>
<path d="M12 11v4a7 7 0 0 0 1.4 4.3"/><path d="M12 19v.01"/></svg>
<h1>Passkey でサインイン</h1>
<button class="filled" onclick="start()">サインイン</button>
<p class="hint">テスト用固定ログイン: __USER__ / __PASS__</p>
<script>
const ISSUER="__ISSUER__";
function b64url(buf){return btoa(String.fromCharCode.apply(null,new Uint8Array(buf))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
async function start(){
  const v=b64url(crypto.getRandomValues(new Uint8Array(32)));
  sessionStorage.setItem('pkce_verifier',v);
  const dig=await crypto.subtle.digest('SHA-256',new TextEncoder().encode(v));
  const u=new URL(ISSUER+'/authorize');
  u.searchParams.set('client_id','demo-rp');
  u.searchParams.set('response_type','code');
  u.searchParams.set('scope','openid profile email offline_access');
  u.searchParams.set('redirect_uri',ISSUER+'/callback');
  u.searchParams.set('state',b64url(crypto.getRandomValues(new Uint8Array(16))));
  u.searchParams.set('nonce',b64url(crypto.getRandomValues(new Uint8Array(16))));
  u.searchParams.set('code_challenge',b64url(dig));
  u.searchParams.set('code_challenge_method','S256');
  location.href=u.toString();
}
</script></body></html>"##;
    Html(
        page.replace("__ISSUER__", &p.issuer)
            .replace("__USER__", &p.demo_user)
            .replace("__PASS__", &p.demo_pass),
    )
}

async fn demo_callback(State(p): State<Arc<Provider>>) -> Html<String> {
    let page = r##"<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>callback</title>
<style>:root{--indigo:#3f51b5}
body{font-family:Roboto,-apple-system,'Helvetica Neue',sans-serif;max-width:420px;margin:0 auto;padding:32px 20px;color:#1a1a1a}
h1{font-size:1.5rem;font-weight:500;margin:0}
.email{color:#00000088;margin:2px 0 20px}
.card{border:1px solid #00000022;border-radius:10px;padding:12px 14px;margin:10px 0}
.lbl{font-size:.8rem;color:var(--indigo);font-weight:600;margin-bottom:4px}
.val{font-size:1.05rem}.unset{color:#aaa}
.center{text-align:center;color:#888;padding:40px 0}
details{margin-top:24px;color:#888;font-size:12px}
pre{background:#f4f4f4;padding:10px;border-radius:6px;overflow:auto}
.logout{width:100%;margin-top:20px;padding:12px;font-size:16px;font-weight:500;background:#fff;color:#c5221f;border:1.5px solid #c5221f;border-radius:24px;cursor:pointer}</style></head><body>
<div id="cibaBox"></div>
<div id="out"><div class="center">サインイン処理中…</div></div>
<script>
const ISSUER="__ISSUER__";
const GENDER={male:'男性',female:'女性',other:'その他'};
function esc(s){return String(s).replace(/[<>&]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]));}
function field(label,val){return '<div class="card"><div class="lbl">'+label+'</div><div class="val">'+(val?esc(val):'<span class="unset">未設定</span>')+'</div></div>';}
let idTokenHint=null;
let lastUi=null,lastProf=null,lastTok=null;
function pf(){return (lastProf&&lastProf.profile)||{};}
// 編集 6 項目は /oidc/profile（保存済みのみ）から、email は userinfo から表示する。
function renderProfile(ui,prof,tok){
  idTokenHint=tok.id_token||null;lastUi=ui;lastProf=prof;lastTok=tok;
  const p=(prof&&prof.profile)||{};
  document.getElementById('out').innerHTML=
    '<h1>プロフィール</h1><div class="email">'+esc(ui.email||'')+'</div>'
    +field('氏名',p.name)+field('ニックネーム',p.nickname)
    +field('性別',GENDER[p.gender]||p.gender)+field('誕生日',p.birthdate)
    +field('タイムゾーン',p.zoneinfo)+field('ロケール',p.locale)
    +'<button class="logout" style="color:var(--indigo);border-color:var(--indigo)" onclick="editProfile()">編集</button>'
    +'<button class="logout" onclick="logout()">ログアウト</button>'
    +'<details><summary>トークン情報 (デバッグ)</summary><pre>'+esc(JSON.stringify({token_type:tok.token_type,scope:tok.scope,userinfo:ui,profile:p},null,2))+'</pre></details>';
}
function inputRow(label,name,val){return '<div class="card"><div class="lbl">'+label+'</div><input id="f_'+name+'" value="'+esc(val||'')+'" style="width:100%;font-size:1.05rem;border:none;outline:none"></div>';}
function editProfile(){
  const p=pf();
  document.getElementById('out').innerHTML=
    '<h1>プロフィール編集</h1><div class="email">'+esc((lastUi&&lastUi.email)||'')+'</div>'
    +inputRow('氏名','name',p.name)+inputRow('ニックネーム','nickname',p.nickname)
    +inputRow('性別 (male/female/other)','gender',p.gender)+inputRow('誕生日 (YYYY-MM-DD)','birthdate',p.birthdate)
    +inputRow('タイムゾーン','zoneinfo',p.zoneinfo)+inputRow('ロケール','locale',p.locale)
    +'<button class="logout" style="color:#fff;background:var(--indigo);border-color:var(--indigo)" onclick="saveProfile()">保存</button>'
    +'<button class="logout" onclick="renderProfile(lastUi,lastProf,lastTok)">キャンセル</button>';
}
const EDITABLE=['name','nickname','gender','birthdate','zoneinfo','locale'];
async function fetchProfile(){
  const t=getTokens();if(!t)return {profile:{}};
  const ath=await sha256u(t.access_token);
  const proof=await dpopProof('GET',ISSUER+'/profile',ath);
  const r=await fetch(ISSUER+'/profile',{headers:{'Authorization':'DPoP '+t.access_token,'DPoP':proof}});
  if(!r.ok)return {profile:{}};
  return await r.json();
}
async function saveProfile(){
  const t=getTokens();if(!t){fail('セッションが切れました');return;}
  const body={};EDITABLE.forEach(k=>{body[k]=document.getElementById('f_'+k).value;});
  const ath=await sha256u(t.access_token);
  const proof=await dpopProof('PUT',ISSUER+'/profile',ath);
  const r=await fetch(ISSUER+'/profile',{method:'PUT',headers:{'Authorization':'DPoP '+t.access_token,'DPoP':proof,'Content-Type':'application/json'},body:JSON.stringify(body)});
  if(!r.ok){fail('保存に失敗しました ('+r.status+')');return;}
  // PUT は更新後 profile を返すのでそれで再描画。
  const prof=await r.json();
  renderProfile(lastUi,prof,lastTok);
}
// RP-Initiated Logout: OP セッションを破棄して post_logout_redirect_uri(=/oidc/)へ。
function logout(){
  sessionStorage.removeItem('profile');
  sessionStorage.removeItem('tokens');
  try{indexedDB.deleteDatabase('dpop-keystore');}catch(_){}
  const u=new URL(ISSUER+'/end-session');
  u.searchParams.set('client_id','demo-rp');
  u.searchParams.set('post_logout_redirect_uri',ISSUER+'/');
  if(idTokenHint)u.searchParams.set('id_token_hint',idTokenHint);
  location.href=u.toString();
}
function fail(msg){document.getElementById('out').innerHTML='<div class="center">'+esc(msg)+'</div>';}
function b64u(buf){return btoa(String.fromCharCode.apply(null,new Uint8Array(buf))).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,'');}
function jb64(o){return b64u(new TextEncoder().encode(JSON.stringify(o)));}
function b64ToBuf(b64){const s=atob(b64.replace(/-/g,'+').replace(/_/g,'/'));const a=new Uint8Array(s.length);for(let i=0;i<s.length;i++)a[i]=s.charCodeAt(i);return a.buffer;}
// CIBA 承認依頼をプロフィール画面に通知表示し、その場で passkey 承認する（access token + DPoP）。
let cibaBusy=false;
async function fetchCibaPending(){
  const t=getTokens();if(!t)return [];
  const ath=await sha256u(t.access_token);
  const proof=await dpopProof('GET',ISSUER+'/ciba/pending',ath);
  const r=await fetch(ISSUER+'/ciba/pending',{headers:{'Authorization':'DPoP '+t.access_token,'DPoP':proof}});
  if(!r.ok)return [];
  return await r.json();
}
function renderCiba(items){
  const box=document.getElementById('cibaBox');
  if(!items||!items.length){box.innerHTML='';return;}
  box.innerHTML=items.map(it=>'<div class="card" style="border-color:var(--indigo)"><div class="lbl">ログイン承認の依頼</div><div class="val">'+esc(it.binding_message||'(no message)')+'</div><div style="color:#888;font-size:12px;margin-top:4px">from '+esc(it.client_id)+' / scope: '+esc(it.scope)+'</div><button class="logout" style="margin-top:10px;color:#fff;background:var(--indigo);border-color:var(--indigo)" onclick="approveCiba(\''+it.auth_req_id+'\')">承認 (passkey)</button><button class="logout" onclick="rejectCiba(\''+it.auth_req_id+'\')">拒否</button></div>').join('');
}
async function approveCiba(id){
  const t=getTokens();if(!t)return;cibaBusy=true;
  try{
    let ath=await sha256u(t.access_token);
    let proof=await dpopProof('POST',ISSUER+'/ciba/'+id+'/passkey-options',ath);
    const r=await fetch(ISSUER+'/ciba/'+id+'/passkey-options',{method:'POST',headers:{'Authorization':'DPoP '+t.access_token,'DPoP':proof,'Content-Type':'application/json'},body:'{}'});
    if(!r.ok){alert(await r.text());cibaBusy=false;return;}
    const o=await r.json();
    const cred=await navigator.credentials.get({publicKey:{challenge:b64ToBuf(o.challenge),rpId:o.rpId,timeout:o.timeout,userVerification:'required',allowCredentials:(o.allowCredentials||[]).map(c=>({type:'public-key',id:b64ToBuf(c.id),transports:c.transports}))}});
    const body={id:cred.id,response:{clientDataJSON:b64u(cred.response.clientDataJSON),authenticatorData:b64u(cred.response.authenticatorData),signature:b64u(cred.response.signature)}};
    ath=await sha256u(t.access_token);
    proof=await dpopProof('POST',ISSUER+'/ciba/'+id+'/approve',ath);
    const v=await fetch(ISSUER+'/ciba/'+id+'/approve',{method:'POST',headers:{'Authorization':'DPoP '+t.access_token,'DPoP':proof,'Content-Type':'application/json'},body:JSON.stringify(body)});
    if(!v.ok){alert(await v.text());}
  }catch(e){alert(e.message);}
  cibaBusy=false;pollCiba();
}
async function rejectCiba(id){
  const t=getTokens();if(!t)return;cibaBusy=true;
  const ath=await sha256u(t.access_token);
  const proof=await dpopProof('POST',ISSUER+'/ciba/'+id+'/reject',ath);
  await fetch(ISSUER+'/ciba/'+id+'/reject',{method:'POST',headers:{'Authorization':'DPoP '+t.access_token,'DPoP':proof}});
  cibaBusy=false;pollCiba();
}
async function pollCiba(){ if(cibaBusy)return; try{renderCiba(await fetchCibaPending());}catch(e){} }
// DPoP 鍵は IndexedDB に非抽出のまま永続化（リロード/再訪でも同じ鍵＝同じ jkt）。
// これにより保存した access_token を継続利用できる（TS の dpop-keystore 相当）。
function idb(){return new Promise((res,rej)=>{const r=indexedDB.open('dpop-keystore',1);r.onupgradeneeded=()=>r.result.createObjectStore('keys');r.onsuccess=()=>res(r.result);r.onerror=()=>rej(r.error);});}
let dpopKeyP=null;
async function getKey(){
  if(dpopKeyP)return dpopKeyP;
  dpopKeyP=(async()=>{
    const db=await idb();
    const existing=await new Promise(res=>{const t=db.transaction('keys','readonly').objectStore('keys').get('dpop');t.onsuccess=()=>res(t.result);t.onerror=()=>res(null);});
    if(existing)return existing;
    const kp=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign']); // 非抽出
    await new Promise((res,rej)=>{const tx=db.transaction('keys','readwrite');tx.objectStore('keys').put(kp,'dpop');tx.oncomplete=()=>res();tx.onerror=()=>rej(tx.error);});
    return kp;
  })();
  return dpopKeyP;
}
async function dpopProof(htm,htu,ath){
  const k=await getKey();
  const jwk=await crypto.subtle.exportKey('jwk',k.publicKey); // 公開鍵は非抽出でも export 可
  const header={typ:'dpop+jwt',alg:'ES256',jwk:{kty:'EC',crv:'P-256',x:jwk.x,y:jwk.y}};
  const payload={jti:b64u(crypto.getRandomValues(new Uint8Array(16))),htm,htu,iat:Math.floor(Date.now()/1000)};
  if(ath)payload.ath=ath;
  const si=jb64(header)+'.'+jb64(payload);
  const sig=await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},k.privateKey,new TextEncoder().encode(si));
  return si+'.'+b64u(sig);
}
async function sha256u(s){return b64u(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(s)));}
function saveTokens(t){sessionStorage.setItem('tokens',JSON.stringify({access_token:t.access_token,refresh_token:t.refresh_token,id_token:t.id_token,token_type:t.token_type,scope:t.scope}));}
function getTokens(){const s=sessionStorage.getItem('tokens');return s?JSON.parse(s):null;}
// userinfo を DPoP 付きで取得。401 なら refresh して 1 回だけリトライ。
async function fetchUserinfo(allowRefresh){
  let t=getTokens();if(!t)return null;
  const ath=await sha256u(t.access_token);
  const proof=await dpopProof('GET',ISSUER+'/userinfo',ath);
  const r=await fetch(ISSUER+'/userinfo',{headers:{'Authorization':'DPoP '+t.access_token,'DPoP':proof}});
  if(r.status===401&&allowRefresh&&t.refresh_token){
    const ok=await doRefresh();
    if(ok)return fetchUserinfo(false);
    return null;
  }
  if(!r.ok)return null;
  return {ui:await r.json(),tok:t};
}
// refresh_token で更新（DPoP 束縛・rotation）。
async function doRefresh(){
  const t=getTokens();if(!t||!t.refresh_token)return false;
  const proof=await dpopProof('POST',ISSUER+'/token');
  const r=await fetch(ISSUER+'/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','DPoP':proof},body:new URLSearchParams({grant_type:'refresh_token',refresh_token:t.refresh_token,client_id:'demo-rp'})});
  const nt=await r.json();
  if(!nt.access_token)return false;
  nt.id_token=nt.id_token||t.id_token;
  saveTokens(nt);return true;
}
(async()=>{
  const q=new URLSearchParams(location.search);
  if(q.get('error')){fail('エラー: '+q.get('error')+' / '+(q.get('error_description')||''));return;}
  const code=q.get('code');
  if(code){
    // 初回: code 交換 → トークン保存 → URL から ?code 除去。
    const verifier=sessionStorage.getItem('pkce_verifier');
    const tproof=await dpopProof('POST',ISSUER+'/token');
    const r=await fetch(ISSUER+'/token',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','DPoP':tproof},body:new URLSearchParams({grant_type:'authorization_code',code,redirect_uri:ISSUER+'/callback',client_id:'demo-rp',code_verifier:verifier})});
    const tok=await r.json();
    if(tok.access_token){saveTokens(tok);try{history.replaceState({},'',location.pathname);}catch(_){}}
    // access_token が取れなかった場合(リロードで消費済み)は下の保存トークン経路へ。
  }
  // 保存トークンでライブに userinfo 取得（リロード/再訪でも継続アクセス）。
  const res=await fetchUserinfo(true);
  if(res){const prof=await fetchProfile();renderProfile(res.ui,prof,res.tok);pollCiba();setInterval(pollCiba,4000);return;}
  // トークンが無い/失効 → サインインへ。
  if(!getTokens()){location.href=ISSUER;return;}
  fail('セッションが切れました。再度サインインしてください。');
})();
</script></body></html>"##;
    Html(page.replace("__ISSUER__", &p.issuer))
}

/* ===== userinfo ===== */

/// Authorization ヘッダから (scheme, token) を取り出す（Bearer / DPoP）。
fn auth_scheme_token(headers: &HeaderMap) -> Option<(String, String)> {
    let h = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    if let Some(t) = h.strip_prefix("Bearer ") {
        return Some(("Bearer".into(), t.to_string()));
    }
    if let Some(t) = h.strip_prefix("DPoP ") {
        return Some(("DPoP".into(), t.to_string()));
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
        None => return Err((StatusCode::UNAUTHORIZED, "invalid token").into_response()),
    };
    // DPoP 束縛トークンは DPoP scheme + proof（jkt 一致 / ath 一致）を要求。
    if let Some(jkt) = &at.jkt {
        if scheme != "DPoP" {
            return Err((StatusCode::UNAUTHORIZED, "DPoP scheme required").into_response());
        }
        let proof = match dpop_header(headers) {
            Some(p) => p,
            None => return Err((StatusCode::UNAUTHORIZED, "DPoP proof required").into_response()),
        };
        let htu = format!("{}{}", p.issuer, path_suffix);
        let want_ath = crate::dpop::ath(&token);
        match p.dpop.verify(&proof, method, &htu, Some(&want_ath)) {
            Ok(got) if &got == jkt => {}
            Ok(_) => return Err((StatusCode::UNAUTHORIZED, "DPoP jkt mismatch").into_response()),
            Err(e) => return Err((StatusCode::UNAUTHORIZED, format!("DPoP: {e}")).into_response()),
        }
    }
    Ok(at)
}

async fn userinfo_respond(
    p: &Provider,
    headers: &HeaderMap,
    method: &str,
    body_token: Option<String>,
) -> Response {
    let at = match authenticate_token(p, headers, method, "/userinfo", body_token).await {
        Ok(at) => at,
        Err(r) => return r,
    };
    let account = p.store.find_account(&at.account_id).await;
    let allowed = crate::claims::claim_names_for_scopes(&at.scope);
    let filtered: HashMap<&str, &serde_json::Value> = allowed
        .iter()
        .filter_map(|name| account.claims.get(*name).map(|v| (*name, v)))
        .collect();
    Json(filtered).into_response()
}

/* ===== profile（編集可能 claim の表示・更新） ===== */

/// 保存済みの編集可能 claim のみを返す（未設定は欠落させ、画面側で空表示にする）。
/// userinfo 用の account_for ダミーは混ぜない。
fn profile_view(sub: &str, profile: &HashMap<String, String>) -> serde_json::Value {
    serde_json::json!({
        "sub": sub,
        "editable_fields": crate::claims::EDITABLE,
        "profile": profile,
    })
}

async fn profile_get(State(p): State<Arc<Provider>>, headers: HeaderMap) -> Response {
    let at = match authenticate_token(&p, &headers, "GET", "/profile", None).await {
        Ok(at) => at,
        Err(r) => return r,
    };
    let profile = match &p.firestore {
        Some(fs) => crate::registration::get_profile(fs, &at.account_id)
            .await
            .unwrap_or_default(),
        None => HashMap::new(),
    };
    Json(profile_view(&at.account_id, &profile)).into_response()
}

async fn profile_put(State(p): State<Arc<Provider>>, headers: HeaderMap, body: String) -> Response {
    let at = match authenticate_token(&p, &headers, "PUT", "/profile", None).await {
        Ok(at) => at,
        Err(r) => return r,
    };
    let fs = match &p.firestore {
        Some(f) => f,
        None => return (StatusCode::NOT_IMPLEMENTED, "profile store unavailable").into_response(),
    };
    let updates: HashMap<String, String> = match serde_json::from_str(&body) {
        Ok(m) => m,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("invalid body: {e}")).into_response(),
    };
    if let Err(e) = crate::registration::save_profile(fs, &at.account_id, &updates).await {
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("save: {e}")).into_response();
    }
    let profile = crate::registration::get_profile(fs, &at.account_id)
        .await
        .unwrap_or_default();
    Json(profile_view(&at.account_id, &profile)).into_response()
}

async fn userinfo_get(State(p): State<Arc<Provider>>, headers: HeaderMap) -> Response {
    userinfo_respond(&p, &headers, "GET", None).await
}

/// POST userinfo（Bearer/DPoP ヘッダ、無ければ body の access_token）。
async fn userinfo_post(State(p): State<Arc<Provider>>, headers: HeaderMap, body: String) -> Response {
    let body_token = serde_urlencoded::from_str::<HashMap<String, String>>(&body)
        .ok()
        .and_then(|m| m.get("access_token").cloned());
    userinfo_respond(&p, &headers, "POST", body_token).await
}
