use super::*;

/// プロフィール画面のポーリング用: 自分宛の pending CIBA 依頼一覧（access token 認証）。
pub(super) async fn ciba_pending_list(State(p): State<Arc<Provider>>, headers: HeaderMap) -> Response {
    let at = match authenticate_token(&p, &headers, "GET", "/ciba/pending", None).await {
        Ok(at) => at,
        Err(r) => return r,
    };
    // 読み取り時スイープ: 期限切れ pending を履歴(expired)へ移して掃除する（掃除漏れ対策）。
    let _ = p.ciba.sweep_expired(&at.account_id).await;
    let pending = p.ciba.list_pending(&at.account_id).await.unwrap_or_default();
    let items: Vec<serde_json::Value> = pending
        .iter()
        .map(|r| {
            // authorization_details は JSON 配列文字列を保持しているので、解析して構造のまま返す。
            // 解析失敗（または無し）なら null にしておき、fido2demo は binding_message に fallback する。
            let ad: Option<serde_json::Value> = r
                .authorization_details
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok());
            serde_json::json!({
                "auth_req_id": r.auth_req_id.as_str(),
                "client_id": r.client_id,
                "scope": r.scope,
                "binding_message": r.binding_message,
                "authorization_details": ad,
            })
        })
        .collect();
    Json(items).into_response()
}

/// 自分宛の解決済み CIBA 履歴（承認/拒否/期限切れ）。access token 認証。新しい順・最大50件。
pub(super) async fn ciba_history(State(p): State<Arc<Provider>>, headers: HeaderMap) -> Response {
    let at = match authenticate_token(&p, &headers, "GET", "/ciba/history", None).await {
        Ok(at) => at,
        Err(r) => return r,
    };
    // 履歴取得のついでに期限切れ pending を expired として履歴へ確定させる。
    let _ = p.ciba.sweep_expired(&at.account_id).await;
    let entries = p.ciba.list_history(&at.account_id, 50).await.unwrap_or_default();
    let items: Vec<serde_json::Value> = entries
        .iter()
        .map(|e| {
            let ad: Option<serde_json::Value> = e
                .authorization_details
                .as_deref()
                .and_then(|s| serde_json::from_str(s).ok());
            serde_json::json!({
                "auth_req_id": e.auth_req_id,
                "client_id": e.client_id,
                "scope": e.scope,
                "binding_message": e.binding_message,
                "authorization_details": ad,
                "outcome": e.outcome,
                "resolved_at": e.resolved_at,
            })
        })
        .collect();
    Json(items).into_response()
}

#[derive(serde::Deserialize)]
pub(super) struct FcmTokenReq {
    token: String,
    platform: Option<String>,
}

/// ネイティブアプリの FCM token を登録（access token 認証）。CIBA 通知の宛先になる。
pub(super) async fn fcm_token_register(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    Json(req): Json<FcmTokenReq>,
) -> Response {
    let at = match authenticate_token(&p, &headers, "POST", "/ciba/fcm-tokens", None).await {
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
pub(super) async fn backchannel_auth(
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
    // JAR (FAPI-CIBA): signed request object を検証し以後のパラメータをその claims から取る。
    // private_key_jwt クライアントは signed request 必須（FAPI-CIBA）。
    let form = match form.get("request").cloned() {
        Some(req) => match crate::request_object::verify(&client, &req, &p.issuer, &p.jar_jti).await {
            Ok(m) => m,
            Err(e) => return e.into_response(),
        },
        None => {
            if client.token_endpoint_auth_method == "private_key_jwt" {
                return OAuthError::InvalidRequest(
                    "signed request object required for this client".into(),
                )
                .into_response();
            }
            form
        }
    };
    // FAPI-CIBA: hint は login_hint / id_token_hint / login_hint_token のうち厳密に 1 つ。
    let hint_count = ["login_hint", "id_token_hint", "login_hint_token"]
        .iter()
        .filter(|k| form.contains_key(**k))
        .count();
    if hint_count != 1 {
        return OAuthError::InvalidRequest(
            "exactly one of login_hint/id_token_hint/login_hint_token is required".into(),
        )
        .into_response();
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
    // RFC 9396 authorization_details: 任意。JSON 配列で各要素に type 必須。
    // 4KB / 5 entry の cap を入れて DoS と乱用を抑える。中身の意味は OP は判定せず
    // 受け取って access token に紐付ける（gateway 側の MandatePolicy で照合する）。
    let authorization_details = match form.get("authorization_details") {
        Some(raw) => {
            if raw.len() > 4096 {
                return OAuthError::InvalidRequest("authorization_details too large".into())
                    .into_response();
            }
            let v: serde_json::Value = match serde_json::from_str(raw) {
                Ok(v) => v,
                Err(_) => {
                    return OAuthError::InvalidRequest(
                        "authorization_details must be JSON".into(),
                    )
                    .into_response();
                }
            };
            let arr = match v.as_array() {
                Some(a) => a,
                None => {
                    return OAuthError::InvalidRequest(
                        "authorization_details must be a JSON array".into(),
                    )
                    .into_response();
                }
            };
            if arr.is_empty() || arr.len() > 5 {
                return OAuthError::InvalidRequest(
                    "authorization_details must have 1..=5 entries".into(),
                )
                .into_response();
            }
            for e in arr {
                if e.get("type").and_then(|t| t.as_str()).is_none() {
                    return OAuthError::InvalidRequest(
                        "authorization_details entry requires 'type'".into(),
                    )
                    .into_response();
                }
            }
            Some(raw.clone())
        }
        None => None,
    };
    // login_hint は passkey 登録済みアカウントであること（未登録は即拒否）。
    // account_id は以後、CIBA 要求本体・発行トークンの sub・FCM 宛先解決すべてに使う
    // （login_hint = email は RP 起点のヒントとして dedup/レート制限のキーにのみ残す）。
    let account_id = match crate::registration::get_credential(fs, &login_hint).await {
        Ok(Some(c)) if !c.account_id.is_empty() => c.account_id,
        Ok(_) => return OAuthError::InvalidRequest("unknown user_id".into()).into_response(),
        Err(e) => {
            tracing::error!("get_credential: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
        }
    };
    // dedup: 同 (client_id, account) に未解決の pending があれば、新規発行も push もせず
    // 既存の auth_req_id を返す（冪等）。連発時の端末スパム抑止。
    match p.ciba.find_pending_for(&client.client_id, &login_hint).await {
        Ok(Some(existing)) => {
            let remaining = existing.expires_at.saturating_sub(now_secs());
            return (
                [(header::CACHE_CONTROL, "no-store")],
                Json(serde_json::json!({
                    "auth_req_id": existing.auth_req_id.0,
                    "expires_in": remaining,
                    "interval": 2,
                })),
            )
                .into_response();
        }
        Ok(None) => {}
        Err(e) => {
            tracing::error!("ciba find_pending_for: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
        }
    }
    // レート制限: dedup を抜けた要求の連発（例: 拒否直後の再試行）を抑止。
    if !p.ciba_rate.check_and_record(&client.client_id, &login_hint) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::CACHE_CONTROL, "no-store"), (header::RETRY_AFTER, "60")],
            Json(serde_json::json!({
                "error": "slow_down",
                "error_description": "rate limit exceeded for this client/user",
            })),
        )
            .into_response();
    }
    match p.ciba.create(&client.client_id, &account_id, &scope, &binding, authorization_details.as_deref()).await {
        Ok(id) => {
            // FCM で iPhone に承認要求を通知（Cloud Run suspend を避けるため await）。
            // token 未登録/送信失敗でも Web 承認は可能なのでベストエフォート。
            // fcm::save_token は at.account_id（UUID）で保存するため、宛先解決も account_id で行う。
            let _ = crate::fcm::send_ciba_request(fs, &account_id, &client.client_id, &scope, &binding, id.as_str(), authorization_details.as_deref()).await;
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

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// 承認 UI: ログイン済セッションが自分宛の pending 要求を承認/拒否する。
pub(super) async fn ciba_pending(State(p): State<Arc<Provider>>, jar: CookieJar) -> Response {
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
    let pending = p.ciba.list_pending(&account).await.unwrap_or_default();
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

pub(super) async fn ciba_approve_options(
    State(p): State<Arc<Provider>>,
    Path(auth_req_id): Path<String>,
) -> Response {
    let fs = match &p.firestore {
        Some(f) => f,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    // 承認主体は CIBA 要求の account（account_id/UUID）から決まる。アプリへの
    // ログインは不要で、パスキー assertion（UV 必須）が本人性を証明する。
    // passkey の資格情報は accounts/{email} 側にあるため、account_id → email を逆引きしてから引く。
    let req = match p.ciba.get(&auth_req_id).await {
        Ok(Some(r)) if !r.expired() => r,
        _ => return (StatusCode::NOT_FOUND, "request not found").into_response(),
    };
    let email = match crate::registration::find_email_by_account_id(fs, &req.account).await {
        Ok(Some(e)) => e,
        _ => return (StatusCode::BAD_REQUEST, "no passkey").into_response(),
    };
    let cred = match crate::registration::get_credential(fs, &email).await {
        Ok(Some(c)) => c,
        _ => return (StatusCode::BAD_REQUEST, "no passkey").into_response(),
    };
    let challenge = match crate::registration::create_webauthn_challenge(
        fs,
        &email,
        crate::registration::ChallengeKind::CibaApprove,
        &auth_req_id,
        "",
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
        "userVerification": "required",
        "allowCredentials": [{ "type": "public-key", "id": cred.credential_id, "transports": ["internal", "hybrid"] }],
    }))
    .into_response()
}

pub(super) async fn ciba_approve(
    State(p): State<Arc<Provider>>,
    Path(auth_req_id): Path<String>,
    Json(req): Json<AuthVerifyReq>,
) -> Response {
    let fs = match &p.firestore {
        Some(f) => f,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    // 承認はログイン不要。チャレンジに紐づくユーザー（passkey-options で発行時に束縛）
    // と CIBA 要求の account が一致し、そのユーザーの登録鍵で assertion を検証する。
    let challenge = match crate::webauthn::extract_challenge(&req.response.client_data_json) {
        Some(c) => c,
        None => return (StatusCode::BAD_REQUEST, "no challenge").into_response(),
    };
    let (email, kind, uid, _) = match crate::registration::consume_webauthn_challenge(fs, &challenge).await {
        Ok(Some(t)) => t,
        _ => return (StatusCode::BAD_REQUEST, "challenge invalid/expired").into_response(),
    };
    if kind != crate::registration::ChallengeKind::CibaApprove || uid != auth_req_id {
        return (StatusCode::BAD_REQUEST, "challenge context mismatch").into_response();
    }
    // チャレンジ発行時に束縛されたユーザー（email）= 承認主体。CIBA 要求側は account_id(UUID)
    // で管理しているため、email → account_id に変換してから照合する。
    let cred = match crate::registration::get_credential(fs, &email).await {
        Ok(Some(c)) if !c.account_id.is_empty() => c,
        _ => return (StatusCode::BAD_REQUEST, "no passkey").into_response(),
    };
    let account = cred.account_id.clone();
    let ciba_req = match p.ciba.get(&auth_req_id).await {
        Ok(Some(r)) if r.account == account && !r.expired() => r,
        _ => return (StatusCode::NOT_FOUND, "request not found").into_response(),
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
        true, // CIBA 承認は UV(生体/PIN) 必須
    ) {
        Ok(n) => {
            let _ = crate::registration::update_sign_count(fs, &email, n).await;
        }
        Err(e) => return (StatusCode::UNAUTHORIZED, format!("passkey verify failed: {e}")).into_response(),
    }
    let _ = ciba_req; // 検証済み。承認に進む。
    // 先勝ち: Pending のときだけ Approved へ原子的に遷移。既に承認/拒否済みなら 409。
    match p.ciba.transition_if_pending(&auth_req_id, crate::ciba::CibaStatus::Approved).await {
        Ok(true) => {
            // 監査履歴に「承認」を追記（ベストエフォート。失敗しても承認は成立させる）。
            let entry = crate::ciba::CibaHistoryEntry::from_request(&ciba_req, "approved", now_secs());
            let _ = p.ciba.record_history(&entry).await;
        }
        Ok(false) => return (StatusCode::CONFLICT, "already handled").into_response(),
        Err(e) => {
            tracing::error!("transition: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
        }
    }
    Json(serde_json::json!({ "ok": true })).into_response()
}

pub(super) async fn ciba_reject(
    State(p): State<Arc<Provider>>,
    Path(auth_req_id): Path<String>,
) -> Response {
    // 拒否はログイン不要。auth_req_id を知る当事者（ユーザー端末/開始側）の fail-safe 操作。
    // 先勝ち: Pending のときだけ Denied へ。既に処理済みなら何もしない（冪等に 204）。
    // 履歴記録のため要求を読んでおく。
    let req = p.ciba.get(&auth_req_id).await.ok().flatten();
    // 期限切れは「拒否」で確定させない（denied と誤記録しない）。スイープが expired として
    // 履歴に確定する。クライアントが UI を区別できるよう 409（偽の成功 204 を返さない）。
    if req.as_ref().map(|r| r.expired()).unwrap_or(false) {
        return (StatusCode::CONFLICT, "expired").into_response();
    }
    match p.ciba.transition_if_pending(&auth_req_id, crate::ciba::CibaStatus::Denied).await {
        // 拒否成立。
        Ok(true) => {
            if let Some(r) = &req {
                let entry = crate::ciba::CibaHistoryEntry::from_request(r, "denied", now_secs());
                let _ = p.ciba.record_history(&entry).await;
            }
            StatusCode::NO_CONTENT.into_response()
        }
        // 既に承認/拒否済み（または存在しない）。偽成功にせず 409 で区別させる。
        Ok(false) => (StatusCode::CONFLICT, "already handled").into_response(),
        Err(e) => {
            tracing::error!("transition: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response()
        }
    }
}
