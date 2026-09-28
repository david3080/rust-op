use super::*;

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

pub(super) async fn register_form(State(p): State<Arc<Provider>>) -> Html<String> {
    let action = p.path("/signup");
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
pub(super) struct RegisterForm {
    email: String,
}

/// メール確認チャレンジを作り確認メールを送る。Web フォーム/ネイティブ JSON 共通。
async fn issue_register_email(
    p: &Provider,
    fs: &crate::firestore::Firestore,
    email: &str,
    ip: &str,
) -> Result<(), String> {
    if !email.contains('@') || email.len() > 254 {
        return Err("invalid email".into());
    }
    // レート制限: 同一アドレスへの連発・同一 IP からの大量送信を抑止
    // （メール爆撃 / 正規ドメイン発フィッシング / 送信枠浪費の対策）。
    if !p.register_rate.check_and_record("email", email)
        || !p.register_rate.check_and_record("ip", ip)
    {
        return Err("rate_limited".into());
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

pub(super) async fn register_submit(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    Form(form): Form<RegisterForm>,
) -> Response {
    let email = form.email.trim().to_lowercase();
    let fs = match &p.firestore {
        Some(fs) => fs,
        None => return plain_error("registration not available (no Firestore)"),
    };
    match issue_register_email(&p, fs, &email, &client_ip(&headers)).await {
        Ok(()) => page(
            "送信しました",
            "<h1>確認メールを送信しました</h1><p>メール内のリンクから passkey を作成して登録を完了してください（有効期限15分）。</p>",
        )
        .into_response(),
        Err(e) if e == "invalid email" => plain_error("invalid email"),
        Err(e) if e == "rate_limited" => {
            (StatusCode::TOO_MANY_REQUESTS, "rate limited; please retry later").into_response()
        }
        Err(e) => {
            tracing::error!("register_submit: {e}");
            plain_error("internal error")
        }
    }
}

/* ネイティブアプリ向け JSON 登録 API（Web の HTML フローと同じ Firestore を共有） */

#[derive(serde::Deserialize)]
pub(super) struct EmailChallengeReq {
    email: String,
}

pub(super) async fn register_email_challenge(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    Json(req): Json<EmailChallengeReq>,
) -> Response {
    let email = req.email.trim().to_lowercase();
    let fs = match &p.firestore {
        Some(fs) => fs,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    match issue_register_email(&p, fs, &email, &client_ip(&headers)).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) if e == "invalid email" => (StatusCode::BAD_REQUEST, "invalid email").into_response(),
        Err(e) if e == "rate_limited" => {
            (StatusCode::TOO_MANY_REQUESTS, "rate limited").into_response()
        }
        Err(e) => {
            tracing::error!("email-challenge: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response()
        }
    }
}

#[derive(serde::Deserialize)]
pub(super) struct VerifyEmailReq {
    token: String,
}

/// メール確認 token を検証して email を返す（token は消費せず passkey-verify で消費）。
pub(super) async fn register_verify_email(
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

/// passkey 作成（ブラウザ）ページ。メールリンク /r と /signup/verify で共用。
/// iPhone は AASA(Universal Link)でアプリが横取りするため通常この HTML は出ず、
/// PC/Mac やアプリ未対応端末ではこのページでブラウザ passkey 登録を完結できる。
/// `invite_return` が Some なら招待の着地: 端末を問わず Web で登録し、成功したら戻り先へ移る。
fn passkey_register_page(p: &Provider, token: &str, invite_return: Option<&str>) -> Html<String> {
    let token: String = token
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
        .collect();
    // UA 判別: モバイル(iOS/Android)はアプリ起動を一次手段に、デスクトップは Web のみ。
    // 自動で navigator.credentials.create を発火させない（ユーザーの明示クリックを要求）。
    let body = r##"<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>passkey 登録</title>
<style>body{font-family:-apple-system,sans-serif;max-width:380px;margin:40px auto;padding:0 16px;color:#222}
h1{font-size:20px;margin:0 0 8px}p{font-size:14px;line-height:1.6}
button,.btn{display:block;width:100%;padding:13px;margin-top:12px;font-size:16px;border:0;border-radius:8px;cursor:pointer;text-align:center;text-decoration:none;box-sizing:border-box}
.primary{background:#3367d6;color:#fff}.secondary{background:#f1f3f4;color:#3367d6}
.small{font-size:12px;color:#5f6368;margin-top:8px}
#msg{font-size:14px;margin-top:14px;min-height:1.4em}#fallback{margin-top:16px}</style></head><body>
<h1>passkey を作成</h1>
<div id="mobile" hidden>
 <p>fido2demo アプリで安全に登録します。</p>
 <button class="primary" onclick="openApp()">アプリで開く</button>
 <p class="small">インストール済みなら自動で開きます。開かない場合は下のボタンから Web で続行できます。</p>
 <div id="fallback" hidden>
  <button class="secondary" onclick="reg()">Web で登録を続ける</button>
  <p class="small">同期 passkey（iCloud Keychain 等）として作成されます。</p>
 </div>
</div>
<div id="desktop" hidden>
 <p>このデバイスの生体認証等で passkey を作成し、登録を完了します。</p>
 <button class="primary" onclick="reg()">passkey を作成して登録</button>
</div>
<p id="msg"></p>
<script>
__WEBAUTHN_JS__
const TOKEN="__TOKEN__",OPT="__OPT__",VER="__VER__",LOGIN="__LOGIN__",AFTER=__AFTER__;
const ua=navigator.userAgent;
const isAndroid=/Android/i.test(ua);
const isIOS=/iPad|iPhone|iPod/i.test(ua)||(/(Macintosh).*Mobile/i.test(ua));
document.getElementById((!AFTER&&(isAndroid||isIOS))?'mobile':'desktop').hidden=false;
function openApp(){
 // iOS=カスタムスキーム / Android=intent URL（fallback付き）。アプリ未起動なら1.5秒後にWebボタン提示。
 const url=isAndroid
  ?('intent://magic?t='+TOKEN+'#Intent;scheme=jp.co.sonrisa.fido2demo;package=jp.co.sonrisa.fido2demo;S.browser_fallback_url='+encodeURIComponent('https://oidc.sonrisa.co.jp/r?t='+TOKEN)+';end')
  :('jp.co.sonrisa.fido2demo://magic?t='+TOKEN);
 const timer=setTimeout(()=>{document.getElementById('fallback').hidden=false;},1500);
 document.addEventListener('visibilitychange',()=>{if(document.hidden)clearTimeout(timer);},{once:true});
 location.href=url;
}
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
  if(AFTER){msg.textContent='登録が完了しました。サインインの画面へ移ります…';location.href=AFTER;return;}
  msg.innerHTML='登録が完了しました。<a href="'+LOGIN+'">ログインへ</a>';
 }catch(e){msg.textContent=e.message;}
}
</script></body></html>"##;
    Html(
        body.replace("__WEBAUTHN_JS__", WEBAUTHN_JS)
            .replace("__TOKEN__", &token)
            .replace("__OPT__", &p.path("/signup/passkey/options"))
            .replace("__VER__", &p.path("/signup/passkey/verify"))
            .replace("__LOGIN__", &p.path("/"))
            .replace("__AFTER__", &js_string_literal(invite_return.unwrap_or(""))),
    )
}

/// `<script>` に埋め込む JS の文字列リテラル。JSON の文字列表現に、`</script>` を閉じさせない `<` の退避を足す。
fn js_string_literal(s: &str) -> String {
    serde_json::Value::String(s.to_string()).to_string().replace('<', "\\u003c")
}

/// メールリンク /r?t= の着地。iPhone は AASA でアプリ起動、PC/Mac はブラウザ登録。
#[derive(serde::Deserialize)]
pub(super) struct MagicQuery {
    t: String,
}

pub(super) async fn magic_redirect(State(p): State<Arc<Provider>>, Query(q): Query<MagicQuery>) -> Html<String> {
    passkey_register_page(&p, &q.t, None)
}

/// oidc.sonrisa.co.jp は Cloud Run へ直結（Firebase Hosting を経由しない）ため AASA を
/// ここで返す。applinks=Universal Link(/r でアプリ起動)、webcredentials=ネイティブ passkey。
pub(super) async fn apple_app_site_association() -> Response {
    (
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"applinks":{"apps":[],"details":[{"appID":"RA5A5W7PJB.jp.co.sonrisa.fido2demo","paths":["/r","/r?*"]}]},"webcredentials":{"apps":["RA5A5W7PJB.jp.co.sonrisa.fido2demo"]}}"#,
    )
        .into_response()
}

#[derive(serde::Deserialize)]
pub(super) struct VerifyQuery {
    token: String,
}

/// Web フォーム経由（/signup/verify?token=）の着地点。
pub(super) async fn verify_form(State(p): State<Arc<Provider>>, Query(q): Query<VerifyQuery>) -> Html<String> {
    passkey_register_page(&p, &q.token, None)
}

/* ===== 招待（RP が発行を頼む、確認メール不要の登録リンク） ===== */

/// `scheme://host[:port]`。https か、http の localhost に限る。
fn url_origin(u: &str) -> Option<String> {
    let (scheme, rest) = u.split_once("://")?;
    let host = rest.split(['/', '?', '#']).next()?;
    if host.is_empty() || host.contains('@') {
        return None;
    }
    let hostname = host.split(':').next().unwrap_or(host);
    match scheme {
        "https" => Some(format!("https://{host}")),
        "http" if hostname == "localhost" || hostname == "127.0.0.1" => Some(format!("http://{host}")),
        _ => None,
    }
}

/// 戻り先は、その client の redirect_uri と同じ origin の下に限る（オープンリダイレクト防止）。
fn return_to_allowed(client: &crate::model::Client, return_to: &str) -> bool {
    if return_to.len() > 2000 || return_to.chars().any(|c| c.is_whitespace() || c.is_control() || "\\\"'<>`".contains(c)) {
        return false;
    }
    let Some(origin) = url_origin(return_to) else { return false };
    let under_origin = return_to == origin || return_to.starts_with(&format!("{origin}/"));
    under_origin && client.redirect_uris.iter().any(|r| url_origin(r).as_deref() == Some(origin.as_str()))
}

/// POST /invites（form: email, return_to ＋ confidential client の認証）。
/// 招待の登録リンクを発行して返す。メールは RP が自分の文面で送る。
/// 既に登録済みのアドレスにはリンクを作らず `registered` を返す（passkey の上書きを招待で起こさない）。
pub(super) async fn invite_create(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let fs = match &p.firestore {
        Some(fs) => fs,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let client = match authenticate_client(&p, &headers, &form).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if client.is_public() || !p.invite_clients.iter().any(|id| id == &client.client_id) {
        tracing::warn!(event = "invite_denied", client_id = %client.client_id);
        return (StatusCode::FORBIDDEN, "client not allowed to invite").into_response();
    }
    let email = form.get("email").map(|e| e.trim().to_lowercase()).unwrap_or_default();
    if !email.contains('@') || email.len() > 254 {
        return plain_error("invalid email");
    }
    let return_to = form.get("return_to").cloned().unwrap_or_default();
    if !return_to_allowed(&client, &return_to) {
        return plain_error("return_to must be under a registered redirect_uri origin");
    }
    match crate::registration::account_exists(fs, &email).await {
        Ok(true) => {
            tracing::info!(event = "invite_already_registered", client_id = %client.client_id);
            return Json(serde_json::json!({ "status": "registered" })).into_response();
        }
        Ok(false) => {}
        Err(e) => {
            tracing::error!("invite account_exists: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
        }
    }
    match crate::registration::create_invite_challenge(fs, &email, &return_to).await {
        Ok(token) => {
            tracing::info!(event = "invite_created", client_id = %client.client_id);
            (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "status": "invited",
                    "url": format!("{}{}?t={}", p.origin(), p.path("/invite"), token),
                })),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("create_invite_challenge: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response()
        }
    }
}

/// GET /invite?t= 招待リンクの着地。アプリへの横取りを挟まず Web で passkey を作り、戻り先へ返す。
pub(super) async fn invite_page(State(p): State<Arc<Provider>>, Query(q): Query<MagicQuery>) -> Response {
    let fs = match &p.firestore {
        Some(fs) => fs,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let (email, return_to) = match crate::registration::peek_invite(fs, &q.t).await {
        Ok(Some(t)) => t,
        Ok(None) => {
            return (
                StatusCode::BAD_REQUEST,
                page(
                    "招待の期限切れ",
                    "<h1>この招待は使えません</h1><p>期限が切れたか、既に使われています。招待した方に、もう一度送ってもらってください。</p>",
                ),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!("peek_invite: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
        }
    };
    if matches!(crate::registration::account_exists(fs, &email).await, Ok(true)) {
        return Redirect::to(&return_to).into_response();
    }
    passkey_register_page(&p, &q.t, Some(&return_to)).into_response()
}

#[derive(serde::Deserialize)]
pub(super) struct RegPkOptionsReq {
    token: String,
}

pub(super) async fn register_passkey_options(
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
    // 既存 passkey の再登録なら account_id を再利用、新規なら払い出す。
    // WebAuthn user.id は sub と同じ不透明な account_id にする（email を含めない）。
    let existing = crate::registration::get_credential(fs, &email).await.ok().flatten();
    let account_id = existing
        .as_ref()
        .map(|c| c.account_id.clone())
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let challenge = match crate::registration::create_webauthn_challenge(fs, &email, crate::registration::ChallengeKind::Reg, "", &account_id).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("create challenge: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
        }
    };
    let exclude: Vec<serde_json::Value> = match &existing {
        Some(c) => vec![serde_json::json!({"type":"public-key","id":c.credential_id})],
        None => vec![],
    };
    Json(serde_json::json!({
        "challenge": challenge,
        "rp": { "id": p.rp_id(), "name": "rust-op" },
        "user": {
            "id": crate::webauthn::b64e(account_id.as_bytes()),
            "name": email,
            "displayName": email,
        },
        "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
        // requireResidentKey は WebAuthn 仕様では非推奨（residentKey に置換）だが、
        // Dart の passkeys パッケージ(AuthenticatorSelectionType)が非 null bool として
        // 要求するため明示する。"preferred" なので必須ではない＝false。
        "authenticatorSelection": { "requireResidentKey": false, "residentKey": "preferred", "userVerification": "preferred" },
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
pub(super) struct RegVerifyReq {
    token: String,
    response: RegResponse,
}

pub(super) async fn register_passkey_verify(
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
    let (email2, kind, _, account_id) = match crate::registration::consume_webauthn_challenge(fs, &challenge).await {
        Ok(Some(t)) => t,
        Ok(None) => return (StatusCode::BAD_REQUEST, "challenge invalid/expired").into_response(),
        Err(e) => {
            tracing::error!("consume webauthn challenge: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
        }
    };
    if kind != crate::registration::ChallengeKind::Reg || email2 != email1 || account_id.is_empty() {
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
    if let Err(e) = crate::registration::save_credential(fs, &email1, &account_id, &outcome).await {
        tracing::error!("save_credential: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
    }
    (
        StatusCode::CREATED,
        Json(serde_json::json!({ "ok": true, "redirect": p.path("/") })),
    )
        .into_response()
}

#[cfg(test)]
mod invite_tests {
    use super::*;
    use crate::fido::verify::test_support::*;
    use crate::fido::verify::FLAG_AT;
    use crate::fido::verify::FLAG_UP;
    use crate::firestore::fake_firestore;
    use crate::model::Client;
    use ciborium::value::Value as Cbor;
    use p256::ecdsa::SigningKey;

    const RP_ORIGIN: &str = "https://amate.example";

    fn rp_client(id: &str, auth: &str, secret: Option<&str>) -> Client {
        Client {
            client_id: id.into(),
            redirect_uris: vec![format!("{RP_ORIGIN}/auth/callback")],
            post_logout_redirect_uris: vec![],
            token_endpoint_auth_method: auth.into(),
            client_secret: secret.map(crate::dcr::hash_token),
            grant_types: vec!["authorization_code".into()],
            dpop_bound: false,
            jwks: vec![],
            jwks_uri: None,
            require_par: false,
            require_pkce: false,
            id_token_signed_response_alg: None,
        }
    }

    async fn provider(invite_clients: &[&str]) -> Arc<Provider> {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Arc::new(crate::firestore::Firestore::new_for_test("proj", host));
        Arc::new(
            Provider::new("https://idp.example".to_string())
                .with_firestore(fs.clone())
                .with_store(Arc::new(crate::firestore_store::FirestoreStore::new(fs)))
                .with_client(rp_client("amate", "client_secret_basic", Some("s3cret")))
                .with_client(rp_client("other", "client_secret_basic", Some("s3cret")))
                .with_client(rp_client("public", "none", None))
                .with_invite_clients(invite_clients.iter().map(|s| s.to_string()).collect()),
        )
    }

    fn basic(id: &str, secret: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(
            header::AUTHORIZATION,
            format!("Basic {}", B64.encode(format!("{id}:{secret}"))).parse().unwrap(),
        );
        h
    }

    fn form(pairs: &[(&str, &str)]) -> Form<HashMap<String, String>> {
        Form(pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect())
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    async fn body_text(resp: Response) -> String {
        let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        String::from_utf8_lossy(&bytes).to_string()
    }

    async fn invite(p: &Arc<Provider>, headers: HeaderMap, email: &str, return_to: &str) -> Response {
        invite_create(State(p.clone()), headers, form(&[("email", email), ("return_to", return_to)])).await
    }

    fn token_of(url: &str) -> String {
        url.split("?t=").nth(1).unwrap().to_string()
    }

    async fn register_with_token(p: &Arc<Provider>, token: &str) -> StatusCode {
        let opts_req: RegPkOptionsReq = serde_json::from_value(serde_json::json!({ "token": token })).unwrap();
        let opts = body_json(register_passkey_options(State(p.clone()), Json(opts_req)).await).await;
        let challenge = opts["challenge"].as_str().unwrap();
        let key = SigningKey::random(&mut rand_core::OsRng);
        let (x, y) = ec_xy(&key);
        let acd = attested_cred_data(b"invite-cred", &cose_es256(&x, &y));
        let att = Cbor::Map(vec![
            (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
            (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
            (Cbor::Text("authData".into()), Cbor::Bytes(build_auth_data(&p.rp_id(), FLAG_UP | FLAG_AT, 0, Some(&acd)))),
        ]);
        let cdj = client_data_json("webauthn.create", challenge, &p.origin());
        let verify_req: RegVerifyReq = serde_json::from_value(serde_json::json!({
            "token": token,
            "response": {
                "clientDataJSON": crate::webauthn::b64e(&cdj),
                "attestationObject": crate::webauthn::b64e(&cbor_to_vec(&att)),
            },
        }))
        .unwrap();
        register_passkey_verify(State(p.clone()), Json(verify_req)).await.status()
    }

    #[tokio::test]
    async fn allowed_client_gets_link_that_registers_and_returns_to_rp() {
        let p = provider(&["amate"]).await;
        let return_to = format!("{RP_ORIGIN}/auth/login");
        let resp = invite(&p, basic("amate", "s3cret"), "New@Example.com ", &return_to).await;
        assert_eq!(resp.status(), StatusCode::CREATED);
        let url = body_json(resp).await["url"].as_str().unwrap().to_string();
        assert!(url.starts_with("https://idp.example/invite?t="), "{url}");
        let token = token_of(&url);

        let page = invite_page(State(p.clone()), Query(MagicQuery { t: token.clone() })).await;
        assert_eq!(page.status(), StatusCode::OK);
        let html = body_text(page).await;
        assert!(html.contains(&format!("AFTER=\"{return_to}\"")), "戻り先が焼き込まれる");

        assert_eq!(register_with_token(&p, &token).await, StatusCode::CREATED);
        let fs = p.firestore.as_ref().unwrap();
        assert!(crate::registration::account_exists(fs, "new@example.com").await.unwrap());
        let cred = crate::registration::get_credential(fs, "new@example.com").await.unwrap().unwrap();
        let claims = p.store.find_account(&cred.account_id).await.claims;
        assert_eq!(claims.get("email"), Some(&serde_json::json!("new@example.com")));
        assert_eq!(
            claims.get("email_verified"),
            Some(&serde_json::json!(true)),
            "招待のリンクがメールの持ち主の確認を兼ねるので、RP には確認済みとして渡る"
        );

        let again = invite_page(State(p.clone()), Query(MagicQuery { t: token })).await;
        assert_eq!(again.status(), StatusCode::BAD_REQUEST, "使った招待は二度使えない");
    }

    #[tokio::test]
    async fn registered_address_gets_no_link() {
        let p = provider(&["amate"]).await;
        let first = invite(&p, basic("amate", "s3cret"), "a@example.com", &format!("{RP_ORIGIN}/")).await;
        let token = token_of(body_json(first).await["url"].as_str().unwrap());
        assert_eq!(register_with_token(&p, &token).await, StatusCode::CREATED);

        let resp = invite(&p, basic("amate", "s3cret"), "a@example.com", &format!("{RP_ORIGIN}/")).await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = body_json(resp).await;
        assert_eq!(body["status"], "registered");
        assert!(body.get("url").is_none());
    }

    #[tokio::test]
    async fn clients_outside_the_allow_list_are_refused() {
        let p = provider(&["amate", "public"]).await;
        let rt = format!("{RP_ORIGIN}/auth/login");
        assert_eq!(invite(&p, basic("other", "s3cret"), "a@example.com", &rt).await.status(), StatusCode::FORBIDDEN);
        assert_eq!(invite(&p, basic("amate", "wrong"), "a@example.com", &rt).await.status(), StatusCode::UNAUTHORIZED);
        let public = invite_create(
            State(p.clone()),
            HeaderMap::new(),
            form(&[("client_id", "public"), ("email", "a@example.com"), ("return_to", &rt)]),
        )
        .await;
        assert_eq!(public.status(), StatusCode::FORBIDDEN, "public client は許可一覧にあっても招待できない");
        let nobody = provider(&[]).await;
        assert_eq!(invite(&nobody, basic("amate", "s3cret"), "a@example.com", &rt).await.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn return_to_must_stay_under_a_registered_origin() {
        let p = provider(&["amate"]).await;
        for bad in [
            "https://evil.example/auth/login",
            "https://amate.example.evil.example/",
            "https://amate.example@evil.example/",
            "http://amate.example/auth/login",
            "javascript:alert(1)",
            "https://amate.example/\"</script>",
            "",
        ] {
            let resp = invite(&p, basic("amate", "s3cret"), "a@example.com", bad).await;
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST, "{bad}");
        }
    }

    #[tokio::test]
    async fn ordinary_signup_token_is_not_an_invite() {
        let p = provider(&["amate"]).await;
        let fs = p.firestore.as_ref().unwrap();
        let token = crate::registration::create_email_challenge(fs, "a@example.com").await.unwrap();
        let resp = invite_page(State(p.clone()), Query(MagicQuery { t: token })).await;
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn script_embedding_cannot_close_the_script_tag() {
        assert_eq!(js_string_literal("a</script>\""), "\"a\\u003c/script>\\\"\"");
        assert_eq!(js_string_literal(""), "\"\"");
    }
}
