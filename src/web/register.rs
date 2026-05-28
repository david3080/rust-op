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
pub(super) struct RegisterForm {
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

pub(super) async fn register_submit(
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
pub(super) struct EmailChallengeReq {
    email: String,
}

pub(super) async fn register_email_challenge(
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

/// passkey 作成（ブラウザ）ページ。メールリンク /r と /register/verify で共用。
/// iPhone は AASA(Universal Link)でアプリが横取りするため通常この HTML は出ず、
/// PC/Mac やアプリ未対応端末ではこのページでブラウザ passkey 登録を完結できる。
fn passkey_register_page(p: &Provider, token: &str) -> Html<String> {
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
const TOKEN="__TOKEN__",OPT="__OPT__",VER="__VER__",LOGIN="__LOGIN__";
const ua=navigator.userAgent;
const isAndroid=/Android/i.test(ua);
const isIOS=/iPad|iPhone|iPod/i.test(ua)||(/(Macintosh).*Mobile/i.test(ua));
document.getElementById((isAndroid||isIOS)?'mobile':'desktop').hidden=false;
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
pub(super) struct MagicQuery {
    t: String,
}

pub(super) async fn magic_redirect(State(p): State<Arc<Provider>>, Query(q): Query<MagicQuery>) -> Html<String> {
    passkey_register_page(&p, &q.t)
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

/// Web フォーム経由（/register/verify?token=）の着地点。
pub(super) async fn verify_form(State(p): State<Arc<Provider>>, Query(q): Query<VerifyQuery>) -> Html<String> {
    passkey_register_page(&p, &q.token)
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
