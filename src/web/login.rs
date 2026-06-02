use super::*;

pub(super) async fn login_form(State(p): State<Arc<Provider>>, Path(uid): Path<String>) -> Html<String> {
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
<button class="outlined" onclick="location.href='__CANCEL__'">キャンセル</button>
<p id="msg"></p>
__PWFORM__
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
    // パスワードフォームはテスト/コンフォーマンス時のみ表示（本番は passkey のみ）。
    let pwform = if super::password_login_enabled() {
        format!(
            r##"<details><summary>パスワード (テスト用)</summary>
<form method="post" action="{login}">
<input name="username" placeholder="email"><input name="password" type="password" placeholder="password">
<button class="filled" type="submit" style="margin-top:8px">ログイン</button></form></details>"##,
            login = p.path(&format!("/interaction/{uid}/login")),
        )
    } else {
        String::new()
    };
    Html(
        body.replace("__WEBAUTHN_JS__", WEBAUTHN_JS)
            .replace("__OPT__", &p.path(&format!("/interaction/{uid}/passkey/options")))
            .replace("__VER__", &p.path(&format!("/interaction/{uid}/passkey/verify")))
            .replace("__PWFORM__", &pwform)
            .replace("__CANCEL__", &p.path(&format!("/interaction/{uid}/cancel")))
            .replace("__REGISTER__", &p.path("/register")),
    )
}

#[derive(serde::Deserialize)]
pub(super) struct LoginForm {
    username: String,
    password: String,
}

pub(super) async fn login_submit(
    State(p): State<Arc<Provider>>,
    jar: CookieJar,
    Path(uid): Path<String>,
    Form(form): Form<LoginForm>,
) -> Response {
    // 多層防御: ルート未登録（本番）でも万一到達したら拒否する。
    if !super::password_login_enabled() {
        return (StatusCode::NOT_FOUND, "not found").into_response();
    }
    // conformance/demo 用の固定資格情報バイパス（a/a）。実ユーザーは passkey を使う。
    let raw = form.username.trim();
    if !(raw == p.demo_user && form.password == p.demo_pass) {
        tracing::warn!(event = "login_failed", method = "password");
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
    tracing::info!(event = "login_success", sub = %account_sub);
    p.store.save_interaction(interaction).await;
    let sid = uuid::Uuid::new_v4().to_string();
    p.store
        .save_session(Session { sid: sid.clone(), account_id: account_sub, auth_time })
        .await;
    let cookie = Cookie::build((SID_COOKIE, sid))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .build();
    (jar.add(cookie), p.path(&format!("/authorize/resume?uid={uid}")))
}

/* ===== passkey ログイン ===== */

#[derive(serde::Deserialize)]
pub(super) struct LoginPkOptionsReq {
    #[serde(default)]
    email: String,
}

pub(super) async fn login_passkey_options(
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

pub(super) async fn login_passkey_verify(
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
        false, // 通常ログインは UP のみ（従来通り）
    ) {
        Ok(new_count) => {
            let _ = crate::registration::update_sign_count(fs, &email, new_count).await;
        }
        Err(e) => {
            tracing::warn!(event = "login_failed", method = "passkey", "webauthn auth failed: {e}");
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
