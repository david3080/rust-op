use super::*;

/* ===== discovery / jwks ===== */

pub(super) async fn discovery(State(p): State<Arc<Provider>>) -> Json<serde_json::Value> {
    let i = &p.issuer;
    Json(serde_json::json!({
        "issuer": i,
        "authorization_endpoint": format!("{i}/authorize"),
        "token_endpoint": format!("{i}/token"),
        "introspection_endpoint": format!("{i}/introspect"),
        "revocation_endpoint": format!("{i}/revoke"),
        "userinfo_endpoint": format!("{i}/userinfo"),
        "jwks_uri": format!("{i}/jwks"),
        "response_types_supported": ["code"],
        "grant_types_supported": p.grants.keys().collect::<Vec<_>>(),
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": p.all_signers().map(|s| s.alg()).collect::<Vec<_>>(),
        "scopes_supported": ["openid", "profile", "email", "address", "phone", "offline_access"],
        "claims_supported": crate::claims::all_supported_claims(),
        "claims_parameter_supported": false,
        "acr_values_supported": ["0", "1", "urn:mace:incommon:iap:bronze"],
        "token_endpoint_auth_methods_supported": p.client_auth.keys().collect::<Vec<_>>(),
        "code_challenge_methods_supported": ["S256"],
        "dpop_signing_alg_values_supported": ["ES256"],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256"],
        // JAR (RFC 9101): signed request object 対応。request_uri は PAR 経由のみ（SSRF 回避で false）。
        "request_parameter_supported": true,
        "request_uri_parameter_supported": false,
        "require_request_uri_registration": false,
        "request_object_signing_alg_values_supported": ["ES256"],
        "backchannel_authentication_request_signing_alg_values_supported": ["ES256"],
        "pushed_authorization_request_endpoint": format!("{i}/par"),
        "end_session_endpoint": format!("{i}/end-session"),
        "authorization_response_iss_parameter_supported": true,
        "backchannel_authentication_endpoint": format!("{i}/backchannel-authentication"),
        "backchannel_token_delivery_modes_supported": ["poll"],
        "backchannel_user_code_parameter_supported": false,
        // 独自エンドポイント（OIDC 標準外）。RP/アプリはここから URL を引き、
        // パスをハードコードしない（OP 側の改名にアプリ無改修で追従できる）。
        // 標準名前空間を汚さないようベンダー名前空間にまとめる。
        "sonrisa_endpoints": sonrisa_endpoints(i),
    }))
}

/// 独自エンドポイント（OIDC 標準外）の URL 群。アプリはここから引く。
/// アプリ側の期待キー/パスとの契約なので、各値は対応する route と一致させること。
fn sonrisa_endpoints(i: &str) -> serde_json::Value {
    serde_json::json!({
        "signup_email_challenge": format!("{i}/signup/email-challenge"),
        "signup_verify_email": format!("{i}/signup/verify-email"),
        "signup_passkey_options": format!("{i}/signup/passkey/options"),
        "signup_passkey_verify": format!("{i}/signup/passkey/verify"),
        "profile": format!("{i}/me/profile"),
        "fcm_token": format!("{i}/ciba/fcm-tokens"),
        "mandate_consume": format!("{i}/oauth/mandate/consume"),
    })
}

pub(super) async fn jwks(State(p): State<Arc<Provider>>) -> Json<serde_json::Value> {
    let keys: Vec<_> = p.all_signers().map(|s| s.public_jwk()).collect();
    Json(serde_json::json!({ "keys": keys }))
}
/* ===== authorize ===== */

pub(super) async fn authorize(
    State(p): State<Arc<Provider>>,
    jar: CookieJar,
    RawQuery(raw): RawQuery,
) -> Response {
    let raw = raw.unwrap_or_default();
    // 非 PAR の素の request_uri は run_checks 後に拒否する（SSRF 回避、PAR-only 維持）。
    let q0: HashMap<String, String> = serde_urlencoded::from_str(&raw).unwrap_or_default();
    let has_nonpar_request_uri = q0
        .get("request_uri")
        .map(|u| !u.starts_with(crate::par::URN_PREFIX))
        .unwrap_or(false);
    // PAR: urn 形式の request_uri があれば保存済みパラメータを復元する。
    let mut par_used = false;
    let mut par_creator: Option<String> = None;
    let mut par_request_uri: Option<String> = None;
    let raw = if let Some(req) = q0.get("request") {
        // JAR (RFC 9101): 直接の request object。client_id で client を引き署名検証する。
        let cid = q0.get("client_id").map(|s| s.as_str()).unwrap_or("");
        let client = match p.clients.get(cid) {
            Some(c) => c,
            None => return plain_error("unknown client for request object"),
        };
        match crate::request_object::verify(client, req, &p.issuer, &p.jar_jti).await {
            Ok(params) => serde_urlencoded::to_string(&params).unwrap_or_default(),
            Err(e) => return plain_error(&format!("invalid request object: {}", e.description())),
        }
    } else {
        match q0.get("request_uri") {
            Some(request_uri) if request_uri.starts_with(crate::par::URN_PREFIX) => {
                let fs = match &p.firestore {
                    Some(fs) => fs,
                    None => return plain_error("PAR unavailable (no Firestore)"),
                };
                // peek: 削除しない。認可完了前は再利用可。コード発行時に delete で単回化する。
                match crate::par::peek(fs, request_uri).await {
                    Ok(Some((cid, params))) => {
                        par_used = true;
                        par_creator = Some(cid);
                        par_request_uri = Some(request_uri.clone());
                        params
                    }
                    _ => return plain_error("invalid or expired request_uri"),
                }
            }
            _ => raw,
        }
    };
    // RFC 9126: request_uri は発行先クライアントに束縛される。authorize の client_id が
    // PAR 作成クライアントと異なる場合は拒否する（別クライアントによる request_uri 流用防止）。
    if let (Some(creator), Some(req_cid)) = (&par_creator, q0.get("client_id")) {
        if req_cid != creator {
            return plain_error("request_uri was issued to a different client");
        }
    }
    let params: AuthParams = match serde_urlencoded::from_str(&raw) {
        Ok(p) => p,
        Err(e) => return plain_error(&format!("invalid query: {e}")),
    };
    let mut ctx = AuthContext::new(params);
    ctx.request_uri = par_request_uri.clone();

    if let Err(e) = run_checks(&p, &mut ctx).await {
        return authorize_error(&p, &ctx, e);
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
            request_uri: par_request_uri,
        })
        .await;
    Redirect::to(&p.path(&format!("/login/{uid}"))).into_response()
}

pub(super) async fn authorize_resume(
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
    ctx.request_uri = interaction.request_uri.clone();
    if let Err(e) = run_checks(&p, &mut ctx).await {
        return authorize_error(&p, &ctx, e);
    }
    ctx.account_id = Some(account_id);
    ctx.auth_time = interaction.auth_time;
    // 完了済み interaction を単回消費してからコード発行。失敗（既に消費＝リプレイ/二重投入）なら
    // 再発行しない（1認証=1コード、PAR request_uri の単回化も保つ）。
    if !p.store.consume_interaction(uid).await {
        return plain_error("interaction already used");
    }
    issue_code(&p, &ctx).await
}

/// ユーザーがログイン画面で「キャンセル」した場合に、登録済み redirect_uri へ
/// access_denied を返す（OIDC Core 3.1.2.6 / RFC 6749 §4.1.2.1）。
pub(super) async fn authorize_cancel(
    State(p): State<Arc<Provider>>,
    Path(uid): Path<String>,
) -> Response {
    let interaction = match p.store.get_interaction(&uid).await {
        Some(i) => i,
        None => return plain_error("interaction not found"),
    };
    let params: AuthParams = match serde_urlencoded::from_str(&interaction.raw_query) {
        Ok(p) => p,
        Err(e) => return plain_error(&format!("invalid stored query: {e}")),
    };
    let mut ctx = AuthContext::new(params);
    ctx.request_uri = interaction.request_uri.clone();
    // redirect_uri を検証してから error redirect する（未登録 URI には返さない）。
    if let Err(e) = run_checks(&p, &mut ctx).await {
        return authorize_error(&p, &ctx, e);
    }
    authorize_error(
        &p,
        &ctx,
        OAuthError::AccessDenied("end-user denied the request".into()),
    )
}

async fn run_checks(p: &Provider, ctx: &mut AuthContext) -> Result<(), OAuthError> {
    for check in &p.checks {
        check.check(p, ctx).await?;
    }
    Ok(())
}

/// Resource Indicators (RFC 8707): resource は fragment 無しの絶対 URI。
fn valid_resource(r: &str) -> bool {
    !r.contains('#') && r.split_once("://").is_some_and(|(s, rest)| !s.is_empty() && !rest.is_empty())
}

/// 検証通過後、認可コードを発行して redirect_uri に返す。
async fn issue_code(p: &Provider, ctx: &AuthContext) -> Response {
    let redirect_uri = ctx.redirect_uri.clone().expect("redirect validated");
    let account_id = ctx.account_id.clone().expect("account present");
    if let Some(r) = &ctx.params.resource {
        if !valid_resource(r) {
            return authorize_error(
                p,
                ctx,
                OAuthError::InvalidTarget("resource must be an absolute URI without fragment".into()),
            );
        }
    }
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
            dpop_jkt: ctx.params.dpop_jkt.clone(),
            resource: ctx.params.resource.clone(),
            expires_at: now() + 60,
        })
        .await;

    // 認可完了: PAR の request_uri を削除して以後の再利用を不可にする（RFC 9126）。
    if let (Some(ru), Some(fs)) = (&ctx.request_uri, &p.firestore) {
        crate::par::delete(fs, ru).await;
    }

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
/* ===== token ===== */

pub(super) async fn token(
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
            match p.dpop.verify(&proof, "POST", &htu, None).await {
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

/* ===== Token Introspection (RFC 7662) ===== */

/// introspect は資格情報で認証できる confidential クライアント(RS)のみ許可する。
/// public(none) は認証不可なのでトークン有効性オラクルを与えない。
fn require_confidential(client: &crate::model::Client) -> Result<(), OAuthError> {
    if client.is_public() {
        return Err(OAuthError::InvalidClient(
            "confidential client authentication required".into(),
        ));
    }
    Ok(())
}

/// 有効トークンの introspection 応答本体（active=true）。
/// DPoP 束縛トークンは cnf.jkt を含め、RS が proof と照合できるようにする。
fn introspection_active_body(at: &crate::model::AccessToken) -> serde_json::Value {
    let mut body = serde_json::json!({
        "active": true,
        "scope": at.scope,
        "client_id": at.client_id,
        "sub": at.account_id,
        "token_type": if at.jkt.is_some() { "DPoP" } else { "Bearer" },
    });
    if let Some(jkt) = &at.jkt {
        body["cnf"] = serde_json::json!({ "jkt": jkt });
    }
    if let Some(aud) = &at.aud {
        body["aud"] = serde_json::json!(aud);
    }
    // Step-up Authentication Challenge (RFC 9470): RS が acr/auth_time で十分性を判断する。
    if let Some(acr) = &at.acr {
        body["acr"] = serde_json::json!(acr);
    }
    if let Some(t) = at.auth_time {
        body["auth_time"] = serde_json::json!(t);
    }
    // RFC 9396: 承認済み mandate を RS に伝える。RS は request body と照合する。
    if let Some(ad) = at.authorization_details.as_deref() {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(ad) {
            body["authorization_details"] = v;
        }
    }
    body
}

/// 分離した RS 向けのトークン検証窓口。同居エンドポイント(/profile, /userinfo)は
/// 従来どおり store 直引きで検証するため、これは外部 RS だけが使う。
/// 呼び出し元(RS)は confidential クライアント認証必須。無効トークンは active=false のみ返す。
pub(super) async fn introspect(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    // RFC 7662 §2.1: 呼び出し元は認証必須。public(none) は不可（資格情報で認証できる RS のみ）。
    let client = match authenticate_client(&p, &headers, &form).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(e) = require_confidential(&client) {
        return e.into_response();
    }
    let token = match form.get("token") {
        Some(t) => t,
        None => return OAuthError::InvalidRequest("token required".into()).into_response(),
    };
    // RFC 7662 §2.2: 無効/未知/失効は active=false のみ（それ以外の情報は漏らさない）。
    // access token のみ対象。期限切れ/未知は get_access_token が None を返す。
    let body = match p.store.get_access_token(token).await {
        Some(at) => introspection_active_body(&at),
        None => serde_json::json!({ "active": false }),
    };
    ([(header::CACHE_CONTROL, "no-store")], Json(body)).into_response()
}
/// RFC 9396 mandate の単回消費窓口。RS が introspection で mandate を確認 → body と一致したら
/// この endpoint を CAS 呼び出し → 成功した呼び出しだけ実行に進む。
/// 認証は introspection と同じ confidential client 必須（呼べる RS を絞る）。
pub(super) async fn mandate_consume(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let client = match authenticate_client(&p, &headers, &form).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    if let Err(e) = require_confidential(&client) {
        return e.into_response();
    }
    let token = match form.get("token") {
        Some(t) => t,
        None => return OAuthError::InvalidRequest("token required".into()).into_response(),
    };
    let consumed = match p.store.consume_mandate_if_unused(token).await {
        Ok(b) => b,
        Err(e) => {
            tracing::error!("consume_mandate_if_unused: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "error").into_response();
        }
    };
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(serde_json::json!({ "consumed": consumed })),
    )
        .into_response()
}

/* ===== Token Revocation (RFC 7009) ===== */

/// クライアントが自分のトークンを失効する。token endpoint と同じクライアント認証。
/// public クライアントも自分のトークンを失効できる（RFC 7009）。
/// 所有者でない/未知トークンでも 200 を返す（情報を漏らさない）。
pub(super) async fn revoke(
    State(p): State<Arc<Provider>>,
    headers: HeaderMap,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let client = match authenticate_client(&p, &headers, &form).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    let token = match form.get("token") {
        Some(t) => t,
        None => return OAuthError::InvalidRequest("token required".into()).into_response(),
    };
    // token_type_hint は最適化のみ。access/refresh の両方を試す。
    // 自分(client_id 一致)のトークンだけ失効する。
    if let Some(at) = p.store.get_access_token(token).await {
        if at.client_id == client.client_id {
            p.store.revoke_access_token(token).await;
        }
    }
    if let Some(rt) = p.store.get_refresh_token(token).await {
        if rt.client_id == client.client_id {
            p.store.revoke_refresh_token(token).await;
        }
    }
    // RFC 7009 §2.2: 成功・無効トークンいずれも 200。
    ([(header::CACHE_CONTROL, "no-store")], StatusCode::OK).into_response()
}
/* ===== RP-Initiated Logout (OpenID Connect RP-Initiated Logout 1.0) ===== */

#[derive(serde::Deserialize)]
pub(super) struct EndSessionQuery {
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

pub(super) async fn end_session(
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

pub(super) async fn par(State(p): State<Arc<Provider>>, headers: HeaderMap, body: String) -> Response {
    let fs = match &p.firestore {
        Some(f) => f,
        None => return (StatusCode::SERVICE_UNAVAILABLE, "no firestore").into_response(),
    };
    let form: HashMap<String, String> = serde_urlencoded::from_str(&body).unwrap_or_default();
    // RFC 9126 §2.1: PAR リクエスト自体に request_uri を含めてはならない。
    if form.contains_key("request_uri") {
        return OAuthError::InvalidRequest("request_uri must not be used in a PAR request".into())
            .into_response();
    }
    let client = match authenticate_client(&p, &headers, &form).await {
        Ok(c) => c,
        Err(r) => return r,
    };
    // JAR (RFC 9101): request object があれば検証し、保存パラメータをその claims で
    // 置き換える（以後の処理・/authorize は検証済みパラメータを使う）。
    let body = if let Some(req) = form.get("request") {
        match crate::request_object::verify(&client, req, &p.issuer, &p.jar_jti).await {
            Ok(params) => serde_urlencoded::to_string(&params).unwrap_or_default(),
            Err(e) => return e.into_response(),
        }
    } else {
        body
    };
    let form: HashMap<String, String> = serde_urlencoded::from_str(&body).unwrap_or_default();
    // PAR 本体の client_id は認証済みクライアントと一致すること。
    if let Some(cid) = form.get("client_id") {
        if cid != &client.client_id {
            return OAuthError::InvalidRequest("client_id mismatch".into()).into_response();
        }
    }
    // DPoP at PAR (RFC 9449 §10): PAR が DPoP 署名されていれば、その proof の jkt に
    // 認可を束縛する。dpop_jkt パラメータがあれば proof と一致必須。proof のみなら
    // jkt を dpop_jkt として注入し、token endpoint で束縛を強制する。
    let body = if let Some(proof) = dpop_header(&headers) {
        let htu = format!("{}/par", p.issuer);
        let jkt = match p.dpop.verify(&proof, "POST", &htu, None).await {
            Ok(j) => j,
            Err(e) => return OAuthError::InvalidDpopProof(e).into_response(),
        };
        match form.get("dpop_jkt") {
            Some(req) if req != &jkt => {
                return OAuthError::InvalidDpopProof(
                    "dpop_jkt does not match the DPoP proof presented to the PAR endpoint".into(),
                )
                .into_response()
            }
            Some(_) => body,                       // 一致: そのまま
            None => format!("{body}&dpop_jkt={jkt}"), // proof の jkt を束縛として注入
        }
    } else {
        body
    };
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

pub(super) async fn profile_get(State(p): State<Arc<Provider>>, headers: HeaderMap) -> Response {
    let at = match authenticate_token(&p, &headers, "GET", "/me/profile", None).await {
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

pub(super) async fn profile_put(State(p): State<Arc<Provider>>, headers: HeaderMap, body: String) -> Response {
    let at = match authenticate_token(&p, &headers, "PUT", "/me/profile", None).await {
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

pub(super) async fn userinfo_get(State(p): State<Arc<Provider>>, headers: HeaderMap) -> Response {
    userinfo_respond(&p, &headers, "GET", None).await
}

/// POST userinfo（Bearer/DPoP ヘッダ、無ければ body の access_token）。
pub(super) async fn userinfo_post(State(p): State<Arc<Provider>>, headers: HeaderMap, body: String) -> Response {
    let body_token = serde_urlencoded::from_str::<HashMap<String, String>>(&body)
        .ok()
        .and_then(|m| m.get("access_token").cloned());
    userinfo_respond(&p, &headers, "POST", body_token).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::AccessToken;

    /// discovery で発行する独自エンドポイント＝アプリ(fido2demo)が読むキー/パスの契約。
    /// route を改名したらここも一致させる（clean-cut 運用での divergence を検出する）。
    #[test]
    fn sonrisa_endpoints_contract() {
        let v = sonrisa_endpoints("https://op.example/oidc");
        assert_eq!(v["signup_email_challenge"], "https://op.example/oidc/signup/email-challenge");
        assert_eq!(v["signup_verify_email"], "https://op.example/oidc/signup/verify-email");
        assert_eq!(v["signup_passkey_options"], "https://op.example/oidc/signup/passkey/options");
        assert_eq!(v["signup_passkey_verify"], "https://op.example/oidc/signup/passkey/verify");
        assert_eq!(v["profile"], "https://op.example/oidc/me/profile");
        assert_eq!(v["fcm_token"], "https://op.example/oidc/ciba/fcm-tokens");
        assert_eq!(v["mandate_consume"], "https://op.example/oidc/oauth/mandate/consume");
    }

    fn at(jkt: Option<&str>) -> AccessToken {
        AccessToken {
            token: "AT".into(),
            client_id: "rp".into(),
            account_id: "user@example.com".into(),
            scope: "openid profile".into(),
            jkt: jkt.map(str::to_string),
            aud: None,
            acr: None,
            auth_time: None,
            authorization_details: None,
            mandate_consumed: false,
        }
    }

    fn client(method: &str) -> crate::model::Client {
        crate::model::Client {
            client_id: "rs".into(),
            redirect_uris: vec![],
            token_endpoint_auth_method: method.into(),
            client_secret: None,
            grant_types: vec![],
            post_logout_redirect_uris: vec![],
            dpop_bound: false,
            jwks: vec![],
            require_par: false,
            require_pkce: false,
            id_token_signed_response_alg: None,
        }
    }

    #[test]
    fn introspect_requires_confidential_client() {
        // public(none) は拒否、confidential は許可。
        assert!(require_confidential(&client("none")).is_err());
        assert!(require_confidential(&client("client_secret_basic")).is_ok());
        assert!(require_confidential(&client("private_key_jwt")).is_ok());
    }

    #[test]
    fn introspection_dpop_token_includes_cnf_jkt() {
        let b = introspection_active_body(&at(Some("JKT123")));
        assert_eq!(b["active"], true);
        assert_eq!(b["token_type"], "DPoP");
        assert_eq!(b["sub"], "user@example.com");
        assert_eq!(b["scope"], "openid profile");
        assert_eq!(b["client_id"], "rp");
        assert_eq!(b["cnf"]["jkt"], "JKT123");
    }

    #[test]
    fn introspection_bearer_token_has_no_cnf() {
        let b = introspection_active_body(&at(None));
        assert_eq!(b["active"], true);
        assert_eq!(b["token_type"], "Bearer");
        assert!(b.get("cnf").is_none());
    }

    #[test]
    fn introspection_includes_aud_when_resource_bound() {
        let mut a = at(None);
        a.aud = Some("https://api.example.com".into());
        let b = introspection_active_body(&a);
        assert_eq!(b["aud"], "https://api.example.com");
    }

    #[test]
    fn introspection_exposes_acr_and_auth_time_for_step_up() {
        let mut a = at(None);
        a.acr = Some("urn:acr:bronze".into());
        a.auth_time = Some(1_700_000_000);
        let b = introspection_active_body(&a);
        assert_eq!(b["acr"], "urn:acr:bronze");
        assert_eq!(b["auth_time"], 1_700_000_000u64);
    }

    #[test]
    fn valid_resource_requires_absolute_uri_without_fragment() {
        assert!(valid_resource("https://api.example.com"));
        assert!(valid_resource("https://api.example.com/v1"));
        assert!(!valid_resource("api.example.com")); // scheme なし
        assert!(!valid_resource("https://api.example.com/#x")); // fragment 不可
        assert!(!valid_resource("://x")); // scheme 空
    }
}
