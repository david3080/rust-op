//! 登録→ログイン→CIBA承認を実 Firestore エミュレータに対して流し、account_id(UUID)が
//! 一貫して使われ、email が sub/user.id/CIBA account に漏れないことを検証する。
//!
//! 実行手順:
//!   firebase emulators:start --only firestore   (別ターミナルで常駐させる)
//!   FIRESTORE_EMULATOR_HOST=127.0.0.1:8180 cargo test -- --ignored web::emulator_tests
//!
//! 通常の `cargo test` では走らない（エミュレータ常駐を前提にしないため）。

use super::*;
use crate::ciba::CibaStatus;
use crate::fido::verify::test_support::*;
use crate::fido::verify::{FLAG_AT, FLAG_UP, FLAG_UV};
use crate::model::Client;
use ciborium::value::Value as Cbor;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};

fn test_provider() -> Arc<Provider> {
    let fs = Arc::new(crate::firestore::Firestore::new("test-emu-probe"));
    // with_firestore は registration:: の直叩き用、with_store は Store トレイト
    // (interaction/session/find_account 等)用で別物。本番(Cloud Run)は両方 Firestore を指すので
    // テストでもここを MemoryStore の既定のままにしない（find_account が PoC ダミー生成に
    // フォールバックしてしまい、firestore_store.rs の実装を検証できなくなる）。
    // ciba は意図的に既定の MemoryCibaStore のまま（FirestoreCibaStore にしない）。
    // 理由: Firestore エミュレータは `currentDocument.updateTime` による楽観ロックCASを
    // 正しく実装していない（updateTime 文字列を数値バージョンとして解釈し、常に
    // FAILED_PRECONDITION になる。exists=false による CAS は正常動作することを curl で確認済み）。
    // ciba_approve のハンドラ側ロジック(email/account_id の解決)は CibaStore の実装に依らず
    // 同一なので、MemoryCibaStore でも本テストの目的(識別子の一貫性)は検証できる。
    // FirestoreCibaStore 自体の updateTime CAS 検証は、この制約のため別の方法が必要
    // （実 Firestore に対する統合テスト等）。
    let p = Provider::new("http://localhost:8099".to_string())
        .with_firestore(fs.clone())
        .with_store(Arc::new(crate::firestore_store::FirestoreStore::new(fs)))
        .with_client(Client {
            client_id: "test-ciba-rp".into(),
            redirect_uris: vec![],
            post_logout_redirect_uris: vec![],
            token_endpoint_auth_method: "none".into(),
            client_secret: None,
            grant_types: vec!["urn:openid:params:grant-type:ciba".into()],
            dpop_bound: false,
            jwks: vec![],
            jwks_uri: None,
            require_par: false,
            require_pkce: false,
            id_token_signed_response_alg: None,
        });
    Arc::new(p)
}

fn make_reg_ceremony(key: &SigningKey, cred_id: &[u8], challenge: &str, origin: &str, rp_id: &str) -> (String, String) {
    let (x, y) = ec_xy(key);
    let cose = cose_es256(&x, &y);
    let acd = attested_cred_data(cred_id, &cose);
    let auth_data = build_auth_data(rp_id, FLAG_UP | FLAG_AT, 0, Some(&acd));
    let att = Cbor::Map(vec![
        (Cbor::Text("fmt".into()), Cbor::Text("none".into())),
        (Cbor::Text("attStmt".into()), Cbor::Map(vec![])),
        (Cbor::Text("authData".into()), Cbor::Bytes(auth_data)),
    ]);
    let cdj = client_data_json("webauthn.create", challenge, origin);
    (crate::webauthn::b64e(&cbor_to_vec(&att)), crate::webauthn::b64e(&cdj))
}

fn make_auth_ceremony(
    key: &SigningKey,
    sign_count: u32,
    challenge: &str,
    origin: &str,
    rp_id: &str,
    uv: bool,
) -> (String, String, String) {
    let flags = if uv { FLAG_UP | FLAG_UV } else { FLAG_UP };
    let auth_data = build_auth_data(rp_id, flags, sign_count, None);
    let cdj = client_data_json("webauthn.get", challenge, origin);
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(&cdj));
    let sig: Signature = key.sign(&signed);
    (
        crate::webauthn::b64e(&auth_data),
        crate::webauthn::b64e(sig.to_der().as_bytes()),
        crate::webauthn::b64e(&cdj),
    )
}

async fn body_json(resp: Response) -> serde_json::Value {
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|e| panic!("status={status} body not json: {e} raw={}", String::from_utf8_lossy(&bytes)))
}

async fn body_text(resp: Response) -> String {
    let bytes = axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    String::from_utf8_lossy(&bytes).to_string()
}

/// email 確認は registration:: を直接叩き、passkey 登録は実 HTTP ハンドラを通す。
/// 戻り値: (SigningKey, credential_id, account_id)。
async fn register_test_account(p: &Arc<Provider>, email: &str) -> (SigningKey, Vec<u8>, String) {
    let fs = p.firestore.as_ref().unwrap();
    let email_token = crate::registration::create_email_challenge(fs, email).await.unwrap();

    let opts_req: register::RegPkOptionsReq =
        serde_json::from_value(json!({ "token": email_token })).unwrap();
    let opts = register::register_passkey_options(State(p.clone()), Json(opts_req)).await;
    assert_eq!(opts.status(), StatusCode::OK);
    let opts_json = body_json(opts).await;
    let challenge = opts_json["challenge"].as_str().unwrap().to_string();
    let user_id_b64 = opts_json["user"]["id"].as_str().unwrap().to_string();
    let account_id_from_options =
        String::from_utf8(crate::es256::b64url_decode(&user_id_b64).unwrap()).unwrap();
    // WebAuthn user.id は不透明な account_id(UUID) であり、email を含んではならない。
    assert!(!account_id_from_options.contains('@'), "user.id leaks email: {account_id_from_options}");
    assert!(
        uuid::Uuid::parse_str(&account_id_from_options).is_ok(),
        "user.id is not a uuid: {account_id_from_options}"
    );

    let key = SigningKey::random(&mut rand_core::OsRng);
    let cred_id = b"probe-credential-id".to_vec();
    let (att_b64, cdj_b64) = make_reg_ceremony(&key, &cred_id, &challenge, &p.origin(), &p.rp_id());

    let verify_req: register::RegVerifyReq = serde_json::from_value(json!({
        "token": email_token,
        "response": { "clientDataJSON": cdj_b64, "attestationObject": att_b64 },
    }))
    .unwrap();
    let verify = register::register_passkey_verify(State(p.clone()), Json(verify_req)).await;
    let verify_status = verify.status();
    let verify_body = body_json(verify).await;
    assert_eq!(verify_status, StatusCode::CREATED, "register_passkey_verify failed: {verify_body:?}");

    let cred = crate::registration::get_credential(fs, email).await.unwrap().unwrap();
    assert_eq!(cred.account_id, account_id_from_options, "options 時点の account_id と保存後の accountId が食い違う");

    // 逆引きインデックスも書けている。
    let looked_up = crate::registration::find_email_by_account_id(fs, &cred.account_id).await.unwrap();
    assert_eq!(looked_up.as_deref(), Some(email), "accountsByUuid の逆引きが email と一致しない");

    (key, cred_id, cred.account_id)
}

/// ログイン成功後の Interaction.account_id（= 最終的に発行される sub）を返す。
async fn login_with_email(p: &Arc<Provider>, email: &str, key: &SigningKey, sign_count: u32) -> String {
    let uid = uuid::Uuid::new_v4().to_string();
    p.store
        .save_interaction(Interaction {
            uid: uid.clone(),
            raw_query: String::new(),
            account_id: None,
            auth_time: None,
            request_uri: None,
        })
        .await;

    let opts_req: login::LoginPkOptionsReq = serde_json::from_value(json!({ "email": email })).unwrap();
    let opts = login::login_passkey_options(State(p.clone()), Path(uid.clone()), Json(opts_req)).await;
    assert_eq!(opts.status(), StatusCode::OK);
    let opts_json = body_json(opts).await;
    let challenge = opts_json["challenge"].as_str().unwrap().to_string();

    let (ad, sig, cdj) = make_auth_ceremony(key, sign_count, &challenge, &p.origin(), &p.rp_id(), false);
    let verify_req: AuthVerifyReq = serde_json::from_value(json!({
        "id": crate::webauthn::b64e(b"probe-credential-id"),
        "response": { "clientDataJSON": cdj, "authenticatorData": ad, "signature": sig, "userHandle": null },
    }))
    .unwrap();
    let verify =
        login::login_passkey_verify(State(p.clone()), CookieJar::default(), Path(uid.clone()), Json(verify_req))
            .await;
    let status = verify.status();
    let body = body_json(verify).await;
    assert_eq!(status, StatusCode::OK, "login (email) failed: {body:?}");

    // finalize_login は Interaction を削除せず account_id を書いて保存し直す
    // （/authorize/resume がこれを読んでコード発行に進むため）。
    let interaction = p.store.get_interaction(&uid).await.expect("interaction should still exist after login");
    interaction.account_id.expect("account_id should be set after successful login")
}

async fn login_discoverable(p: &Arc<Provider>, account_id: &str, key: &SigningKey, sign_count: u32) {
    let uid = uuid::Uuid::new_v4().to_string();
    p.store
        .save_interaction(Interaction {
            uid: uid.clone(),
            raw_query: String::new(),
            account_id: None,
            auth_time: None,
            request_uri: None,
        })
        .await;

    let opts_req: login::LoginPkOptionsReq = serde_json::from_value(json!({})).unwrap();
    let opts = login::login_passkey_options(State(p.clone()), Path(uid.clone()), Json(opts_req)).await;
    assert_eq!(opts.status(), StatusCode::OK);
    let opts_json = body_json(opts).await;
    let challenge = opts_json["challenge"].as_str().unwrap().to_string();

    let (ad, sig, cdj) = make_auth_ceremony(key, sign_count, &challenge, &p.origin(), &p.rp_id(), false);
    // userHandle = account_id(UUID)。email は一切登場しない。
    let user_handle_b64 = crate::webauthn::b64e(account_id.as_bytes());
    let verify_req: AuthVerifyReq = serde_json::from_value(json!({
        "id": crate::webauthn::b64e(b"probe-credential-id"),
        "response": { "clientDataJSON": cdj, "authenticatorData": ad, "signature": sig, "userHandle": user_handle_b64 },
    }))
    .unwrap();
    let verify =
        login::login_passkey_verify(State(p.clone()), CookieJar::default(), Path(uid.clone()), Json(verify_req))
            .await;
    let status = verify.status();
    let body = body_json(verify).await;
    assert_eq!(status, StatusCode::OK, "login (discoverable) failed: {body:?}");

    let interaction = p.store.get_interaction(&uid).await.expect("interaction should still exist after login");
    assert_eq!(
        interaction.account_id.as_deref(),
        Some(account_id),
        "discoverable ログインの最終 sub が userHandle の account_id と一致しない"
    );
}

/// DCR登録エンドポイント(oidc::register)が ConfidentialSecret プロファイルの IAT を
/// 正しく処理し、生成した client_secret をレスポンスへ一度だけ平文で載せつつ、
/// Firestore にはハッシュのみを保存することを実HTTPハンドラ経由で検証する。
/// dcr.rs の単体テストは validate_registration の戻り値を直接見るのみで、
/// raw_client_secret が register() ハンドラ経由で実際に配線されているかは見ていなかった。
#[tokio::test]
#[ignore]
async fn register_confidential_secret_returns_raw_secret_once() {
    let p = test_provider();
    let fs = p.firestore.as_ref().unwrap();

    let constraints = crate::dcr::IatConstraints {
        allowed_redirect_hosts: vec!["rp.example.com".into()],
        allowed_grant_types: vec!["authorization_code".into()],
        profile: crate::dcr::ClientProfile::ConfidentialSecret,
    };
    let (raw_iat, iat_hash) = crate::dcr::gen_random_token();
    let expires_at = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() + 3600;
    crate::dcr_store::put_iat(fs, &iat_hash, &constraints, expires_at, false).await.unwrap();

    let mut headers = HeaderMap::new();
    headers.insert(header::AUTHORIZATION, format!("Bearer {raw_iat}").parse().unwrap());
    let body = json!({ "redirect_uris": ["https://rp.example.com/cb"] }).to_string();

    let resp = oidc::register(State(p.clone()), headers, body).await;
    let status = resp.status();
    let resp_body = body_json(resp).await;
    assert_eq!(status, StatusCode::CREATED, "register failed: {resp_body:?}");
    assert_eq!(resp_body["token_endpoint_auth_method"], "client_secret_basic");
    assert_eq!(resp_body["client_secret_expires_at"], 0);
    let raw_secret = resp_body["client_secret"]
        .as_str()
        .expect("ConfidentialSecretはclient_secretを平文で返す");

    // 保存されているのはハッシュのみ(レスポンスで返した平文そのものではない)。
    let client_id = resp_body["client_id"].as_str().unwrap();
    let stored = crate::dcr_store::load_client(fs, client_id)
        .await
        .expect("client should be saved");
    assert_eq!(
        stored.client_secret.as_deref(),
        Some(crate::dcr::hash_token(raw_secret).as_str())
    );
    assert_ne!(stored.client_secret.as_deref(), Some(raw_secret));
}

/// account_admin::disable_account で凍結したアカウントが、実HTTPハンドラ(login_passkey_verify)
/// 経由でログインを拒否されることを検証する。login.rs 側の disabled チェックの配線確認。
#[tokio::test]
#[ignore]
async fn disabled_account_cannot_login() {
    let p = test_provider();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (key, _cred_id, _account_id) = register_test_account(&p, &email).await;

    let fs = p.firestore.as_ref().unwrap();
    let out = crate::account_admin::disable_account(fs, "test", &email).await.unwrap();
    assert!(matches!(out, crate::account_admin::DisableOutcome::Disabled { .. }));

    let uid = uuid::Uuid::new_v4().to_string();
    p.store
        .save_interaction(Interaction {
            uid: uid.clone(),
            raw_query: String::new(),
            account_id: None,
            auth_time: None,
            request_uri: None,
        })
        .await;

    let opts_req: login::LoginPkOptionsReq = serde_json::from_value(json!({ "email": email })).unwrap();
    let opts = login::login_passkey_options(State(p.clone()), Path(uid.clone()), Json(opts_req)).await;
    assert_eq!(opts.status(), StatusCode::OK, "options自体は通す(disabled状態を先出ししない)");
    let opts_json = body_json(opts).await;
    let challenge = opts_json["challenge"].as_str().unwrap().to_string();

    let (ad, sig, cdj) = make_auth_ceremony(&key, 0, &challenge, &p.origin(), &p.rp_id(), false);
    let verify_req: AuthVerifyReq = serde_json::from_value(json!({
        "id": crate::webauthn::b64e(b"probe-credential-id"),
        "response": { "clientDataJSON": cdj, "authenticatorData": ad, "signature": sig, "userHandle": null },
    }))
    .unwrap();
    let verify =
        login::login_passkey_verify(State(p.clone()), CookieJar::default(), Path(uid.clone()), Json(verify_req))
            .await;
    assert_eq!(verify.status(), StatusCode::FORBIDDEN, "disabled account should be rejected");
}

/// 管理UI経由でIATをmint→一度だけ表示→再訪問で「表示済み」になる一連の流れを実HTTPハンドラ
/// 経由で検証する。「一度きり表示」は read-then-delete の順序を間違えやすく、実装ミスに
/// 気付きにくいため、web/admin.rs のユニットテストとは別にここで通しで確認する。
#[tokio::test]
#[ignore]
async fn admin_mint_iat_flash_is_shown_once() {
    let p = test_provider();
    let email = format!("admin-{}@example.com", uuid::Uuid::new_v4());
    let (_key, _cred_id, account_id) = register_test_account(&p, &email).await;
    let fs = p.firestore.as_ref().unwrap();
    crate::admin_store::grant_admin(fs, &account_id, "test").await.unwrap();

    let sid = uuid::Uuid::new_v4().to_string();
    p.store
        .save_session(Session { sid: sid.clone(), account_id: account_id.clone(), auth_time: 0 })
        .await;
    let jar = CookieJar::default().add(Cookie::new(SID_COOKIE, sid));

    let form: admin::IatMintForm = serde_json::from_value(json!({
        "profile": "confidential-secret",
        "redirect_hosts": "rp.example.com",
        "grant_types": "",
        "ttl_hours": 1,
    }))
    .unwrap();
    let mint_resp = admin::iat_mint_submit(State(p.clone()), jar.clone(), Form(form)).await;
    assert!(mint_resp.status().is_redirection(), "mint成功後はリダイレクトすること: {}", mint_resp.status());
    let location = mint_resp
        .headers()
        .get(header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("Location header required")
        .to_string();
    let flash_id = location.rsplit('/').next().unwrap().to_string();

    let first = admin::iat_show_once(State(p.clone()), jar.clone(), Path(flash_id.clone())).await;
    assert_eq!(first.status(), StatusCode::OK);
    let first_body = body_text(first).await;
    assert!(first_body.contains("IATを発行しました"), "1回目は生トークンを表示すること: {first_body}");

    let second = admin::iat_show_once(State(p.clone()), jar.clone(), Path(flash_id)).await;
    let second_body = body_text(second).await;
    assert!(second_body.contains("表示済みです"), "2回目は「表示済み」になること: {second_body}");
}

#[tokio::test]
#[ignore]
async fn register_then_login_uses_account_id_not_email() {
    let p = test_provider();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (key, _cred_id, account_id) = register_test_account(&p, &email).await;

    // email 入力ログイン。最終 sub は email ではなく account_id であること。
    let sub_from_email_login = login_with_email(&p, &email, &key, 0).await;
    assert_eq!(sub_from_email_login, account_id);
    assert_ne!(sub_from_email_login, email);
    // discoverable ログイン（userHandle のみ）。email は一切送らない。
    login_discoverable(&p, &account_id, &key, 1).await;

    // find_account(FirestoreStore) が account_id から正しく email claim を逆引きできる。
    let account = p.store.find_account(&account_id).await;
    assert_eq!(account.sub, account_id);
    assert_eq!(account.claims.get("email").and_then(|v| v.as_str()), Some(email.as_str()));
    assert_eq!(account.claims.get("email_verified").and_then(|v| v.as_bool()), Some(true));

    // 未知の account_id では email claim が付かない（逆引き失敗を静かに許容し、値をでっち上げない）。
    let unknown = p.store.find_account("00000000-0000-0000-0000-000000000000").await;
    assert!(!unknown.claims.contains_key("email"));
}

#[tokio::test]
#[ignore]
async fn reregistration_reuses_existing_account_id() {
    let p = test_provider();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (_key1, _cred1, account_id1) = register_test_account(&p, &email).await;

    // 同じ email で passkey を作り直す（機種変更等）。account_id は変わってはならない
    // （変わると、過去に発行済みの sub を持つ他システムとの紐付けが切れる）。
    let fs = p.firestore.as_ref().unwrap();
    let email_token = crate::registration::create_email_challenge(fs, &email).await.unwrap();
    let opts_req: register::RegPkOptionsReq =
        serde_json::from_value(json!({ "token": email_token })).unwrap();
    let opts = register::register_passkey_options(State(p.clone()), Json(opts_req)).await;
    let opts_json = body_json(opts).await;
    let user_id_b64 = opts_json["user"]["id"].as_str().unwrap().to_string();
    let account_id2 = String::from_utf8(crate::es256::b64url_decode(&user_id_b64).unwrap()).unwrap();

    assert_eq!(account_id1, account_id2, "再登録で account_id が変わってしまっている");
}

#[tokio::test]
#[ignore]
async fn sign_count_update_preserves_account_id() {
    let p = test_provider();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (key, _cred_id, account_id) = register_test_account(&p, &email).await;

    // 複数回ログインして update_sign_count がドキュメント全体を書き直す経路を通す。
    login_with_email(&p, &email, &key, 1).await;
    login_with_email(&p, &email, &key, 2).await;

    let fs = p.firestore.as_ref().unwrap();
    let cred = crate::registration::get_credential(fs, &email).await.unwrap().unwrap();
    assert_eq!(cred.account_id, account_id, "signCount 更新のたびに accountId が消えていないこと");
    assert_eq!(cred.sign_count, 2);
}

#[tokio::test]
#[ignore]
async fn ciba_flow_uses_account_id_consistently() {
    let p = test_provider();
    let email = format!("probe-{}@example.com", uuid::Uuid::new_v4());
    let (key, cred_id, account_id) = register_test_account(&p, &email).await;

    // backchannel-authentication: login_hint は email(RP起点のヒント)。
    let mut form = HashMap::new();
    form.insert("client_id".to_string(), "test-ciba-rp".to_string());
    form.insert("login_hint".to_string(), email.clone());
    form.insert("scope".to_string(), "openid".to_string());
    let resp = ciba::backchannel_auth(State(p.clone()), HeaderMap::new(), Form(form)).await;
    let status = resp.status();
    let body = body_json(resp).await;
    assert_eq!(status, StatusCode::OK, "backchannel_auth failed: {body:?}");
    let auth_req_id = body["auth_req_id"].as_str().unwrap().to_string();

    // CIBA 要求本体の account は account_id であって login_hint(email) ではない。
    let stored = p.ciba.get(&auth_req_id).await.unwrap().unwrap();
    assert_eq!(stored.account, account_id, "CIBA 要求の account に email が残っている");
    assert_ne!(stored.account, email);

    // 承認オプション → 承認（UV 必須）。
    let opts = ciba::ciba_approve_options(State(p.clone()), Path(auth_req_id.clone())).await;
    assert_eq!(opts.status(), StatusCode::OK);
    let opts_json = body_json(opts).await;
    let challenge = opts_json["challenge"].as_str().unwrap().to_string();

    let (ad, sig, cdj) = make_auth_ceremony(&key, 1, &challenge, &p.origin(), &p.rp_id(), true);
    let approve_req: AuthVerifyReq = serde_json::from_value(json!({
        "id": crate::webauthn::b64e(&cred_id),
        "response": { "clientDataJSON": cdj, "authenticatorData": ad, "signature": sig, "userHandle": null },
    }))
    .unwrap();
    let approve = ciba::ciba_approve(State(p.clone()), Path(auth_req_id.clone()), Json(approve_req)).await;
    let approve_status = approve.status();
    let approve_body = body_json(approve).await;
    assert_eq!(approve_status, StatusCode::OK, "ciba_approve failed: {approve_body:?}");

    let approved = p.ciba.get(&auth_req_id).await.unwrap().unwrap();
    assert_eq!(approved.status, CibaStatus::Approved);
    assert_eq!(approved.account, account_id);
}
