//! FIDO2 Server Conformance（FIDO Conformance Tools v1.8.5）用の RP エンドポイント。
//!
//! 本番ログイン経路（crate::webauthn の自作 ES256 検証）とは独立した面。
//! 検証コアはピュア Rust（RustCrypto）で段階的に自作する。ここは土台と
//! `/fido/attestation/options`（Step 1）まで。result / assertion は後続ステップで実装。
//!
//! 設計メモ:
//! - challenge state は clientDataJSON.challenge をキーに in-memory で引く
//!   （Conformance Tool は Cookie を返さないため。TS 実装と同じ流儀）。
//! - リクエストは生 JSON を自前で型チェックする（negative test 耐性）。
//! - 失敗は HTTP 400 + {status:"failed", errorMessage}、成功は 200 + {status:"ok", ...}。

use axum::extract::Request;
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::{from_fn, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use rand_core::{OsRng, RngCore};
use serde_json::{json, Value};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

mod mds;
pub(crate) mod store;
mod tpm;
pub(crate) mod verify;

use crate::es256::{b64url_decode, b64url_encode};
use store::{ChallengeState, FidoStore, FirestoreFidoStore, MemFidoStore, StoredCredential};

/// pubKeyCredParams で広告する COSEAlgorithmIdentifier。
/// 「広告 = 実装」を厳守する。ES256(-7) / RS256(-257) / EdDSA(-8) / RS1(-65535)。
const SUPPORTED_ALGS: &[i32] = &[-7, -257, -8, -65535];

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn random_b64url(len: usize) -> String {
    let mut buf = vec![0u8; len];
    OsRng.fill_bytes(&mut buf);
    b64url_encode(&buf)
}

/// MDS（Metadata Service）の設定とキャッシュ。enabled 時のみ full attestation で照合する。
#[derive(Default)]
struct MdsState {
    enabled: bool,
    roots: Vec<Vec<u8>>,
    cache: mds::MdsCache,
}

/// `/fido/*` 用の状態。OIDC の Provider とは独立。
/// 永続化は store（ローカル=in-memory / Cloud Run=Firestore）に委譲する。
pub struct FidoState {
    rp_id: String,
    rp_name: String,
    /// clientDataJSON.origin の期待値。Conformance Tool に設定するサーバ URL と一致させる。
    origin: String,
    store: Arc<dyn FidoStore>,
    mds: Mutex<MdsState>,
}

impl FidoState {
    /// 環境変数から構築。ローカル emulator 既定は localhost。
    /// FIDO_RP_ID / FIDO_ORIGIN で Conformance Tool 設定に合わせて上書きする。
    /// K_SERVICE(Cloud Run) では Firestore、それ以外は in-memory。
    pub fn from_env() -> Self {
        let rp_id = std::env::var("FIDO_RP_ID").unwrap_or_else(|_| "localhost".into());
        let origin = std::env::var("FIDO_ORIGIN")
            .unwrap_or_else(|_| format!("http://{rp_id}"));
        let rp_name = std::env::var("FIDO_RP_NAME").unwrap_or_else(|_| "rust-op FIDO2".into());
        let store: Arc<dyn FidoStore> = if std::env::var("K_SERVICE").is_ok() {
            let project = std::env::var("GCLOUD_PROJECT")
                .or_else(|_| std::env::var("GOOGLE_CLOUD_PROJECT"))
                .unwrap_or_else(|_| "fido2-8b943".into());
            let fs = Arc::new(crate::firestore::Firestore::new(project));
            Arc::new(FirestoreFidoStore::new(fs))
        } else {
            Arc::new(MemFidoStore::default())
        };
        FidoState {
            rp_id,
            rp_name,
            origin,
            store,
            mds: Mutex::new(MdsState::default()),
        }
    }

    async fn save_challenge(&self, challenge: String, st: ChallengeState) {
        self.store.save_challenge(&challenge, st).await
    }
    async fn get_challenge(&self, challenge: &str) -> Option<ChallengeState> {
        self.store.get_challenge(challenge).await
    }
    async fn save_credential(&self, user: &str, cred: StoredCredential) {
        self.store.save_credential(user, cred).await
    }
    async fn find_credentials(&self, user: &str) -> Vec<StoredCredential> {
        self.store.find_credentials(user).await
    }
    async fn update_sign_count(&self, user: &str, cred_id: &str, new_count: u32) {
        self.store.update_sign_count(user, cred_id, new_count).await
    }
}

/// AAGUID(16 bytes) を 8-4-4-4-12 のハイフン区切り hex に。
fn aaguid_to_string(aaguid: &[u8]) -> String {
    let h: String = aaguid.iter().map(|b| format!("{b:02x}")).collect();
    if h.len() != 32 {
        return h;
    }
    format!("{}-{}-{}-{}-{}", &h[0..8], &h[8..12], &h[12..16], &h[16..20], &h[20..32])
}

/// clientDataJSON(b64url) から challenge 文字列を取り出す（state 引き当て用）。
fn extract_challenge(client_data_json_b64: &str) -> Option<String> {
    let raw = b64url_decode(client_data_json_b64).ok()?;
    let v: Value = serde_json::from_slice(&raw).ok()?;
    v.get("challenge")?.as_str().map(|s| s.to_string())
}

/// response オブジェクトから文字列フィールドを取り出す（negative test 耐性）。
fn resp_string(m: &serde_json::Map<String, Value>, key: &str) -> Result<String, Response> {
    let resp = m
        .get("response")
        .and_then(|v| v.as_object())
        .ok_or_else(|| failed("missing response object"))?;
    match resp.get(key) {
        Some(Value::String(s)) if !s.is_empty() => Ok(s.clone()),
        _ => Err(failed(format!("response.{key} must be a non-empty string"))),
    }
}

/// `/fido/*` をトップレベルに配線するルータ（base_path に依存しない）。
pub fn router(state: Arc<FidoState>) -> Router {
    Router::new()
        .route("/fido/attestation/options", post(attestation_options))
        .route("/fido/attestation/result", post(attestation_result))
        .route("/fido/assertion/options", post(assertion_options))
        .route("/fido/assertion/result", post(assertion_result))
        // dev 用: MDS BLOB 検証のオフライン確認（本番では外す）。
        .route("/fido/mds/_verify", post(mds_test_verify))
        .route("/fido/mds/config", post(mds_config))
        .with_state(state)
        // Conformance Tool は Chromium の fetch で叩くため CORS プリフライトが要る。
        .layer(from_fn(cors))
}

/// dev 用: {blob, roots:[b64std DER], aaguid?} を受けて MDS 検証結果を返す。
async fn mds_test_verify(State(_st): State<Arc<FidoState>>, body: String) -> Response {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    let m = match parse_object(&body) {
        Ok(m) => m,
        Err(r) => return r,
    };
    let blob = match m.get("blob").and_then(|v| v.as_str()) {
        Some(s) => s,
        None => return failed("blob required"),
    };
    let roots: Vec<Vec<u8>> = match m.get("roots").and_then(|v| v.as_array()) {
        Some(arr) => arr
            .iter()
            .filter_map(|v| v.as_str())
            .filter_map(|s| B64.decode(s).ok())
            .collect(),
        None => return failed("roots required"),
    };
    let mut cache = mds::MdsCache::default();
    match cache.load_blob(blob, &roots).await {
        Err(e) => ok_with(json!({ "loaded": false, "error": e })),
        Ok(n) => {
            let mut resp = json!({ "loaded": true, "count": n });
            if let Some(aaguid) = m.get("aaguid").and_then(|v| v.as_str()) {
                match cache.get_statement(aaguid) {
                    Ok(Some(_)) => resp["statement"] = json!("ok"),
                    Ok(None) => resp["statement"] = json!("none"),
                    Err(e) => {
                        resp["statement"] = json!("error");
                        resp["statusError"] = json!(e);
                    }
                }
            }
            ok_with(resp)
        }
    }
}

/// MDS を設定する。{roots:[b64std DER], blobs?:[JWT], blobUrls?:[url]}。
/// roots は信頼アンカー（conformance では tool の test root）。BLOB は直接 or URL 取得。
async fn mds_config(State(st): State<Arc<FidoState>>, body: String) -> Response {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;
    let m = match parse_object(&body) {
        Ok(m) => m,
        Err(r) => return r,
    };
    let str_array = |key: &str| -> Vec<String> {
        m.get(key)
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(String::from)).collect())
            .unwrap_or_default()
    };
    let roots: Vec<Vec<u8>> = str_array("roots")
        .iter()
        .filter_map(|s| B64.decode(s).ok())
        .collect();
    if roots.is_empty() {
        return failed("roots required (base64 DER)");
    }

    // BLOB を集める（直接 + URL 取得）。fetch は lock を取る前に済ませる。
    let mut blobs = str_array("blobs");
    for url in str_array("blobUrls") {
        match reqwest::get(&url).await {
            Ok(resp) => match resp.text().await {
                Ok(t) => blobs.push(t),
                Err(e) => return failed(format!("fetch {url} body: {e}")),
            },
            Err(e) => return failed(format!("fetch {url}: {e}")),
        }
    }

    // fetch + 失効確認は async。std Mutex を await 跨ぎで保持しないよう lock の外で構築する。
    // 不正な BLOB(署名/チェーン/失効)はスキップして有効なものだけ載せる
    // （conformance は不正シナリオの BLOB も混ぜてくる。それらの authenticator は
    //   未登録となり attestation 時に拒否される）。
    let mut cache = mds::MdsCache::default();
    let mut loaded = 0usize;
    let mut skipped: Vec<Value> = Vec::new();
    for (i, blob) in blobs.iter().enumerate() {
        match cache.load_blob(blob, &roots).await {
            Ok(n) => loaded += n,
            Err(e) => skipped.push(json!({ "index": i, "error": e })),
        }
    }
    // 生メタデータ statement（DOWNLOAD TEST METADATA）を直接ロードする。
    let mut statements_loaded = 0usize;
    if let Some(stmts) = m.get("statements").and_then(|v| v.as_array()) {
        for s in stmts {
            if cache.load_statement(s) {
                statements_loaded += 1;
            }
        }
    }
    let mut guard = st.mds.lock().unwrap();
    guard.roots = roots;
    guard.cache = cache;
    guard.enabled = true;
    ok_with(json!({ "enabled": true, "entries": loaded, "statements": statements_loaded, "skipped": skipped }))
}

fn add_cors_headers(h: &mut HeaderMap, origin: &str) {
    // credentials 付き fetch でも通るよう Origin を反射する（"*" は credentials と非互換）。
    let allow = HeaderValue::from_str(if origin == "-" { "*" } else { origin })
        .unwrap_or_else(|_| HeaderValue::from_static("*"));
    h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, allow);
    h.insert(header::ACCESS_CONTROL_ALLOW_CREDENTIALS, HeaderValue::from_static("true"));
    h.insert(header::VARY, HeaderValue::from_static("Origin"));
    h.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        HeaderValue::from_static("POST, OPTIONS"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        HeaderValue::from_static("content-type"),
    );
    h.insert(header::ACCESS_CONTROL_MAX_AGE, HeaderValue::from_static("600"));
}

/// 全 /fido レスポンスに CORS ヘッダを付与し、OPTIONS プリフライトに 204 で答える。
async fn cors(req: Request, next: Next) -> Response {
    let origin = req
        .headers()
        .get(header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("-")
        .to_string();
    tracing::info!("fido {} {} (origin={origin})", req.method(), req.uri().path());
    if req.method() == Method::OPTIONS {
        let mut res = (StatusCode::NO_CONTENT, ()).into_response();
        add_cors_headers(res.headers_mut(), &origin);
        return res;
    }
    let mut res = next.run(req).await;
    add_cors_headers(res.headers_mut(), &origin);
    res
}

/* ===== ServerResponse ヘルパ ===== */

fn failed(msg: impl Into<String>) -> Response {
    let msg = msg.into();
    tracing::info!("fido REJECT: {msg}");
    (
        StatusCode::BAD_REQUEST,
        Json(json!({ "status": "failed", "errorMessage": msg })),
    )
        .into_response()
}

fn ok_with(mut v: Value) -> Response {
    if let Value::Object(ref mut m) = v {
        m.insert("status".into(), json!("ok"));
        m.insert("errorMessage".into(), json!(""));
    }
    (StatusCode::OK, Json(v)).into_response()
}

/// 生ボディを JSON オブジェクトとしてパース。negative test 耐性のため自前で型チェックする。
fn parse_object(body: &str) -> Result<serde_json::Map<String, Value>, Response> {
    let v: Value = serde_json::from_str(body).map_err(|e| failed(format!("invalid JSON: {e}")))?;
    match v {
        Value::Object(m) => Ok(m),
        _ => Err(failed("body must be a JSON object")),
    }
}

/// 厳格な base64url 判定（`+ / =` を含まない）。Conformance は標準 base64 を拒否させる。
fn is_b64url(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

fn req_string<'a>(m: &'a serde_json::Map<String, Value>, key: &str) -> Result<&'a str, Response> {
    match m.get(key) {
        Some(Value::String(s)) if !s.is_empty() => Ok(s),
        _ => Err(failed(format!("{key} must be a non-empty string"))),
    }
}

/* ===== Step 1: MakeCredential Request ===== */

use axum::extract::State;

async fn attestation_options(State(st): State<Arc<FidoState>>, body: String) -> Response {
    let m = match parse_object(&body) {
        Ok(m) => m,
        Err(r) => return r,
    };

    let username = match req_string(&m, "username") {
        Ok(s) => s.to_string(),
        Err(r) => return r,
    };
    let display_name = m
        .get("displayName")
        .and_then(|v| v.as_str())
        .unwrap_or(&username)
        .to_string();

    // authenticatorSelection はそのまま透過しつつ userVerification だけ state に控える。
    let authenticator_selection = m.get("authenticatorSelection").cloned();
    let user_verification = authenticator_selection
        .as_ref()
        .and_then(|v| v.get("userVerification"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let attestation = m
        .get("attestation")
        .and_then(|v| v.as_str())
        .unwrap_or("none")
        .to_string();
    let extensions = m.get("extensions").cloned();

    let challenge = random_b64url(32);
    // userID は username バイト列を b64url（TS 実装と同じ。安定 ID）。
    let user_id = b64url_encode(username.as_bytes());

    // 既存 credential を excludeCredentials に並べる。
    let exclude: Vec<Value> = st
        .find_credentials(&username)
        .await
        .iter()
        .map(|c| {
            json!({
                "type": "public-key",
                "id": c.id,
                "transports": ["usb", "ble", "nfc", "internal"],
            })
        })
        .collect();

    st.save_challenge(
        challenge.clone(),
        ChallengeState {
            username: username.clone(),
            user_verification,
            created_at: now(),
        },
    )
    .await;

    let pub_key_cred_params: Vec<Value> = SUPPORTED_ALGS
        .iter()
        .map(|alg| json!({ "type": "public-key", "alg": alg }))
        .collect();

    let mut resp = json!({
        "rp": { "name": st.rp_name, "id": st.rp_id },
        "user": { "id": user_id, "name": username, "displayName": display_name },
        "challenge": challenge,
        "pubKeyCredParams": pub_key_cred_params,
        "timeout": 60000,
        "excludeCredentials": exclude,
        "attestation": attestation,
    });
    if let Some(sel) = authenticator_selection {
        resp["authenticatorSelection"] = sel;
    }
    if let Some(ext) = extensions {
        resp["extensions"] = ext;
    }
    ok_with(resp)
}

/* ===== Step 2: MakeCredential Response（none + ES256）===== */

async fn attestation_result(State(st): State<Arc<FidoState>>, body: String) -> Response {
    let m = match parse_object(&body) {
        Ok(m) => m,
        Err(r) => return r,
    };
    // credential の必須トップレベル項目（F-: id 欠落 / 非 base64url / type 不正は拒否）。
    match m.get("id").and_then(|v| v.as_str()) {
        Some(s) if is_b64url(s) => {}
        _ => return failed("id must be a non-empty base64url string"),
    }
    if m.get("type").and_then(|v| v.as_str()) != Some("public-key") {
        return failed("type must be 'public-key'");
    }
    let client_data_b64 = match resp_string(&m, "clientDataJSON") {
        Ok(s) => s,
        Err(r) => return r,
    };
    let att_obj_b64 = match resp_string(&m, "attestationObject") {
        Ok(s) => s,
        Err(r) => return r,
    };

    let challenge = match extract_challenge(&client_data_b64) {
        Some(c) => c,
        None => return failed("clientDataJSON missing or unparsable challenge"),
    };
    let state = match st.get_challenge(&challenge).await {
        Some(s) => s,
        None => return failed("challenge state not found or expired"),
    };
    let require_uv = state.user_verification.as_deref() == Some("required");

    let result: Result<StoredCredential, String> = (|| {
        let client_data =
            verify::check_client_data(&client_data_b64, "webauthn.create", &challenge, &st.origin)?;
        let att = b64url_decode(&att_obj_b64)?;
        let ao = verify::parse_attestation_object(&att)?;
        let ad = verify::parse_auth_data(&ao.auth_data)?;
        verify::check_rp_id_hash(ad.rp_id_hash, &st.rp_id)?;
        verify::check_flags(ad.flags, require_uv)?;
        if ad.flags & verify::FLAG_AT == 0 {
            return Err("AT flag not set (no attested credential data)".into());
        }
        // attestedCredentialData: aaguid(16) | credIdLen(2) | credId | COSE
        let rest = ad.rest;
        if rest.len() < 18 {
            return Err("attestedCredentialData too short".into());
        }
        let aaguid = &rest[0..16];
        let cred_id_len = u16::from_be_bytes([rest[16], rest[17]]) as usize;
        if rest.len() < 18 + cred_id_len {
            return Err("credId length overflow".into());
        }
        let cred_id = &rest[18..18 + cred_id_len];
        let cose_slice = &rest[18 + cred_id_len..];
        let (cred_key, consumed) = verify::parse_cose_key(cose_slice)?;
        // ED フラグが無いのに余剰バイトが残る authData は不正（F-12）。
        if ad.flags & verify::FLAG_ED == 0 && consumed != cose_slice.len() {
            return Err("authData has leftover bytes after attested credential data".into());
        }

        match ao.fmt.as_str() {
            "none" => verify::require_empty_att_stmt(&ao.att_stmt)?,
            "packed" => {
                verify::verify_packed(&ao.att_stmt, &ao.auth_data, &client_data, &cred_key, aaguid)?
            }
            "fido-u2f" => {
                // fido-u2f は AAGUID 全ゼロが必須（F-1）。
                if aaguid.iter().any(|&b| b != 0) {
                    return Err("fido-u2f AAGUID must be all zero".into());
                }
                let (ux, uy) = cred_key
                    .ec_xy()
                    .ok_or("fido-u2f requires an EC P-256 credential key")?;
                verify::verify_u2f(&ao.att_stmt, ad.rp_id_hash, &client_data, cred_id, ux, uy)?
            }
            "tpm" => tpm::verify_tpm(&ao.att_stmt, &ao.auth_data, &client_data, &cred_key)?,
            other => return Err(format!("attestation fmt '{other}' not supported yet")),
        }

        // MDS が有効なら full attestation(x5c あり)を metadata で照合する。
        {
            let guard = st.mds.lock().unwrap();
            if guard.enabled {
                let x5c = verify::att_x5c_ders(&ao.att_stmt);
                // fido-u2f は AAGUID 全ゼロで、MDS は鍵識別子で引く別形式のため照合対象外。
                let is_u2f_zero_aaguid = aaguid.iter().all(|&b| b == 0);
                if !x5c.is_empty() && !is_u2f_zero_aaguid {
                    let aaguid_str = aaguid_to_string(aaguid);
                    match guard.cache.get_statement(&aaguid_str)? {
                        Some(stmt) => {
                            mds::validate_attestation_chain(&x5c, &stmt.attestation_root_certificates)?
                        }
                        None => return Err(format!("AAGUID {aaguid_str} not registered in MDS")),
                    }
                }
            }
        }

        tracing::info!(
            "attestation OK: fmt={} aaguid={} user={}",
            ao.fmt,
            aaguid_to_string(aaguid),
            state.username
        );
        Ok(StoredCredential {
            id: b64url_encode(cred_id),
            key: cred_key,
            sign_count: ad.sign_count,
        })
    })();

    match result {
        Ok(cred) => {
            st.save_credential(&state.username, cred).await;
            ok_with(json!({}))
        }
        Err(e) => failed(e),
    }
}

/* ===== Step 3: GetAssertion Request / Response ===== */

async fn assertion_options(State(st): State<Arc<FidoState>>, body: String) -> Response {
    let m = match parse_object(&body) {
        Ok(m) => m,
        Err(r) => return r,
    };
    let username = match req_string(&m, "username") {
        Ok(s) => s.to_string(),
        Err(r) => return r,
    };
    let user_verification = m
        .get("userVerification")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let extensions = m.get("extensions").cloned();

    let allow: Vec<Value> = st
        .find_credentials(&username)
        .await
        .iter()
        .map(|c| {
            json!({
                "type": "public-key",
                "id": c.id,
                "transports": ["usb", "ble", "nfc", "internal"],
            })
        })
        .collect();

    let challenge = random_b64url(32);
    st.save_challenge(
        challenge.clone(),
        ChallengeState {
            username,
            user_verification: user_verification.clone(),
            created_at: now(),
        },
    )
    .await;

    let mut resp = json!({
        "challenge": challenge,
        "timeout": 60000,
        "rpId": st.rp_id,
        "allowCredentials": allow,
        "userVerification": user_verification.unwrap_or_else(|| "preferred".into()),
    });
    if let Some(ext) = extensions {
        resp["extensions"] = ext;
    }
    ok_with(resp)
}

async fn assertion_result(State(st): State<Arc<FidoState>>, body: String) -> Response {
    let m = match parse_object(&body) {
        Ok(m) => m,
        Err(r) => return r,
    };
    let cred_id = match m.get("id").and_then(|v| v.as_str()) {
        Some(s) if is_b64url(s) => s.to_string(),
        _ => return failed("id must be a non-empty base64url string"),
    };
    if m.get("type").and_then(|v| v.as_str()) != Some("public-key") {
        return failed("type must be 'public-key'");
    }
    // userHandle は任意。存在するなら null か文字列のみ（F-21）。
    if let Some(uh) = m.get("response").and_then(|r| r.as_object()).and_then(|r| r.get("userHandle")) {
        if !uh.is_null() && !uh.is_string() {
            return failed("userHandle must be a string or null");
        }
    }
    let client_data_b64 = match resp_string(&m, "clientDataJSON") {
        Ok(s) => s,
        Err(r) => return r,
    };
    let auth_data_b64 = match resp_string(&m, "authenticatorData") {
        Ok(s) => s,
        Err(r) => return r,
    };
    let signature_b64 = match resp_string(&m, "signature") {
        Ok(s) => s,
        Err(r) => return r,
    };
    if !is_b64url(&auth_data_b64) {
        return failed("authenticatorData must be base64url");
    }
    if !is_b64url(&signature_b64) {
        return failed("signature must be base64url");
    }

    let challenge = match extract_challenge(&client_data_b64) {
        Some(c) => c,
        None => return failed("clientDataJSON missing or unparsable challenge"),
    };
    let state = match st.get_challenge(&challenge).await {
        Some(s) => s,
        None => return failed("challenge state not found or expired"),
    };
    let require_uv = state.user_verification.as_deref() == Some("required");

    let cred = match st
        .find_credentials(&state.username)
        .await
        .into_iter()
        .find(|c| c.id == cred_id)
    {
        Some(c) => c,
        None => return failed("unknown credential id"),
    };

    let result: Result<u32, String> = (|| {
        let client_data =
            verify::check_client_data(&client_data_b64, "webauthn.get", &challenge, &st.origin)?;
        let auth_data = b64url_decode(&auth_data_b64)?;
        let ad = verify::parse_auth_data(&auth_data)?;
        verify::check_rp_id_hash(ad.rp_id_hash, &st.rp_id)?;
        verify::check_flags(ad.flags, require_uv)?;
        verify::verify_assertion(
            &cred.key,
            &auth_data,
            &client_data,
            &b64url_decode(&signature_b64)?,
        )?;
        // signCount: 受信 0 は無視。0 でなければ単調増加を要求。
        if ad.sign_count != 0 && ad.sign_count <= cred.sign_count {
            return Err("signCount did not increase (possible clone)".into());
        }
        Ok(ad.sign_count)
    })();

    match result {
        Ok(new_count) => {
            st.update_sign_count(&state.username, &cred_id, new_count).await;
            ok_with(json!({}))
        }
        Err(e) => failed(e),
    }
}
