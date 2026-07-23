//! メール確認つき passkey 登録の永続化。Firestore を使う。
//! - emailChallenges/{token}: メール所有確認待ち（email, expiresAt）。30分・単回。
//! - webauthnChallenges/{challenge}: passkey セレモニーのチャレンジ（email, kind, uid, accountId, expiresAt）。5分・単回。
//! - accounts/{email}: 確認済みユーザー + passkey（accountId, credentialId, pubX, pubY, signCount, ...）。
//! - accountsByUuid/{accountId}: accounts/{email} への逆引き（email のみ）。discoverable な
//!   passkey ログイン（userHandle = accountId しか分からない）で email を引くために使う。
//!   sub/account_id は email ではなく accountId（登録時に発行する UUID v4）。

use crate::firestore::{self, Firestore};
use crate::jws::b64url;
use crate::webauthn::RegOutcome;
use rand_core::{OsRng, RngCore};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

// メール送信 → アプリ起動 → verify-email → options → Face ID → verify までを許容できる
// 余裕のある TTL。短すぎると passkey 作成中にトークン失効で 400 になる。
const EMAIL_TTL_SECS: u64 = 30 * 60;
const CEREMONY_TTL_SECS: u64 = 5 * 60;

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn random_token() -> String {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    b64url(buf)
}

fn token_ok(t: &str) -> bool {
    (20..=100).contains(&t.len())
        && t.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/* ===== email 所有確認チャレンジ ===== */

pub async fn create_email_challenge(fs: &Firestore, email: &str) -> Result<String, String> {
    let token = random_token();
    fs.set_doc(
        "emailChallenges",
        &token,
        json!({
            "email": firestore::s(email),
            "expiresAt": firestore::ts(&firestore::rfc3339(now() + EMAIL_TTL_SECS)),
        }),
    )
    .await?;
    Ok(token)
}

/// 消費せず email を覗く（passkey options 生成時に使用）。
pub async fn peek_email_challenge(fs: &Firestore, token: &str) -> Result<Option<String>, String> {
    if !token_ok(token) {
        return Ok(None);
    }
    let fields = match fs.get_doc("emailChallenges", token).await? {
        Some(f) => f,
        None => return Ok(None),
    };
    if challenge_expired(&fields) {
        return Ok(None);
    }
    Ok(firestore::field_str(&fields, "email").map(|s| s.to_string()))
}

/// 単回消費して email を返す（passkey verify 成功時）。
pub async fn consume_email_challenge(fs: &Firestore, token: &str) -> Result<Option<String>, String> {
    if !token_ok(token) {
        return Ok(None);
    }
    let fields = match fs.get_doc("emailChallenges", token).await? {
        Some(f) => f,
        None => return Ok(None),
    };
    fs.delete_doc("emailChallenges", token).await.ok();
    if challenge_expired(&fields) {
        return Ok(None);
    }
    Ok(firestore::field_str(&fields, "email").map(|s| s.to_string()))
}

pub async fn account_exists(fs: &Firestore, email: &str) -> Result<bool, String> {
    Ok(fs.get_doc("accounts", email).await?.is_some())
}

/* ===== WebAuthn セレモニーチャレンジ ===== */

/// passkey セレモニーの種別。文字列比較ミスを型で防ぐ。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeKind {
    Reg,
    Auth,
    CibaApprove,
}

impl ChallengeKind {
    fn as_str(self) -> &'static str {
        match self {
            ChallengeKind::Reg => "reg",
            ChallengeKind::Auth => "auth",
            ChallengeKind::CibaApprove => "ciba-approve",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        match s {
            "reg" => Some(ChallengeKind::Reg),
            "auth" => Some(ChallengeKind::Auth),
            "ciba-approve" => Some(ChallengeKind::CibaApprove),
            _ => None,
        }
    }
}

pub async fn create_webauthn_challenge(
    fs: &Firestore,
    email: &str,
    kind: ChallengeKind,
    uid: &str,
    account_id: &str,
) -> Result<String, String> {
    let challenge = random_token();
    fs.set_doc(
        "webauthnChallenges",
        &challenge,
        json!({
            "email": firestore::s(email),
            "kind": firestore::s(kind.as_str()),
            "uid": firestore::s(uid),
            "accountId": firestore::s(account_id),
            "expiresAt": firestore::ts(&firestore::rfc3339(now() + CEREMONY_TTL_SECS)),
        }),
    )
    .await?;
    Ok(challenge)
}

/// (email, kind, uid, accountId) を単回消費で返す。kind が未知なら None。
/// accountId は ChallengeKind::Reg のときのみ意味を持つ（登録時に払い出した/再利用する UUID）。
pub async fn consume_webauthn_challenge(
    fs: &Firestore,
    challenge: &str,
) -> Result<Option<(String, ChallengeKind, String, String)>, String> {
    if !token_ok(challenge) {
        return Ok(None);
    }
    let fields = match fs.get_doc("webauthnChallenges", challenge).await? {
        Some(f) => f,
        None => return Ok(None),
    };
    fs.delete_doc("webauthnChallenges", challenge).await.ok();
    if challenge_expired(&fields) {
        return Ok(None);
    }
    let kind = match ChallengeKind::parse(firestore::field_str(&fields, "kind").unwrap_or("")) {
        Some(k) => k,
        None => return Ok(None),
    };
    let email = firestore::field_str(&fields, "email").unwrap_or("").to_string();
    let uid = firestore::field_str(&fields, "uid").unwrap_or("").to_string();
    let account_id = firestore::field_str(&fields, "accountId").unwrap_or("").to_string();
    Ok(Some((email, kind, uid, account_id)))
}

/* ===== passkey 認証情報 ===== */

pub struct Credential {
    pub account_id: String,
    pub credential_id: String,
    pub pub_x: String,
    pub pub_y: String,
    pub sign_count: u32,
}

/// account_id は呼び出し側が払い出す（新規登録なら新規 UUID、既存 passkey 追加なら既存値の再利用）。
/// accounts/{email} を先に書き、逆引き accountsByUuid/{account_id} を後で書く。
/// 逆引きの書き込みが失敗しても登録自体は失敗させない（email 入力でのログインは影響を受けない、
/// discoverable ログインのみ縮退する）。
pub async fn save_credential(
    fs: &Firestore,
    email: &str,
    account_id: &str,
    c: &RegOutcome,
) -> Result<(), String> {
    fs.set_doc(
        "accounts",
        email,
        json!({
            "email": firestore::s(email),
            "accountId": firestore::s(account_id),
            "credentialId": firestore::s(&c.credential_id),
            "pubX": firestore::s(&c.pub_x),
            "pubY": firestore::s(&c.pub_y),
            "signCount": { "integerValue": c.sign_count.to_string() },
            "verified": firestore::b(true),
            "createdAt": firestore::ts(&firestore::rfc3339(now())),
        }),
    )
    .await?;
    if let Err(e) = fs
        .set_doc("accountsByUuid", account_id, json!({ "email": firestore::s(email) }))
        .await
    {
        tracing::error!("accountsByUuid index write failed for account_id={account_id}: {e}");
    }
    Ok(())
}

pub async fn get_credential(fs: &Firestore, email: &str) -> Result<Option<Credential>, String> {
    let fields = match fs.get_doc("accounts", email).await? {
        Some(f) => f,
        None => return Ok(None),
    };
    let credential_id = match firestore::field_str(&fields, "credentialId") {
        Some(s) => s.to_string(),
        None => return Ok(None),
    };
    let sign_count = fields
        .get("signCount")
        .and_then(|v| v.get("integerValue"))
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(0);
    Ok(Some(Credential {
        account_id: firestore::field_str(&fields, "accountId").unwrap_or("").to_string(),
        credential_id,
        pub_x: firestore::field_str(&fields, "pubX").unwrap_or("").to_string(),
        pub_y: firestore::field_str(&fields, "pubY").unwrap_or("").to_string(),
        sign_count,
    }))
}

pub async fn update_sign_count(fs: &Firestore, email: &str, n: u32) -> Result<(), String> {
    // 既存ドキュメントを取り直して signCount だけ更新（PATCH は全 fields 置換のため）。
    // accountId は既存値をそのまま引き継ぐ（再生成しない）。
    if let Some(c) = get_credential(fs, email).await? {
        fs.set_doc(
            "accounts",
            email,
            json!({
                "email": firestore::s(email),
                "accountId": firestore::s(&c.account_id),
                "credentialId": firestore::s(&c.credential_id),
                "pubX": firestore::s(&c.pub_x),
                "pubY": firestore::s(&c.pub_y),
                "signCount": { "integerValue": n.to_string() },
                "verified": firestore::b(true),
            }),
        )
        .await?;
    }
    Ok(())
}

/// accountId(UUID) -> email の逆引き。discoverable ログイン（userHandle=accountId のみ判明）で使う。
pub async fn find_email_by_account_id(
    fs: &Firestore,
    account_id: &str,
) -> Result<Option<String>, String> {
    let fields = match fs.get_doc("accountsByUuid", account_id).await? {
        Some(f) => f,
        None => return Ok(None),
    };
    Ok(firestore::field_str(&fields, "email").map(|s| s.to_string()))
}

/* ===== ユーザープロフィール（編集可能 claim、passkey とは別 collection） ===== */

/// profiles/{email} の編集可能 claim を返す（未保存なら空）。
pub async fn get_profile(
    fs: &Firestore,
    email: &str,
) -> Result<std::collections::HashMap<String, String>, String> {
    let mut out = std::collections::HashMap::new();
    let fields = match fs.get_doc("profiles", email).await? {
        Some(f) => f,
        None => return Ok(out),
    };
    for k in crate::claims::EDITABLE {
        if let Some(v) = firestore::field_str(&fields, k) {
            out.insert(k.to_string(), v.to_string());
        }
    }
    Ok(out)
}

/// 既存値とマージして profiles/{email} を保存（EDITABLE 以外は無視）。
pub async fn save_profile(
    fs: &Firestore,
    email: &str,
    updates: &std::collections::HashMap<String, String>,
) -> Result<(), String> {
    let mut current = get_profile(fs, email).await?;
    for (k, v) in updates {
        if crate::claims::EDITABLE.contains(&k.as_str()) {
            current.insert(k.clone(), v.clone());
        }
    }
    let mut fields = serde_json::Map::new();
    fields.insert("email".into(), firestore::s(email));
    for (k, v) in &current {
        fields.insert(k.clone(), firestore::s(v));
    }
    fs.set_doc("profiles", email, serde_json::Value::Object(fields)).await
}

fn challenge_expired(fields: &serde_json::Value) -> bool {
    let exp = fields
        .get("expiresAt")
        .and_then(|v| v.get("timestampValue"))
        .and_then(|v| v.as_str())
        .map(crate::firestore::parse_rfc3339_secs)
        .unwrap_or(0);
    exp < now()
}
