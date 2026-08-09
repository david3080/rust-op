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
    /// 管理者による凍結フラグ。true ならログイン/CIBA承認を拒否する
    /// （[`crate::account_admin`] 参照）。欠落時は false（既存アカウントは凍結されていない）。
    pub disabled: bool,
}

/// account_id は呼び出し側が払い出す（新規登録なら新規 UUID、既存 passkey 追加なら既存値の再利用）。
/// accounts/{email} を先に書き、逆引き accountsByUuid/{account_id} を後で書く。
/// 逆引きの書き込みが失敗しても登録自体は失敗させない（email 入力でのログインは影響を受けない、
/// discoverable ログインのみ縮退する）。
///
/// 既存アカウントの disabled 状態を引き継ぐ: 全フィールド置換の書き込みなので、ここで
/// 明示的に引き継がないと、凍結済みアカウントが passkey を作り直す（機種変更/再登録）
/// だけで凍結が消えてしまう（disabled を持たない新フィールド集合で上書きされるため）。
pub async fn save_credential(
    fs: &Firestore,
    email: &str,
    account_id: &str,
    c: &RegOutcome,
) -> Result<(), String> {
    let disabled = get_credential(fs, email).await?.map(|existing| existing.disabled).unwrap_or(false);
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
            "disabled": firestore::b(disabled),
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
        disabled: firestore::field_bool(&fields, "disabled").unwrap_or(false),
    }))
}

pub struct AccountSummary {
    pub email: String,
    pub account_id: String,
    pub disabled: bool,
    pub sign_count: u32,
    pub created_at: u64,
}

/// accounts/ 全件を列挙する（管理UIの一覧表示用）。accountId が欠落/空の壊れたドキュメントは
/// tracing::error! で痕跡を残しつつスキップする（get_credential の「fail-closed だが沈黙
/// しない」方針を踏襲。1件の壊れたドキュメントで一覧全体が失敗しないようにする）。
pub async fn list_accounts(fs: &Firestore) -> Result<Vec<AccountSummary>, String> {
    let rows = fs.list_collection("accounts").await?;
    let mut out = Vec::with_capacity(rows.len());
    for (email, fields, _update_time) in rows {
        let account_id = match firestore::field_str(&fields, "accountId") {
            Some(s) if !s.is_empty() => s.to_string(),
            _ => {
                tracing::error!("list_accounts: {email}: accountId missing/empty, skipping");
                continue;
            }
        };
        let sign_count = firestore::field_u64(&fields, "signCount").unwrap_or(0) as u32;
        out.push(AccountSummary {
            email,
            account_id,
            disabled: firestore::field_bool(&fields, "disabled").unwrap_or(false),
            sign_count,
            created_at: firestore::field_ts_secs(&fields, "createdAt").unwrap_or(0),
        });
    }
    Ok(out)
}

/// signCount だけを部分更新する（`Firestore::update_field`）。全フィールド置換の
/// read-modify-write だと、並行して走る `set_disabled` の書き込みと競合したとき
/// 後勝ちの側が相手の変更（disabled フラグ）を丸ごと巻き戻す事故になる
/// （両者が同じ accounts/{email} ドキュメントを取り合うため）。部分更新なら
/// 互いのフィールドに触れないのでこの競合が原理的に起きない。
pub async fn update_sign_count(fs: &Firestore, email: &str, n: u32) -> Result<(), String> {
    fs.update_field("accounts", email, "signCount", json!({ "integerValue": n.to_string() })).await
}

/// disabled フラグだけを部分更新する（[`update_sign_count`] と同じ理由で全体置換にしない）。
/// account_admin::disable_account/enable_account から呼ばれる。呼び出し側が事前に
/// get_credential でアカウントの存在を確認している前提（重複読み取りを避けるため、
/// ここでは再確認しない。存在しなければ update_field が currentDocument.exists 制約で
/// エラーを返す）。
pub async fn set_disabled(fs: &Firestore, email: &str, disabled: bool) -> Result<(), String> {
    fs.update_field("accounts", email, "disabled", firestore::b(disabled)).await
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firestore::fake_firestore;

    fn outcome(account_id: &str) -> RegOutcome {
        RegOutcome {
            credential_id: format!("cred-{account_id}"),
            pub_x: "x".into(),
            pub_y: "y".into(),
            sign_count: 0,
        }
    }

    #[tokio::test]
    async fn list_accounts_returns_all_and_reflects_disabled() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        save_credential(&fs, "a@example.com", "acc-a", &outcome("acc-a")).await.unwrap();
        save_credential(&fs, "b@example.com", "acc-b", &outcome("acc-b")).await.unwrap();
        set_disabled(&fs, "b@example.com", true).await.unwrap();

        let mut list = list_accounts(&fs).await.unwrap();
        list.sort_by(|a, b| a.email.cmp(&b.email));
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].email, "a@example.com");
        assert_eq!(list[0].account_id, "acc-a");
        assert!(!list[0].disabled);
        assert_eq!(list[1].email, "b@example.com");
        assert!(list[1].disabled);
    }

    #[tokio::test]
    async fn list_accounts_skips_docs_missing_account_id() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        save_credential(&fs, "good@example.com", "acc-good", &outcome("acc-good")).await.unwrap();
        // accountId を持たない壊れたドキュメントを直接差し込む。
        fs.set_doc("accounts", "broken@example.com", json!({ "email": firestore::s("broken@example.com") }))
            .await
            .unwrap();

        let list = list_accounts(&fs).await.unwrap();
        assert_eq!(list.len(), 1, "壊れたドキュメントはスキップされ、正常な1件だけ返る");
        assert_eq!(list[0].email, "good@example.com");
    }

    #[tokio::test]
    async fn list_accounts_empty_when_no_accounts() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        assert!(list_accounts(&fs).await.unwrap().is_empty());
    }
}
