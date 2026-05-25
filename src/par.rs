//! PAR (Pushed Authorization Requests, RFC 9126)。
//! クライアントが認可リクエストを事前 POST し request_uri を受け取る。
//! authorize はその request_uri からパラメータを復元する。FAPI 2.0 で必須。

use crate::firestore::{self, Firestore};
use crate::jws::b64url;
use rand_core::{OsRng, RngCore};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

const TTL_SECS: u64 = 60;
const COL: &str = "parRequests";
pub const URN_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// PAR の request_uri。auth_req_id 等と取り違えないよう newtype。
#[derive(Debug, Clone)]
pub struct RequestUri(pub String);

/// 認可リクエストを保存し request_uri を返す。params は元の urlencoded クエリ。
pub async fn create(fs: &Firestore, client_id: &str, params: &str) -> Result<RequestUri, String> {
    let mut buf = [0u8; 32];
    OsRng.fill_bytes(&mut buf);
    let id = b64url(buf);
    fs.set_doc(
        COL,
        &id,
        json!({
            "clientId": firestore::s(client_id),
            "params": firestore::s(params),
            "expiresAt": firestore::ts(&firestore::rfc3339(now() + TTL_SECS)),
        }),
    )
    .await?;
    Ok(RequestUri(format!("{URN_PREFIX}{id}")))
}

/// request_uri を読むが削除しない (client_id, params)。期限切れ・不正は None。
/// 認可完了前は再利用可能とするため /authorize ではこちらを使い、
/// コード発行時に delete で単回化する（RFC 9126: 完了後の再利用は不可）。
pub async fn peek(fs: &Firestore, request_uri: &str) -> Result<Option<(String, String)>, String> {
    let id = match request_uri.strip_prefix(URN_PREFIX) {
        Some(id) if (20..=100).contains(&id.len()) => id,
        _ => return Ok(None),
    };
    let fields = match fs.get_doc(COL, id).await? {
        Some(f) => f,
        None => return Ok(None),
    };
    let expires = fields
        .get("expiresAt")
        .and_then(|v| v.get("timestampValue"))
        .and_then(|v| v.as_str())
        .map(firestore::parse_rfc3339_secs)
        .unwrap_or(0);
    if expires < now() {
        return Ok(None);
    }
    let client_id = firestore::field_str(&fields, "clientId").unwrap_or("").to_string();
    let params = firestore::field_str(&fields, "params").unwrap_or("").to_string();
    Ok(Some((client_id, params)))
}

/// request_uri を削除する（コード発行時に呼び、以後の再利用を不可にする）。
pub async fn delete(fs: &Firestore, request_uri: &str) {
    if let Some(id) = request_uri.strip_prefix(URN_PREFIX) {
        fs.delete_doc(COL, id).await.ok();
    }
}
