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

/// request_uri を単回消費し (client_id, params) を返す。期限切れ・不正は None。
pub async fn consume(fs: &Firestore, request_uri: &str) -> Result<Option<(String, String)>, String> {
    let id = match request_uri.strip_prefix(URN_PREFIX) {
        Some(id) if (20..=100).contains(&id.len()) => id,
        _ => return Ok(None),
    };
    let fields = match fs.get_doc(COL, id).await? {
        Some(f) => f,
        None => return Ok(None),
    };
    fs.delete_doc(COL, id).await.ok();
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
