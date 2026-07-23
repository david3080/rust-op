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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firestore::fake_firestore;

    #[tokio::test]
    async fn create_then_peek_roundtrips_and_is_non_destructive() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);

        let uri = create(&fs, "client-1", "response_type=code&scope=openid").await.unwrap();
        assert!(uri.0.starts_with(URN_PREFIX));

        // peek は削除しない(認可完了前は何度でも読める)。
        let first = peek(&fs, &uri.0).await.unwrap().unwrap();
        assert_eq!(first, ("client-1".to_string(), "response_type=code&scope=openid".to_string()));
        let second = peek(&fs, &uri.0).await.unwrap();
        assert!(second.is_some(), "peek はドキュメントを消費しない");
    }

    #[tokio::test]
    async fn delete_makes_request_uri_unusable() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);

        let uri = create(&fs, "client-1", "p=1").await.unwrap();
        delete(&fs, &uri.0).await;
        assert!(peek(&fs, &uri.0).await.unwrap().is_none(), "delete 後は再利用できない");
    }

    #[tokio::test]
    async fn peek_rejects_expired_request() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);

        // create() を経由せず、既に期限切れの expiresAt を直接書き込む
        // (期限判定は firestore.rules の TTL ではなくこのコード自身が行うため、直接検証できる)。
        let id = "expired-id-000000000000000000";
        fs.set_doc(
            COL,
            id,
            serde_json::json!({
                "clientId": firestore::s("client-1"),
                "params": firestore::s("p=1"),
                "expiresAt": firestore::ts(&firestore::rfc3339(0)), // 1970年、確実に期限切れ
            }),
        )
        .await
        .unwrap();

        let uri = format!("{URN_PREFIX}{id}");
        assert!(peek(&fs, &uri).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn peek_rejects_malformed_request_uri() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);

        assert!(peek(&fs, "not-a-valid-uri").await.unwrap().is_none());
        assert!(peek(&fs, &format!("{URN_PREFIX}short")).await.unwrap().is_none(), "20文字未満のIDは拒否");
    }
}
