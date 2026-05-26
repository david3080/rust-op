//! CIBA (OIDC Client-Initiated Backchannel Authentication) のバックチャネル要求。
//! Rust を生かす: auth_req_id は newtype、status は網羅 enum、Firestore 永続化。

use crate::firestore::{self, Firestore};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

const TTL_SECS: u64 = 300;
const COL: &str = "cibaRequests";

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// auth_req_id は他の ID(token/challenge)と取り違えないよう newtype 化。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AuthReqId(pub String);

impl AuthReqId {
    pub fn generate() -> Self {
        Self(uuid::Uuid::new_v4().simple().to_string())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// バックチャネル要求の状態。poll はこれで網羅分岐する。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CibaStatus {
    Pending,
    Approved,
    Denied,
}

impl CibaStatus {
    fn as_str(self) -> &'static str {
        match self {
            CibaStatus::Pending => "pending",
            CibaStatus::Approved => "approved",
            CibaStatus::Denied => "denied",
        }
    }
    fn parse(s: &str) -> Self {
        match s {
            "approved" => CibaStatus::Approved,
            "denied" => CibaStatus::Denied,
            _ => CibaStatus::Pending,
        }
    }
}

pub struct BackchannelAuthRequest {
    pub auth_req_id: AuthReqId,
    pub client_id: String,
    pub account: String,
    pub scope: String,
    pub binding_message: String,
    pub status: CibaStatus,
    pub expires_at: u64,
}

impl BackchannelAuthRequest {
    pub fn expired(&self) -> bool {
        self.expires_at < now()
    }
    fn fields(&self) -> serde_json::Value {
        json!({
            "clientId": firestore::s(&self.client_id),
            "account": firestore::s(&self.account),
            "scope": firestore::s(&self.scope),
            "bindingMessage": firestore::s(&self.binding_message),
            "status": firestore::s(self.status.as_str()),
            "expiresAt": firestore::ts(&firestore::rfc3339(self.expires_at)),
        })
    }
    fn from_fields(auth_req_id: AuthReqId, f: &serde_json::Value) -> Self {
        let g = |k: &str| firestore::field_str(f, k).unwrap_or("").to_string();
        let expires_at = f
            .get("expiresAt")
            .and_then(|v| v.get("timestampValue"))
            .and_then(|v| v.as_str())
            .map(firestore::parse_rfc3339_secs)
            .unwrap_or(0);
        Self {
            auth_req_id,
            client_id: g("clientId"),
            account: g("account"),
            scope: g("scope"),
            binding_message: g("bindingMessage"),
            status: CibaStatus::parse(firestore::field_str(f, "status").unwrap_or("pending")),
            expires_at,
        }
    }
}

pub async fn create(
    fs: &Firestore,
    client_id: &str,
    account: &str,
    scope: &str,
    binding_message: &str,
) -> Result<AuthReqId, String> {
    let req = BackchannelAuthRequest {
        auth_req_id: AuthReqId::generate(),
        client_id: client_id.to_string(),
        account: account.to_string(),
        scope: scope.to_string(),
        binding_message: binding_message.to_string(),
        status: CibaStatus::Pending,
        expires_at: now() + TTL_SECS,
    };
    fs.set_doc(COL, req.auth_req_id.as_str(), req.fields()).await?;
    Ok(req.auth_req_id)
}

pub async fn get(fs: &Firestore, auth_req_id: &str) -> Result<Option<BackchannelAuthRequest>, String> {
    match fs.get_doc(COL, auth_req_id).await? {
        Some(f) => Ok(Some(BackchannelAuthRequest::from_fields(
            AuthReqId(auth_req_id.to_string()),
            &f,
        ))),
        None => Ok(None),
    }
}

/// Pending のときだけ status へ原子的に遷移する（CIBA の「先勝ち」）。
/// 遷移できたら Ok(true)。既に Pending でない / 他者が先に更新（レース敗北）なら Ok(false)。
/// updateTime プリコンディションで承認と拒否の競合を一意に決める。
pub async fn transition_if_pending(
    fs: &Firestore,
    auth_req_id: &str,
    status: CibaStatus,
) -> Result<bool, String> {
    let (fields, update_time) = match fs.get_doc_with_update_time(COL, auth_req_id).await? {
        Some(x) => x,
        None => return Ok(false),
    };
    let mut req = BackchannelAuthRequest::from_fields(AuthReqId(auth_req_id.to_string()), &fields);
    if req.status != CibaStatus::Pending {
        return Ok(false); // 既に承認/拒否済み（後発は負け）
    }
    req.status = status;
    fs.set_doc_if_unchanged(COL, auth_req_id, req.fields(), &update_time).await
}

pub async fn delete(fs: &Firestore, auth_req_id: &str) -> Result<(), String> {
    fs.delete_doc(COL, auth_req_id).await
}

/// Approved の要求を原子的に「消費（削除）」する。CIBA は単回なので、poll が並行しても
/// CAS 削除に成功した呼び出しだけがトークンを発行できる。消費できたら Ok(Some(req))、
/// 既に消費済み/Pending/Denied/レース敗北なら Ok(None)。
pub async fn consume_if_approved(
    fs: &Firestore,
    auth_req_id: &str,
) -> Result<Option<BackchannelAuthRequest>, String> {
    let (fields, update_time) = match fs.get_doc_with_update_time(COL, auth_req_id).await? {
        Some(x) => x,
        None => return Ok(None),
    };
    let req = BackchannelAuthRequest::from_fields(AuthReqId(auth_req_id.to_string()), &fields);
    if req.status != CibaStatus::Approved {
        return Ok(None);
    }
    if fs.delete_doc_if_unchanged(COL, auth_req_id, &update_time).await? {
        Ok(Some(req))
    } else {
        Ok(None) // 他者が先に消費（レース敗北）
    }
}

/// アカウントの pending な要求一覧（承認 UI 用）。期限切れは除く。
pub async fn list_pending(fs: &Firestore, account: &str) -> Result<Vec<BackchannelAuthRequest>, String> {
    let rows = fs.query_eq(COL, "account", account).await?;
    Ok(rows
        .into_iter()
        .map(|(id, f)| BackchannelAuthRequest::from_fields(AuthReqId(id), &f))
        .filter(|r| r.status == CibaStatus::Pending && !r.expired())
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_str_roundtrip_and_unknown_defaults_pending() {
        for s in [CibaStatus::Pending, CibaStatus::Approved, CibaStatus::Denied] {
            assert_eq!(CibaStatus::parse(s.as_str()), s);
        }
        assert_eq!(CibaStatus::parse("garbage"), CibaStatus::Pending);
    }

    #[test]
    fn fields_roundtrip_preserves_values() {
        let req = BackchannelAuthRequest {
            auth_req_id: AuthReqId("abc".into()),
            client_id: "rp".into(),
            account: "u@example.com".into(),
            scope: "openid profile".into(),
            binding_message: "確認してください".into(),
            status: CibaStatus::Approved,
            expires_at: 1_900_000_000,
        };
        let back = BackchannelAuthRequest::from_fields(AuthReqId("abc".into()), &req.fields());
        assert_eq!(back.client_id, "rp");
        assert_eq!(back.account, "u@example.com");
        assert_eq!(back.scope, "openid profile");
        assert_eq!(back.binding_message, "確認してください");
        assert_eq!(back.status, CibaStatus::Approved);
        assert_eq!(back.expires_at, 1_900_000_000);
    }

    #[test]
    fn expired_reflects_clock() {
        let mk = |exp| BackchannelAuthRequest {
            auth_req_id: AuthReqId("x".into()),
            client_id: "c".into(),
            account: "a".into(),
            scope: "openid".into(),
            binding_message: String::new(),
            status: CibaStatus::Pending,
            expires_at: exp,
        };
        assert!(mk(0).expired());
        assert!(!mk(now() + 100).expired());
    }
}
