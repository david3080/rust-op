//! CIBA (OIDC Client-Initiated Backchannel Authentication) のバックチャネル要求。
//! Rust を生かす: auth_req_id は newtype、status は網羅 enum、Firestore 永続化。

use crate::firestore::{self, Firestore};
use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;
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

#[derive(Clone)]
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

/// CIBA バックチャネル要求の永続化。本番は Firestore、テストは In-memory。
/// transition_if_pending / consume_if_approved は CIBA の「先勝ち」「単回消費」を担う
/// CAS 操作で、承認/拒否の競合と並行 poll の二重発行を一意に決める。
#[async_trait]
pub trait CibaStore: Send + Sync {
    async fn create(
        &self,
        client_id: &str,
        account: &str,
        scope: &str,
        binding_message: &str,
    ) -> Result<AuthReqId, String>;
    async fn get(&self, auth_req_id: &str) -> Result<Option<BackchannelAuthRequest>, String>;
    /// Pending のときだけ status へ原子的に遷移。遷移できたら Ok(true)、
    /// 既に Pending でない/レース敗北なら Ok(false)。
    async fn transition_if_pending(&self, auth_req_id: &str, status: CibaStatus) -> Result<bool, String>;
    /// Approved を原子的に消費（削除）。消費できたら Ok(Some(req))、
    /// 既に消費済み/Pending/Denied/レース敗北なら Ok(None)。
    async fn consume_if_approved(&self, auth_req_id: &str) -> Result<Option<BackchannelAuthRequest>, String>;
    async fn delete(&self, auth_req_id: &str) -> Result<(), String>;
    /// アカウントの pending な要求一覧（承認 UI 用）。期限切れは除く。
    async fn list_pending(&self, account: &str) -> Result<Vec<BackchannelAuthRequest>, String>;
}

/// 本番実装。Firestore の updateTime プリコンディションで CAS を実現する。
pub struct FirestoreCibaStore {
    fs: Arc<Firestore>,
}

impl FirestoreCibaStore {
    pub fn new(fs: Arc<Firestore>) -> Self {
        Self { fs }
    }
}

#[async_trait]
impl CibaStore for FirestoreCibaStore {
    async fn create(
        &self,
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
        self.fs.set_doc(COL, req.auth_req_id.as_str(), req.fields()).await?;
        Ok(req.auth_req_id)
    }

    async fn get(&self, auth_req_id: &str) -> Result<Option<BackchannelAuthRequest>, String> {
        match self.fs.get_doc(COL, auth_req_id).await? {
            Some(f) => Ok(Some(BackchannelAuthRequest::from_fields(
                AuthReqId(auth_req_id.to_string()),
                &f,
            ))),
            None => Ok(None),
        }
    }

    async fn transition_if_pending(&self, auth_req_id: &str, status: CibaStatus) -> Result<bool, String> {
        let (fields, update_time) = match self.fs.get_doc_with_update_time(COL, auth_req_id).await? {
            Some(x) => x,
            None => return Ok(false),
        };
        let mut req = BackchannelAuthRequest::from_fields(AuthReqId(auth_req_id.to_string()), &fields);
        if req.status != CibaStatus::Pending {
            return Ok(false);
        }
        req.status = status;
        self.fs.set_doc_if_unchanged(COL, auth_req_id, req.fields(), &update_time).await
    }

    async fn consume_if_approved(&self, auth_req_id: &str) -> Result<Option<BackchannelAuthRequest>, String> {
        let (fields, update_time) = match self.fs.get_doc_with_update_time(COL, auth_req_id).await? {
            Some(x) => x,
            None => return Ok(None),
        };
        let req = BackchannelAuthRequest::from_fields(AuthReqId(auth_req_id.to_string()), &fields);
        if req.status != CibaStatus::Approved {
            return Ok(None);
        }
        if self.fs.delete_doc_if_unchanged(COL, auth_req_id, &update_time).await? {
            Ok(Some(req))
        } else {
            Ok(None)
        }
    }

    async fn delete(&self, auth_req_id: &str) -> Result<(), String> {
        self.fs.delete_doc(COL, auth_req_id).await
    }

    async fn list_pending(&self, account: &str) -> Result<Vec<BackchannelAuthRequest>, String> {
        let rows = self.fs.query_eq(COL, "account", account).await?;
        Ok(rows
            .into_iter()
            .map(|(id, f)| BackchannelAuthRequest::from_fields(AuthReqId(id), &f))
            .filter(|r| r.status == CibaStatus::Pending && !r.expired())
            .collect())
    }
}

/// In-memory 実装（Provider のデフォルト / テスト用）。Mutex 下で状態遷移するので
/// 「先勝ち」「単回消費」のロジックは満たすが、Firestore の updateTime CAS 自体の
/// 検証にはならない（そこはコードレビューで担保）。
#[derive(Default)]
pub struct MemoryCibaStore {
    map: std::sync::Mutex<std::collections::HashMap<String, BackchannelAuthRequest>>,
}

#[async_trait]
impl CibaStore for MemoryCibaStore {
    async fn create(
        &self,
        client_id: &str,
        account: &str,
        scope: &str,
        binding_message: &str,
    ) -> Result<AuthReqId, String> {
        let id = AuthReqId::generate();
        let req = BackchannelAuthRequest {
            auth_req_id: id.clone(),
            client_id: client_id.to_string(),
            account: account.to_string(),
            scope: scope.to_string(),
            binding_message: binding_message.to_string(),
            status: CibaStatus::Pending,
            expires_at: now() + TTL_SECS,
        };
        self.map.lock().unwrap().insert(id.0.clone(), req);
        Ok(id)
    }

    async fn get(&self, auth_req_id: &str) -> Result<Option<BackchannelAuthRequest>, String> {
        Ok(self.map.lock().unwrap().get(auth_req_id).cloned())
    }

    async fn transition_if_pending(&self, auth_req_id: &str, status: CibaStatus) -> Result<bool, String> {
        let mut map = self.map.lock().unwrap();
        match map.get_mut(auth_req_id) {
            Some(req) if req.status == CibaStatus::Pending => {
                req.status = status;
                Ok(true)
            }
            _ => Ok(false),
        }
    }

    async fn consume_if_approved(&self, auth_req_id: &str) -> Result<Option<BackchannelAuthRequest>, String> {
        let mut map = self.map.lock().unwrap();
        match map.get(auth_req_id) {
            Some(req) if req.status == CibaStatus::Approved => Ok(map.remove(auth_req_id)),
            _ => Ok(None),
        }
    }

    async fn delete(&self, auth_req_id: &str) -> Result<(), String> {
        self.map.lock().unwrap().remove(auth_req_id);
        Ok(())
    }

    async fn list_pending(&self, account: &str) -> Result<Vec<BackchannelAuthRequest>, String> {
        Ok(self
            .map
            .lock()
            .unwrap()
            .values()
            .filter(|r| r.account == account && r.status == CibaStatus::Pending && !r.expired())
            .cloned()
            .collect())
    }
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

    #[tokio::test]
    async fn memory_store_transition_is_first_wins() {
        let s = MemoryCibaStore::default();
        let id = s.create("rp", "u", "openid", "").await.unwrap();
        // 先勝ち: 最初の Pending→Approved だけ成功し、後発は負ける。
        assert!(s.transition_if_pending(id.as_str(), CibaStatus::Approved).await.unwrap());
        assert!(!s.transition_if_pending(id.as_str(), CibaStatus::Denied).await.unwrap());
        assert_eq!(s.get(id.as_str()).await.unwrap().unwrap().status, CibaStatus::Approved);
    }

    #[tokio::test]
    async fn memory_store_consume_is_single_use() {
        let s = MemoryCibaStore::default();
        let id = s.create("rp", "u", "openid", "").await.unwrap();
        // Approved でないと消費できない。
        assert!(s.consume_if_approved(id.as_str()).await.unwrap().is_none());
        s.transition_if_pending(id.as_str(), CibaStatus::Approved).await.unwrap();
        // 単回消費: 1 回目だけ Some、2 回目は None（並行 poll の二重発行防止）。
        assert!(s.consume_if_approved(id.as_str()).await.unwrap().is_some());
        assert!(s.consume_if_approved(id.as_str()).await.unwrap().is_none());
        assert!(s.get(id.as_str()).await.unwrap().is_none());
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
