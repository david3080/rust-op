//! FIDO の永続化抽象。conformance/ローカルは MemFidoStore（in-memory）、
//! Cloud Run(K_SERVICE) は FirestoreFidoStore。OIDC 統合時はこの credential を
//! accounts(email) と統合していく（user キーに email を渡す）。

use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::es256::{b64url_decode, b64url_encode};
use crate::fido::verify::CredKey;
use crate::firestore::{self, Firestore};
use serde_json::{json, Value};

const CHALLENGE_TTL_SECS: u64 = 300;

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// 登録/認証セレモニーの状態。challenge をキーに引く。
#[derive(Clone)]
pub struct ChallengeState {
    pub username: String,
    /// "required" のときだけ UV を必須にする。
    pub user_verification: Option<String>,
    pub created_at: u64,
}

#[derive(Clone)]
pub struct StoredCredential {
    pub id: String, // credentialId（b64url）
    pub key: CredKey,
    pub sign_count: u32,
}

#[async_trait]
pub trait FidoStore: Send + Sync {
    async fn save_challenge(&self, challenge: &str, st: ChallengeState);
    async fn get_challenge(&self, challenge: &str) -> Option<ChallengeState>;
    async fn save_credential(&self, user: &str, cred: StoredCredential);
    async fn find_credentials(&self, user: &str) -> Vec<StoredCredential>;
    async fn update_sign_count(&self, user: &str, cred_id: &str, new_count: u32);
}

/* ===== in-memory（ローカル / conformance 既定） ===== */

#[derive(Default)]
struct MemInner {
    challenges: HashMap<String, ChallengeState>,
    credentials: HashMap<String, Vec<StoredCredential>>,
}

#[derive(Default)]
pub struct MemFidoStore {
    inner: Mutex<MemInner>,
}

#[async_trait]
impl FidoStore for MemFidoStore {
    async fn save_challenge(&self, challenge: &str, st: ChallengeState) {
        let mut g = self.inner.lock().unwrap();
        let cutoff = now().saturating_sub(CHALLENGE_TTL_SECS);
        g.challenges.retain(|_, v| v.created_at >= cutoff);
        g.challenges.insert(challenge.to_string(), st);
    }
    async fn get_challenge(&self, challenge: &str) -> Option<ChallengeState> {
        let g = self.inner.lock().unwrap();
        let st = g.challenges.get(challenge)?;
        if st.created_at < now().saturating_sub(CHALLENGE_TTL_SECS) {
            return None;
        }
        Some(st.clone())
    }
    async fn save_credential(&self, user: &str, cred: StoredCredential) {
        let mut g = self.inner.lock().unwrap();
        let list = g.credentials.entry(user.to_string()).or_default();
        if !list.iter().any(|c| c.id == cred.id) {
            list.push(cred);
        }
    }
    async fn find_credentials(&self, user: &str) -> Vec<StoredCredential> {
        self.inner.lock().unwrap().credentials.get(user).cloned().unwrap_or_default()
    }
    async fn update_sign_count(&self, user: &str, cred_id: &str, new_count: u32) {
        let mut g = self.inner.lock().unwrap();
        if let Some(list) = g.credentials.get_mut(user) {
            if let Some(c) = list.iter_mut().find(|c| c.id == cred_id) {
                c.sign_count = new_count;
            }
        }
    }
}

/* ===== Firestore（Cloud Run） ===== */

const COL_CHALLENGES: &str = "fidoChallenges";
const COL_CREDENTIALS: &str = "fidoCredentials";

pub struct FirestoreFidoStore {
    fs: Arc<Firestore>,
}

impl FirestoreFidoStore {
    pub fn new(fs: Arc<Firestore>) -> Self {
        Self { fs }
    }
}

fn cred_to_fields(user: &str, c: &StoredCredential) -> Value {
    let mut f = serde_json::Map::new();
    f.insert("user".into(), firestore::s(user));
    f.insert("credId".into(), firestore::s(&c.id));
    f.insert("signCount".into(), firestore::int(c.sign_count as u64));
    let (kty, parts): (&str, Vec<(&str, &[u8])>) = match &c.key {
        CredKey::Es256 { x, y } => ("es256", vec![("x", x), ("y", y)]),
        CredKey::Rs256 { n, e } => ("rs256", vec![("n", n), ("e", e)]),
        CredKey::Rs1 { n, e } => ("rs1", vec![("n", n), ("e", e)]),
        CredKey::Ed25519 { pk } => ("ed25519", vec![("pk", pk)]),
    };
    f.insert("kty".into(), firestore::s(kty));
    for (k, v) in parts {
        f.insert(k.to_string(), firestore::s(&b64url_encode(v)));
    }
    Value::Object(f)
}

fn cred_from_fields(f: &Value) -> Option<StoredCredential> {
    let id = firestore::field_str(f, "credId")?.to_string();
    let sign_count = firestore::field_u64(f, "signCount").unwrap_or(0) as u32;
    let dec = |k: &str| b64url_decode(firestore::field_str(f, k).unwrap_or("")).ok();
    let key = match firestore::field_str(f, "kty")? {
        "es256" => CredKey::Es256 { x: dec("x")?, y: dec("y")? },
        "rs256" => CredKey::Rs256 { n: dec("n")?, e: dec("e")? },
        "rs1" => CredKey::Rs1 { n: dec("n")?, e: dec("e")? },
        "ed25519" => CredKey::Ed25519 { pk: dec("pk")? },
        _ => return None,
    };
    Some(StoredCredential { id, key, sign_count })
}

#[async_trait]
impl FidoStore for FirestoreFidoStore {
    async fn save_challenge(&self, challenge: &str, st: ChallengeState) {
        let fields = json!({
            "username": firestore::s(&st.username),
            "userVerification": firestore::s(st.user_verification.as_deref().unwrap_or("")),
            "expiresAt": firestore::ts(&firestore::rfc3339(now() + CHALLENGE_TTL_SECS)),
        });
        let _ = self.fs.set_doc(COL_CHALLENGES, challenge, fields).await;
    }
    async fn get_challenge(&self, challenge: &str) -> Option<ChallengeState> {
        let f = self.fs.get_doc(COL_CHALLENGES, challenge).await.ok()??;
        let expires = firestore::field_ts_secs(&f, "expiresAt").unwrap_or(0);
        if expires < now() {
            return None;
        }
        let uv = firestore::field_str(&f, "userVerification").unwrap_or("");
        Some(ChallengeState {
            username: firestore::field_str(&f, "username").unwrap_or("").to_string(),
            user_verification: (!uv.is_empty()).then(|| uv.to_string()),
            created_at: now(),
        })
    }
    async fn save_credential(&self, user: &str, cred: StoredCredential) {
        let _ = self
            .fs
            .set_doc(COL_CREDENTIALS, &cred.id, cred_to_fields(user, &cred))
            .await;
    }
    async fn find_credentials(&self, user: &str) -> Vec<StoredCredential> {
        match self.fs.query_eq(COL_CREDENTIALS, "user", user).await {
            Ok(rows) => rows.iter().filter_map(|(_, f)| cred_from_fields(f)).collect(),
            Err(_) => Vec::new(),
        }
    }
    async fn update_sign_count(&self, user: &str, cred_id: &str, new_count: u32) {
        // credId(=doc id) で取り直し、signCount を更新して再保存。
        if let Ok(Some(f)) = self.fs.get_doc(COL_CREDENTIALS, cred_id).await {
            if let Some(mut cred) = cred_from_fields(&f) {
                cred.sign_count = new_count;
                let _ = self
                    .fs
                    .set_doc(COL_CREDENTIALS, cred_id, cred_to_fields(user, &cred))
                    .await;
            }
        }
    }
}
