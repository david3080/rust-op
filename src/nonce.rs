//! 単回 nonce / jti ストア。リプレイ防止に使う。
//! ローカル/テストは in-memory、本番（Cloud Run）は Firestore（インスタンス跨ぎで単回保証）。

use crate::firestore::{self, Firestore};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// jti / nonce の単回 claim を提供する。
pub enum NonceStore {
    Memory(Mutex<HashMap<String, Instant>>),
    Firestore(Arc<Firestore>),
}

impl NonceStore {
    pub fn memory() -> Self {
        NonceStore::Memory(Mutex::new(HashMap::new()))
    }

    pub fn firestore(fs: Arc<Firestore>) -> Self {
        NonceStore::Firestore(fs)
    }

    /// `key` を単回で claim する。初出（fresh）なら true、既出（replay）なら false。
    /// `ttl` は in-memory の保持期間 / Firestore の expiresAt 算出に使う。
    /// Firestore エラー時は **fail-open（true=許可）**：可用性を優先し、in-memory 相当の
    /// 防御（= iat 窓 60 秒）にデグレードさせる（リプレイ防止は best-effort のハードニング）。
    pub async fn claim(&self, key: &str, ttl: Duration) -> bool {
        match self {
            NonceStore::Memory(m) => {
                let mut g = m.lock().unwrap();
                let now = Instant::now();
                g.retain(|_, exp| *exp > now);
                if g.contains_key(key) {
                    false
                } else {
                    g.insert(key.to_string(), now + ttl);
                    true
                }
            }
            NonceStore::Firestore(fs) => {
                let exp = firestore::rfc3339(now_secs() + ttl.as_secs());
                let fields = serde_json::json!({ "expiresAt": firestore::ts(&exp) });
                match fs.create_if_absent("nonces", key, fields).await {
                    Ok(created) => created, // created=true は初出、false は既存=replay
                    Err(e) => {
                        tracing::warn!("nonce store error ({e}); fail-open");
                        true
                    }
                }
            }
        }
    }
}

impl Default for NonceStore {
    fn default() -> Self {
        NonceStore::memory()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn memory_claim_is_single_use() {
        let s = NonceStore::memory();
        assert!(s.claim("jti-1", Duration::from_secs(300)).await); // 初出
        assert!(!s.claim("jti-1", Duration::from_secs(300)).await); // 再claim=replay
        assert!(s.claim("jti-2", Duration::from_secs(300)).await); // 別keyは独立
    }

    #[tokio::test]
    async fn memory_expired_entries_are_reclaimable() {
        let s = NonceStore::memory();
        assert!(s.claim("x", Duration::from_millis(20)).await);
        assert!(!s.claim("x", Duration::from_millis(20)).await);
        std::thread::sleep(Duration::from_millis(40));
        assert!(s.claim("x", Duration::from_millis(20)).await); // TTL 経過で再claim可
    }
}
