//! private_key_jwt クライアントの `jwks_uri` から公開鍵を取得し TTL キャッシュする
//! （RFC 7591 / 鍵ローテーション対応）。inline jwks に kid が無い時のフォールバック。

use crate::model::JwkPub;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// キャッシュ TTL。鍵ローテーションの反映遅延の上限であり、jwks_uri への取得頻度の下限。
const TTL_SECS: u64 = 300;

struct Cached {
    keys: Vec<JwkPub>,
    expires_at: u64,
}

pub struct JwksResolver {
    http: reqwest::Client,
    cache: Mutex<HashMap<String, Cached>>,
}

impl Default for JwksResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl JwksResolver {
    pub fn new() -> Self {
        Self {
            http: reqwest::Client::new(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// `jwks_uri` から kid に一致する公開鍵を返す。キャッシュが有効ならその中から探し、
    /// 期限切れ/未取得なら取得し直す。kid が見つからなければ None。
    pub async fn resolve(&self, jwks_uri: &str, kid: &str) -> Option<JwkPub> {
        let now = now();
        {
            let cache = self.cache.lock().unwrap();
            if let Some(c) = cache.get(jwks_uri) {
                if c.expires_at > now {
                    return c.keys.iter().find(|k| k.kid == kid).cloned();
                }
            }
        }
        let keys = self.fetch(jwks_uri).await?;
        let found = keys.iter().find(|k| k.kid == kid).cloned();
        self.cache.lock().unwrap().insert(
            jwks_uri.to_string(),
            Cached { keys, expires_at: now + TTL_SECS },
        );
        found
    }

    async fn fetch(&self, jwks_uri: &str) -> Option<Vec<JwkPub>> {
        // SSRF 緩和: https のみ。jwks_uri は DCR(IAT 必須)で登録された半信頼値だが二重に絞る。
        // 内部 https へのアクセス遮断（private IP 拒否）は本実装の範囲外（運用/ネットワークで担保）。
        if !jwks_uri.starts_with("https://") {
            return None;
        }
        let resp = self
            .http
            .get(jwks_uri)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .ok()?;
        if !resp.status().is_success() {
            return None;
        }
        let v: serde_json::Value = resp.json().await.ok()?;
        let keys = crate::dcr::jwks_from_jwk_set(Some(&v));
        if keys.is_empty() {
            None
        } else {
            Some(keys)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn non_https_schemes_are_rejected_for_ssrf() {
        let r = JwksResolver::new();
        // https 以外は一切ネットワークに出さない（SSRF 緩和）。大文字 HTTPS も
        // starts_with は大小区別＝拒否（err on the safe side）。
        for bad in [
            "http://example.com/jwks",
            "file:///etc/passwd",
            "ftp://host/jwks",
            "gopher://host/",
            "javascript:alert(1)",
            "HTTPS://Example.com/jwks",
            "https:/missing-slash",
            "//evil.com/jwks",
            "",
            " https://leading-space/jwks",
        ] {
            assert!(r.fetch(bad).await.is_none(), "{bad:?} を取得してはならない");
        }
    }
}
