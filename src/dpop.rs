//! DPoP (RFC 9449) proof 検証。概念トレイト + ES256 実装（ピュア Rust）。
//! proof は JWS Compact（ES256, 署名は raw r||s 64byte）。WebAuthn の DER とは別。

use crate::es256;
use crate::nonce::NonceStore;
use async_trait::async_trait;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::Signature;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;

const IAT_SKEW_SECS: i64 = 60;
const JTI_TTL: Duration = Duration::from_secs(300);

#[async_trait]
pub trait DpopVerifier: Send + Sync {
    /// proof を検証し、成功時に jkt (JWK SHA-256 Thumbprint) を返す。
    /// expected_ath は resource(userinfo) 検証時のみ Some。
    async fn verify(
        &self,
        proof: &str,
        htm: &str,
        htu: &str,
        expected_ath: Option<&str>,
    ) -> Result<String, String>;
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// access_token の ath（RFC 9449 §4.3）= base64url(SHA-256(token ascii))。全長。
pub fn ath(access_token: &str) -> String {
    es256::b64url_encode(Sha256::digest(access_token.as_bytes()))
}

/// htu 正規化: query(?) と fragment(#) を除去（RFC 9449 §4.3）。
/// `'?'`/`'#'` は ASCII なので `find` の返す byte index は常に UTF-8 境界 → `&u[..end]` は
/// panic しない。この境界安全性を Kani で確認する（記号モデルが見ない実装固有の死角。ただし
/// `find` の記号スキャンが状態爆発するため代表的な境界ケースに有界化。kani_harness.rs 参照）。
pub(crate) fn strip_query_fragment(u: &str) -> &str {
    let end = u.find(['?', '#']).unwrap_or(u.len());
    &u[..end]
}

pub struct Es256Dpop {
    jti: NonceStore,
}

impl Default for Es256Dpop {
    fn default() -> Self {
        Self { jti: NonceStore::memory() }
    }
}

impl Es256Dpop {
    /// 本番: Firestore 連携で jti をインスタンス跨ぎで単回化する。
    pub fn with_store(fs: Arc<crate::firestore::Firestore>) -> Self {
        Self { jti: NonceStore::firestore(fs) }
    }
}

#[async_trait]
impl DpopVerifier for Es256Dpop {
    async fn verify(
        &self,
        proof: &str,
        htm: &str,
        htu: &str,
        expected_ath: Option<&str>,
    ) -> Result<String, String> {
        let parts: Vec<&str> = proof.split('.').collect();
        if parts.len() != 3 {
            return Err("proof not a compact JWS".into());
        }
        let header: serde_json::Value = serde_json::from_slice(&es256::b64url_decode(parts[0])?)
            .map_err(|e| format!("header json: {e}"))?;
        if header.get("typ").and_then(|v| v.as_str()) != Some("dpop+jwt") {
            return Err("typ != dpop+jwt".into());
        }
        if header.get("alg").and_then(|v| v.as_str()) != Some("ES256") {
            return Err("alg != ES256".into());
        }
        let jwk = header.get("jwk").ok_or("header.jwk missing")?;
        if jwk.get("kty").and_then(|v| v.as_str()) != Some("EC")
            || jwk.get("crv").and_then(|v| v.as_str()) != Some("P-256")
        {
            return Err("jwk not EC/P-256".into());
        }
        if jwk.get("d").is_some() {
            return Err("jwk contains private key".into());
        }
        let x = jwk.get("x").and_then(|v| v.as_str()).ok_or("jwk.x")?;
        let y = jwk.get("y").and_then(|v| v.as_str()).ok_or("jwk.y")?;

        // 署名検証（埋め込み公開鍵で）。JWS の ES256 署名は raw r||s。
        let vk = es256::verifying_key_from_xy(&es256::b64url_decode(x)?, &es256::b64url_decode(y)?)?;
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig = Signature::from_slice(&es256::b64url_decode(parts[2])?)
            .map_err(|e| format!("sig: {e}"))?;
        vk.verify(signing_input.as_bytes(), &sig)
            .map_err(|_| "invalid proof signature".to_string())?;

        // payload クレーム。
        let payload: serde_json::Value = serde_json::from_slice(&es256::b64url_decode(parts[1])?)
            .map_err(|e| format!("payload json: {e}"))?;
        if payload.get("htm").and_then(|v| v.as_str()) != Some(htm) {
            return Err("htm mismatch".into());
        }
        // RFC 9449 §4.3: htu 比較では query と fragment を無視する。
        let proof_htu = payload.get("htu").and_then(|v| v.as_str()).unwrap_or("");
        if strip_query_fragment(proof_htu) != strip_query_fragment(htu) {
            return Err(format!("htu mismatch (got {proof_htu:?}, want {htu})"));
        }
        let iat = payload.get("iat").and_then(|v| v.as_i64()).ok_or("iat missing")?;
        if (now_secs() - iat).abs() > IAT_SKEW_SECS {
            return Err("iat out of window".into());
        }
        if let Some(want) = expected_ath {
            if payload.get("ath").and_then(|v| v.as_str()) != Some(want) {
                return Err("ath mismatch".into());
            }
        }
        let jti = payload.get("jti").and_then(|v| v.as_str()).ok_or("jti missing")?;
        // DPoP と client_assertion で名前空間を分け、jti 文字列の偶発衝突を避ける。
        if !self.jti.claim(&format!("dpop:{jti}"), JTI_TTL).await {
            return Err("jti replay".into());
        }

        Ok(es256::jwk_thumbprint_p256(x, y))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Signer as _, Signature, SigningKey};
    use serde_json::{json, Value};

    /// header と payload(JSON)から ES256(raw r‖s)で署名した compact JWS を作る。
    fn make_proof(key: &SigningKey, header: &Value, payload: &Value) -> String {
        let h = es256::b64url_encode(header.to_string());
        let p = es256::b64url_encode(payload.to_string());
        let signing_input = format!("{h}.{p}");
        let sig: Signature = key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", es256::b64url_encode(sig.to_bytes()))
    }

    /// 埋め込み公開鍵 jwk を作る。
    fn pub_jwk(key: &SigningKey) -> Value {
        let pt = key.verifying_key().to_encoded_point(false);
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": es256::b64url_encode(pt.x().unwrap()),
            "y": es256::b64url_encode(pt.y().unwrap()),
        })
    }

    fn header(key: &SigningKey) -> Value {
        json!({"typ": "dpop+jwt", "alg": "ES256", "jwk": pub_jwk(key)})
    }

    fn payload(htm: &str, htu: &str, iat: i64) -> Value {
        json!({"htm": htm, "htu": htu, "iat": iat, "jti": uuid::Uuid::new_v4().to_string()})
    }

    const HTM: &str = "POST";
    const HTU: &str = "https://op.example/token";

    #[tokio::test]
    async fn valid_proof_returns_jkt() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let v = Es256Dpop::default();
        let proof = make_proof(&key, &header(&key), &payload(HTM, HTU, now_secs()));
        let jkt = v.verify(&proof, HTM, HTU, None).await.unwrap();
        // 返る jkt は埋め込み鍵の thumbprint。
        let pj = pub_jwk(&key);
        assert_eq!(jkt, es256::jwk_thumbprint_p256(pj["x"].as_str().unwrap(), pj["y"].as_str().unwrap()));
    }

    #[tokio::test]
    async fn rejects_non_compact() {
        let v = Es256Dpop::default();
        assert!(v.verify("only.two", HTM, HTU, None).await.is_err());
    }

    #[tokio::test]
    async fn rejects_wrong_typ() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let v = Es256Dpop::default();
        let mut h = header(&key);
        h["typ"] = json!("jwt");
        let proof = make_proof(&key, &h, &payload(HTM, HTU, now_secs()));
        assert!(v.verify(&proof, HTM, HTU, None).await.is_err());
    }

    #[tokio::test]
    async fn rejects_wrong_alg() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let v = Es256Dpop::default();
        let mut h = header(&key);
        h["alg"] = json!("RS256");
        let proof = make_proof(&key, &h, &payload(HTM, HTU, now_secs()));
        assert!(v.verify(&proof, HTM, HTU, None).await.is_err());
    }

    #[tokio::test]
    async fn rejects_jwk_containing_private_key() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let v = Es256Dpop::default();
        let mut h = header(&key);
        h["jwk"]["d"] = json!("c29tZS1wcml2YXRl"); // 秘密成分混入
        let proof = make_proof(&key, &h, &payload(HTM, HTU, now_secs()));
        assert!(v.verify(&proof, HTM, HTU, None).await.is_err());
    }

    #[tokio::test]
    async fn rejects_htm_and_htu_mismatch() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let v = Es256Dpop::default();
        let proof = make_proof(&key, &header(&key), &payload(HTM, HTU, now_secs()));
        assert!(v.verify(&proof, "GET", HTU, None).await.is_err()); // htm 不一致
        let proof2 = make_proof(&key, &header(&key), &payload(HTM, HTU, now_secs()));
        assert!(v.verify(&proof2, HTM, "https://evil.example/token", None).await.is_err()); // htu 不一致
    }

    #[tokio::test]
    async fn rejects_iat_out_of_window() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let v = Es256Dpop::default();
        // 過去側
        let past = make_proof(&key, &header(&key), &payload(HTM, HTU, now_secs() - 600));
        assert!(v.verify(&past, HTM, HTU, None).await.is_err());
        // 未来側（.abs() の両側を踏む）
        let future = make_proof(&key, &header(&key), &payload(HTM, HTU, now_secs() + 600));
        assert!(v.verify(&future, HTM, HTU, None).await.is_err());
    }

    #[tokio::test]
    async fn htu_ignores_query_and_fragment() {
        // RFC 9449 §4.3: proof の htu に query/fragment があっても、サーバ側 htu と
        // path まで一致すれば受理する。
        let key = SigningKey::random(&mut rand_core::OsRng);
        let v = Es256Dpop::default();
        let htu_with_extra = format!("{HTU}?foo=bar#frag");
        let proof = make_proof(&key, &header(&key), &payload(HTM, &htu_with_extra, now_secs()));
        assert!(v.verify(&proof, HTM, HTU, None).await.is_ok());
    }

    #[tokio::test]
    async fn ath_checked_when_expected() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let v = Es256Dpop::default();
        let token = "an-access-token";
        let mut pl = payload(HTM, HTU, now_secs());
        pl["ath"] = json!(ath(token));
        let proof = make_proof(&key, &header(&key), &pl);
        assert!(v.verify(&proof, HTM, HTU, Some(&ath(token))).await.is_ok());
        // ath を要求するのに proof に無い → 失敗。
        let proof2 = make_proof(&key, &header(&key), &payload(HTM, HTU, now_secs()));
        assert!(v.verify(&proof2, HTM, HTU, Some(&ath(token))).await.is_err());
    }

    #[tokio::test]
    async fn rejects_jti_replay() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let v = Es256Dpop::default();
        let pl = payload(HTM, HTU, now_secs()); // 同一 jti
        let proof = make_proof(&key, &header(&key), &pl);
        assert!(v.verify(&proof, HTM, HTU, None).await.is_ok());
        let proof_same = make_proof(&key, &header(&key), &pl);
        assert!(v.verify(&proof_same, HTM, HTU, None).await.is_err()); // リプレイ
    }

    #[tokio::test]
    async fn rejects_tampered_signature() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let v = Es256Dpop::default();
        let proof = make_proof(&key, &header(&key), &payload(HTM, HTU, now_secs()));
        // payload を別 htu に差し替え、署名はそのまま → 署名検証で落ちる。
        let parts: Vec<&str> = proof.split('.').collect();
        let forged_payload = es256::b64url_encode(payload(HTM, "https://evil.example/x", now_secs()).to_string());
        let forged = format!("{}.{}.{}", parts[0], forged_payload, parts[2]);
        assert!(v.verify(&forged, HTM, "https://evil.example/x", None).await.is_err());
    }

    #[tokio::test]
    async fn rejects_proof_signed_by_different_key_than_embedded_jwk() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let other = SigningKey::random(&mut rand_core::OsRng);
        let v = Es256Dpop::default();
        // 埋め込み jwk は key、署名は other → 署名検証で落ちる（鍵すり替え）。
        let h = header(&key);
        let pl = payload(HTM, HTU, now_secs());
        let hh = es256::b64url_encode(h.to_string());
        let pp = es256::b64url_encode(pl.to_string());
        let signing_input = format!("{hh}.{pp}");
        let sig: Signature = other.sign(signing_input.as_bytes());
        let proof = format!("{signing_input}.{}", es256::b64url_encode(sig.to_bytes()));
        assert!(v.verify(&proof, HTM, HTU, None).await.is_err());
    }
}
