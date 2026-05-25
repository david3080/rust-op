//! DPoP (RFC 9449) proof 検証。概念トレイト + ES256 実装（ピュア Rust）。
//! proof は JWS Compact（ES256, 署名は raw r||s 64byte）。WebAuthn の DER とは別。

use crate::es256;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::Signature;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

const IAT_SKEW_SECS: i64 = 60;
const JTI_TTL: Duration = Duration::from_secs(300);

pub trait DpopVerifier: Send + Sync {
    /// proof を検証し、成功時に jkt (JWK SHA-256 Thumbprint) を返す。
    /// expected_ath は resource(userinfo) 検証時のみ Some。
    fn verify(
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
fn strip_query_fragment(u: &str) -> &str {
    let end = u.find(['?', '#']).unwrap_or(u.len());
    &u[..end]
}

pub struct Es256Dpop {
    seen_jti: Mutex<HashMap<String, Instant>>,
}

impl Default for Es256Dpop {
    fn default() -> Self {
        Self { seen_jti: Mutex::new(HashMap::new()) }
    }
}

impl DpopVerifier for Es256Dpop {
    fn verify(
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
        {
            let mut seen = self.seen_jti.lock().unwrap();
            let now = Instant::now();
            seen.retain(|_, exp| *exp > now);
            if seen.contains_key(jti) {
                return Err("jti replay".into());
            }
            seen.insert(jti.to_string(), now + JTI_TTL);
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

    #[test]
    fn valid_proof_returns_jkt() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let v = Es256Dpop::default();
        let proof = make_proof(&key, &header(&key), &payload(HTM, HTU, now_secs()));
        let jkt = v.verify(&proof, HTM, HTU, None).unwrap();
        // 返る jkt は埋め込み鍵の thumbprint。
        let pj = pub_jwk(&key);
        assert_eq!(jkt, es256::jwk_thumbprint_p256(pj["x"].as_str().unwrap(), pj["y"].as_str().unwrap()));
    }

    #[test]
    fn rejects_non_compact() {
        let v = Es256Dpop::default();
        assert!(v.verify("only.two", HTM, HTU, None).is_err());
    }

    #[test]
    fn rejects_wrong_typ() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let v = Es256Dpop::default();
        let mut h = header(&key);
        h["typ"] = json!("jwt");
        let proof = make_proof(&key, &h, &payload(HTM, HTU, now_secs()));
        assert!(v.verify(&proof, HTM, HTU, None).is_err());
    }

    #[test]
    fn rejects_wrong_alg() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let v = Es256Dpop::default();
        let mut h = header(&key);
        h["alg"] = json!("RS256");
        let proof = make_proof(&key, &h, &payload(HTM, HTU, now_secs()));
        assert!(v.verify(&proof, HTM, HTU, None).is_err());
    }

    #[test]
    fn rejects_jwk_containing_private_key() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let v = Es256Dpop::default();
        let mut h = header(&key);
        h["jwk"]["d"] = json!("c29tZS1wcml2YXRl"); // 秘密成分混入
        let proof = make_proof(&key, &h, &payload(HTM, HTU, now_secs()));
        assert!(v.verify(&proof, HTM, HTU, None).is_err());
    }

    #[test]
    fn rejects_htm_and_htu_mismatch() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let v = Es256Dpop::default();
        let proof = make_proof(&key, &header(&key), &payload(HTM, HTU, now_secs()));
        assert!(v.verify(&proof, "GET", HTU, None).is_err()); // htm 不一致
        let proof2 = make_proof(&key, &header(&key), &payload(HTM, HTU, now_secs()));
        assert!(v.verify(&proof2, HTM, "https://evil.example/token", None).is_err()); // htu 不一致
    }

    #[test]
    fn rejects_iat_out_of_window() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let v = Es256Dpop::default();
        let proof = make_proof(&key, &header(&key), &payload(HTM, HTU, now_secs() - 600));
        assert!(v.verify(&proof, HTM, HTU, None).is_err());
    }

    #[test]
    fn ath_checked_when_expected() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let v = Es256Dpop::default();
        let token = "an-access-token";
        let mut pl = payload(HTM, HTU, now_secs());
        pl["ath"] = json!(ath(token));
        let proof = make_proof(&key, &header(&key), &pl);
        assert!(v.verify(&proof, HTM, HTU, Some(&ath(token))).is_ok());
        // ath を要求するのに proof に無い → 失敗。
        let proof2 = make_proof(&key, &header(&key), &payload(HTM, HTU, now_secs()));
        assert!(v.verify(&proof2, HTM, HTU, Some(&ath(token))).is_err());
    }

    #[test]
    fn rejects_jti_replay() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let v = Es256Dpop::default();
        let pl = payload(HTM, HTU, now_secs()); // 同一 jti
        let proof = make_proof(&key, &header(&key), &pl);
        assert!(v.verify(&proof, HTM, HTU, None).is_ok());
        let proof_same = make_proof(&key, &header(&key), &pl);
        assert!(v.verify(&proof_same, HTM, HTU, None).is_err()); // リプレイ
    }

    #[test]
    fn rejects_tampered_signature() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let v = Es256Dpop::default();
        let proof = make_proof(&key, &header(&key), &payload(HTM, HTU, now_secs()));
        // payload を別 htu に差し替え、署名はそのまま → 署名検証で落ちる。
        let parts: Vec<&str> = proof.split('.').collect();
        let forged_payload = es256::b64url_encode(payload(HTM, "https://evil.example/x", now_secs()).to_string());
        let forged = format!("{}.{}.{}", parts[0], forged_payload, parts[2]);
        assert!(v.verify(&forged, HTM, "https://evil.example/x", None).is_err());
    }

    #[test]
    fn rejects_proof_signed_by_different_key_than_embedded_jwk() {
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
        assert!(v.verify(&proof, HTM, HTU, None).is_err());
    }
}
