//! JWS 署名の概念トレイトと、ES256(P-256) のピュア Rust 実装。
//! 後で RS256/PS256/EdDSA を足す時はこのトレイトに impl を増やすだけ。

use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};

/// base64url(no-pad) エンコード。実体は es256 に集約。
pub fn b64url(bytes: impl AsRef<[u8]>) -> String {
    crate::es256::b64url_encode(bytes)
}

/// 署名鍵の概念。alg / 署名 / 公開 JWK を提供する。
/// sign は async（Cloud KMS 実装がネットワーク署名するため）。ローカル鍵実装は即時 return。
#[async_trait]
pub trait JwsSigner: Send + Sync {
    fn alg(&self) -> &str;
    /// claims を JWS Compact Serialization (header.payload.signature) で署名する。
    async fn sign(&self, claims: &serde_json::Value) -> String;
    /// /jwks で公開する 1 鍵分の JWK。
    fn public_jwk(&self) -> serde_json::Value;
}

pub struct Es256Signer {
    key: SigningKey,
    kid: String,
    x: String,
    y: String,
}

impl Es256Signer {
    pub fn generate() -> Self {
        let key = SigningKey::random(&mut rand_core::OsRng);
        Self::from_key(key)
    }

    /// 秘密スカラー(P-256, 32byte)の b64url から再構成する。
    /// Secret Manager 保存鍵の読込に使う。
    pub fn from_scalar_b64(s: &str) -> Result<Self, String> {
        let bytes = URL_SAFE_NO_PAD
            .decode(s.trim())
            .map_err(|e| format!("scalar b64: {e}"))?;
        let key = SigningKey::from_slice(&bytes).map_err(|e| format!("scalar key: {e}"))?;
        Ok(Self::from_key(key))
    }

    fn from_key(key: SigningKey) -> Self {
        let vk = key.verifying_key();
        let point = vk.to_encoded_point(false);
        let x = b64url(point.x().expect("P-256 has x"));
        let y = b64url(point.y().expect("P-256 has y"));
        let kid = thumbprint(&x, &y);
        Self { key, kid, x, y }
    }
}

/// RFC 7638 JWK Thumbprint (EC) は es256 に集約。
fn thumbprint(x: &str, y: &str) -> String {
    crate::es256::jwk_thumbprint_p256(x, y)
}

#[async_trait]
impl JwsSigner for Es256Signer {
    fn alg(&self) -> &str {
        "ES256"
    }
    async fn sign(&self, claims: &serde_json::Value) -> String {
        let header = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": self.kid });
        let header_b64 = b64url(header.to_string());
        let payload_b64 = b64url(claims.to_string());
        let signing_input = format!("{header_b64}.{payload_b64}");
        let sig: Signature = self.key.sign(signing_input.as_bytes());
        let sig_b64 = b64url(sig.to_bytes());
        format!("{signing_input}.{sig_b64}")
    }
    fn public_jwk(&self) -> serde_json::Value {
        serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": self.x,
            "y": self.y,
            "alg": "ES256",
            "use": "sig",
            "kid": self.kid,
        })
    }
}

/// RS256 (RSASSA-PKCS1-v1.5 / SHA-256)。OIDC Core §15.1 は OP に RS256 を要求する。
pub struct Rs256Signer {
    key: rsa::RsaPrivateKey,
    kid: String,
    n: String,
    e: String,
}

impl Rs256Signer {
    /// テスト専用の一時鍵生成。本番経路から参照できないよう cfg(test) で隔離する。
    #[cfg(test)]
    pub fn generate() -> Self {
        let key = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).expect("rsa keygen");
        Self::from_key(key)
    }

    /// PKCS#8 PEM から読み込む（Secret Manager 保存鍵の読込に使う）。
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, String> {
        use rsa::pkcs8::DecodePrivateKey;
        let key = rsa::RsaPrivateKey::from_pkcs8_pem(pem.trim())
            .map_err(|e| format!("rsa pkcs8 pem: {e}"))?;
        Ok(Self::from_key(key))
    }

    fn from_key(key: rsa::RsaPrivateKey) -> Self {
        use rsa::traits::PublicKeyParts;
        let n = b64url(key.n().to_bytes_be());
        let e = b64url(key.e().to_bytes_be());
        // RFC 7638 RSA Thumbprint: canonical JSON はキー昇順 e,kty,n。
        let canonical = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
        let kid = b64url(<sha2::Sha256 as sha2::Digest>::digest(canonical.as_bytes()));
        Self { key, kid, n, e }
    }
}

#[async_trait]
impl JwsSigner for Rs256Signer {
    fn alg(&self) -> &str {
        "RS256"
    }
    async fn sign(&self, claims: &serde_json::Value) -> String {
        use sha2::Digest;
        let header = serde_json::json!({ "alg": "RS256", "typ": "JWT", "kid": self.kid });
        let signing_input = format!("{}.{}", b64url(header.to_string()), b64url(claims.to_string()));
        let hashed = sha2::Sha256::digest(signing_input.as_bytes());
        let sig = self
            .key
            .sign(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &hashed)
            .expect("rsa sign");
        format!("{signing_input}.{}", b64url(sig))
    }
    fn public_jwk(&self) -> serde_json::Value {
        serde_json::json!({
            "kty": "RSA",
            "n": self.n,
            "e": self.e,
            "alg": "RS256",
            "use": "sig",
            "kid": self.kid,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

    fn b64d(s: &str) -> Vec<u8> {
        URL_SAFE_NO_PAD.decode(s).unwrap()
    }

    fn vk_from_jwk(jwk: &serde_json::Value) -> VerifyingKey {
        crate::es256::verifying_key_from_xy(
            &b64d(jwk["x"].as_str().unwrap()),
            &b64d(jwk["y"].as_str().unwrap()),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn sign_produces_verifiable_compact_jws() {
        let signer = Es256Signer::generate();
        let claims = serde_json::json!({"sub": "alice", "iss": "https://op.example"});
        let jwt = signer.sign(&claims).await;
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);

        // header に alg/typ/kid。
        let header: serde_json::Value = serde_json::from_slice(&b64d(parts[0])).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "JWT");
        assert_eq!(header["kid"], signer.kid);

        // payload はラウンドトリップする。
        let payload: serde_json::Value = serde_json::from_slice(&b64d(parts[1])).unwrap();
        assert_eq!(payload, claims);

        // 公開 JWK の (x,y) で署名検証できる。
        let vk = vk_from_jwk(&signer.public_jwk());
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig = Signature::from_slice(&b64d(parts[2])).unwrap();
        assert!(vk.verify(signing_input.as_bytes(), &sig).is_ok());
    }

    #[tokio::test]
    async fn tampered_payload_fails_verification() {
        let signer = Es256Signer::generate();
        let jwt = signer.sign(&serde_json::json!({"sub": "alice"})).await;
        let parts: Vec<&str> = jwt.split('.').collect();
        // payload を別物に差し替えると signing_input が変わり検証が落ちる。
        let forged_payload = b64url(serde_json::json!({"sub": "attacker"}).to_string());
        let vk = vk_from_jwk(&signer.public_jwk());
        let signing_input = format!("{}.{}", parts[0], forged_payload);
        let sig = Signature::from_slice(&b64d(parts[2])).unwrap();
        assert!(vk.verify(signing_input.as_bytes(), &sig).is_err());
    }

    #[test]
    fn from_scalar_b64_reconstructs_same_key() {
        let signer = Es256Signer::generate();
        let scalar = b64url(signer.key.to_bytes());
        let restored = Es256Signer::from_scalar_b64(&scalar).unwrap();
        // 同じ鍵 → 同じ kid / 公開鍵。
        assert_eq!(restored.kid, signer.kid);
        assert_eq!(restored.public_jwk(), signer.public_jwk());
    }

    #[test]
    fn from_scalar_b64_rejects_garbage() {
        assert!(Es256Signer::from_scalar_b64("!!!notb64!!!").is_err());
    }

    #[test]
    fn kid_equals_jwk_thumbprint() {
        let signer = Es256Signer::generate();
        assert_eq!(signer.kid, crate::es256::jwk_thumbprint_p256(&signer.x, &signer.y));
    }

    #[tokio::test]
    async fn rs256_sign_produces_verifiable_jws() {
        use rsa::traits::PublicKeyParts;
        use rsa::{BigUint, Pkcs1v15Sign, RsaPublicKey};
        use sha2::Digest;
        let signer = Rs256Signer::generate();
        let jwt = signer.sign(&serde_json::json!({"sub": "alice"})).await;
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: serde_json::Value = serde_json::from_slice(&b64d(parts[0])).unwrap();
        assert_eq!(header["alg"], "RS256");
        assert_eq!(header["kid"], signer.kid);
        // 公開 JWK の n,e で署名検証できる。
        let jwk = signer.public_jwk();
        let n = BigUint::from_bytes_be(&b64d(jwk["n"].as_str().unwrap()));
        let e = BigUint::from_bytes_be(&b64d(jwk["e"].as_str().unwrap()));
        let pk = RsaPublicKey::new(n, e).unwrap();
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let hashed = sha2::Sha256::digest(signing_input.as_bytes());
        assert!(pk
            .verify(Pkcs1v15Sign::new::<sha2::Sha256>(), &hashed, &b64d(parts[2]))
            .is_ok());
        // public_jwk の e は本物の指数（PublicKeyParts と一致）。
        assert_eq!(b64d(jwk["e"].as_str().unwrap()), signer.key.e().to_bytes_be());
    }
}
