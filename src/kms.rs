//! Cloud KMS による JWS 署名（非対称署名鍵、ソフトウェア保護）。
//! 秘密鍵がプロセスに展開されない（侵害ホストから抜けない）。alg は ES256 / RS256。
//! 公開鍵は起動時に 1 回取得して JWK 化・キャッシュ（/jwks は KMS を叩かない）。

use crate::firestore::Firestore;
use crate::jws::{b64url, JwsSigner};
use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use sha2::Digest;
use std::sync::Arc;

#[derive(Clone, Copy)]
enum KmsKind {
    Es256,
    Rs256,
}

pub struct KmsSigner {
    kind: KmsKind,
    fs: Arc<Firestore>, // metadata server のアクセストークン取得に使う
    http: reqwest::Client,
    version: String, // cryptoKeyVersion のフル resource path
    kid: String,
    jwk: serde_json::Value,
}

impl KmsSigner {
    pub async fn es256(fs: Arc<Firestore>, key_path: &str) -> Result<Self, String> {
        Self::new(KmsKind::Es256, fs, key_path).await
    }
    pub async fn rs256(fs: Arc<Firestore>, key_path: &str) -> Result<Self, String> {
        Self::new(KmsKind::Rs256, fs, key_path).await
    }

    async fn new(kind: KmsKind, fs: Arc<Firestore>, key_path: &str) -> Result<Self, String> {
        let version = format!("{}/cryptoKeyVersions/1", key_path.trim_end_matches('/'));
        let http = reqwest::Client::new();
        // 公開鍵 PEM を取得し JWK / kid を作る（既存 jws.rs と同じ kid スキーム）。
        let tok = fs.token().await?;
        let url = format!("https://cloudkms.googleapis.com/v1/{version}/publicKey");
        let resp = http
            .get(&url)
            .bearer_auth(&tok)
            .send()
            .await
            .map_err(|e| format!("kms publicKey: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!(
                "kms publicKey {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            ));
        }
        let j: serde_json::Value = resp.json().await.map_err(|e| format!("kms publicKey json: {e}"))?;
        let pem = j.get("pem").and_then(|v| v.as_str()).ok_or("kms publicKey: no pem")?;
        let (jwk, kid) = match kind {
            KmsKind::Es256 => {
                use p256::elliptic_curve::sec1::ToEncodedPoint;
                use p256::pkcs8::DecodePublicKey;
                let pk = p256::PublicKey::from_public_key_pem(pem)
                    .map_err(|e| format!("es256 spki: {e}"))?;
                let pt = pk.to_encoded_point(false);
                let x = b64url(pt.x().ok_or("no x")?);
                let y = b64url(pt.y().ok_or("no y")?);
                let kid = crate::es256::jwk_thumbprint_p256(&x, &y);
                let jwk = serde_json::json!({
                    "kty":"EC","crv":"P-256","x":x,"y":y,"alg":"ES256","use":"sig","kid":kid
                });
                (jwk, kid)
            }
            KmsKind::Rs256 => {
                use rsa::pkcs8::DecodePublicKey;
                use rsa::traits::PublicKeyParts;
                let pk = rsa::RsaPublicKey::from_public_key_pem(pem)
                    .map_err(|e| format!("rs256 spki: {e}"))?;
                let n = b64url(pk.n().to_bytes_be());
                let e = b64url(pk.e().to_bytes_be());
                let canonical = format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#);
                let kid = b64url(sha2::Sha256::digest(canonical.as_bytes()));
                let jwk = serde_json::json!({
                    "kty":"RSA","n":n,"e":e,"alg":"RS256","use":"sig","kid":kid
                });
                (jwk, kid)
            }
        };
        Ok(Self { kind, fs, http, version, kid, jwk })
    }

    /// digest(SHA-256) を KMS で署名し、JOSE 形式の署名(b64url)を返す。
    async fn kms_sign(&self, digest: &[u8]) -> Result<String, String> {
        let tok = self.fs.token().await?;
        let url = format!("https://cloudkms.googleapis.com/v1/{}:asymmetricSign", self.version);
        let body = serde_json::json!({ "digest": { "sha256": B64.encode(digest) } });
        let resp = self
            .http
            .post(&url)
            .bearer_auth(&tok)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("kms sign: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!(
                "kms sign {} {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            ));
        }
        let j: serde_json::Value = resp.json().await.map_err(|e| format!("kms sign json: {e}"))?;
        let sig_b64 = j.get("signature").and_then(|v| v.as_str()).ok_or("kms sign: no signature")?;
        let sig = B64.decode(sig_b64).map_err(|e| format!("kms sig b64: {e}"))?;
        let raw = match self.kind {
            // KMS は ES256 を DER で返す。JWS は raw r||s なので変換する。
            KmsKind::Es256 => p256::ecdsa::Signature::from_der(&sig)
                .map_err(|e| format!("es256 der: {e}"))?
                .to_bytes()
                .to_vec(),
            // RS256(PKCS1v15) は raw 署名そのまま。
            KmsKind::Rs256 => sig,
        };
        Ok(b64url(raw))
    }
}

#[async_trait]
impl JwsSigner for KmsSigner {
    fn alg(&self) -> &str {
        match self.kind {
            KmsKind::Es256 => "ES256",
            KmsKind::Rs256 => "RS256",
        }
    }

    async fn sign(&self, claims: &serde_json::Value) -> String {
        let header = serde_json::json!({ "alg": self.alg(), "typ": "JWT", "kid": self.kid });
        let signing_input = format!("{}.{}", b64url(header.to_string()), b64url(claims.to_string()));
        let digest = sha2::Sha256::digest(signing_input.as_bytes());
        match self.kms_sign(&digest).await {
            Ok(sig) => format!("{signing_input}.{sig}"),
            Err(e) => {
                // 署名不能は致命的。誤った署名で発行するより、検証で確実に落ちる空署名にする。
                tracing::error!(event = "kms_sign_failed", "{e}");
                format!("{signing_input}.")
            }
        }
    }

    fn public_jwk(&self) -> serde_json::Value {
        self.jwk.clone()
    }
}
