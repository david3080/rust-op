//! token endpoint のクライアント認証方式。
//! node-oidc-provider の `shared/client_auth.js` 相当。
//! private_key_jwt / client_secret_jwt を足す時はこの trait に impl を増やす。

use crate::error::OAuthError;
use crate::model::Client;
use crate::provider::Provider;
use async_trait::async_trait;
use subtle::ConstantTimeEq;

/// client_assertion の最大有効期間（秒）。これを超える exp は拒否し、jti をこの上限まで
/// 覚えればリプレイ窓を塞げる（FAPI2 は短命な client_assertion を推奨）。request_object と同値。
const MAX_ASSERTION_LIFETIME_SECS: i64 = 3600;

/// client_secret の定数時間比較（タイミング攻撃対策）。
fn secret_eq(a: &str, b: &str) -> bool {
    a.as_bytes().ct_eq(b.as_bytes()).into()
}

/// token endpoint から渡る認証材料。
pub struct ClientAuthInput {
    /// Authorization: Basic ... をデコードした (id, secret)。
    pub basic: Option<(String, String)>,
    /// body の client_id（public client）。
    pub body_client_id: Option<String>,
    /// private_key_jwt の client_assertion(JWT)。
    pub client_assertion: Option<String>,
}

#[async_trait]
pub trait ClientAuthMethod: Send + Sync {
    fn method(&self) -> &'static str;
    async fn authenticate(&self, p: &Provider, input: &ClientAuthInput) -> Result<Client, OAuthError>;
}

/// token_endpoint_auth_method = none（public client + PKCE）。
pub struct NoneAuth;
#[async_trait]
impl ClientAuthMethod for NoneAuth {
    fn method(&self) -> &'static str {
        "none"
    }
    async fn authenticate(&self, p: &Provider, input: &ClientAuthInput) -> Result<Client, OAuthError> {
        let id = input
            .body_client_id
            .as_deref()
            .ok_or_else(|| OAuthError::InvalidClient("client_id required".into()))?;
        let client = p
            .resolve_client(id)
            .await
            .ok_or_else(|| OAuthError::InvalidClient(format!("unknown client {id}")))?;
        if !client.is_public() {
            return Err(OAuthError::InvalidClient(
                "client requires authentication".into(),
            ));
        }
        Ok(client)
    }
}

/// token_endpoint_auth_method = client_secret_basic。
pub struct ClientSecretBasic;
#[async_trait]
impl ClientAuthMethod for ClientSecretBasic {
    fn method(&self) -> &'static str {
        "client_secret_basic"
    }
    async fn authenticate(&self, p: &Provider, input: &ClientAuthInput) -> Result<Client, OAuthError> {
        let (id, secret) = input
            .basic
            .as_ref()
            .ok_or_else(|| OAuthError::InvalidClient("Basic credentials required".into()))?;
        let client = p
            .resolve_client(id)
            .await
            .ok_or_else(|| OAuthError::InvalidClient(format!("unknown client {id}")))?;
        match &client.client_secret {
            Some(s) if secret_eq(s, secret) => Ok(client),
            _ => Err(OAuthError::InvalidClient("bad client secret".into())),
        }
    }
}

/// token_endpoint_auth_method = private_key_jwt（RFC 7523, ES256）。
pub struct PrivateKeyJwt {
    jti: crate::nonce::NonceStore,
}

impl Default for PrivateKeyJwt {
    fn default() -> Self {
        Self { jti: crate::nonce::NonceStore::memory() }
    }
}

impl PrivateKeyJwt {
    /// 本番: Firestore 連携で client_assertion の jti をインスタンス跨ぎ単回化。
    pub fn with_store(fs: std::sync::Arc<crate::firestore::Firestore>) -> Self {
        Self { jti: crate::nonce::NonceStore::firestore(fs) }
    }
}

#[async_trait]
impl ClientAuthMethod for PrivateKeyJwt {
    fn method(&self) -> &'static str {
        "private_key_jwt"
    }
    async fn authenticate(&self, p: &Provider, input: &ClientAuthInput) -> Result<Client, OAuthError> {
        let bad = |m: &str| OAuthError::InvalidClient(m.to_string());
        let assertion = input
            .client_assertion
            .as_deref()
            .ok_or_else(|| bad("client_assertion required"))?;
        let parts: Vec<&str> = assertion.split('.').collect();
        if parts.len() != 3 {
            return Err(bad("client_assertion not a compact JWS"));
        }
        let dec = |s: &str| crate::es256::b64url_decode(s).map_err(|_| bad("assertion base64"));
        let header: serde_json::Value =
            serde_json::from_slice(&dec(parts[0])?).map_err(|_| bad("assertion header"))?;
        if header.get("alg").and_then(|v| v.as_str()) != Some("ES256") {
            return Err(bad("assertion alg != ES256"));
        }
        let kid = header.get("kid").and_then(|v| v.as_str()).unwrap_or("");
        let payload: serde_json::Value =
            serde_json::from_slice(&dec(parts[1])?).map_err(|_| bad("assertion payload"))?;

        // iss と sub は client_id と一致すること（RFC 7523 §3）。
        let sub = payload.get("sub").and_then(|v| v.as_str()).unwrap_or("");
        let iss = payload.get("iss").and_then(|v| v.as_str()).unwrap_or("");
        if sub.is_empty() || sub != iss {
            return Err(bad("assertion iss/sub mismatch"));
        }
        let client = p.resolve_client(sub).await.ok_or_else(|| bad("unknown client"))?;
        if client.token_endpoint_auth_method != "private_key_jwt" {
            return Err(bad("client is not private_key_jwt"));
        }

        // kid で公開鍵を選び、ES256(raw r||s) で署名検証。
        let jwk = client
            .jwks
            .iter()
            .find(|k| k.kid == kid)
            .ok_or_else(|| bad("no matching kid"))?;
        let vk = crate::es256::verifying_key_from_xy(&dec(&jwk.x)?, &dec(&jwk.y)?)
            .map_err(|e| bad(&e))?;
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig = p256::ecdsa::Signature::from_slice(&dec(parts[2])?).map_err(|_| bad("assertion sig"))?;
        use p256::ecdsa::signature::Verifier;
        vk.verify(signing_input.as_bytes(), &sig)
            .map_err(|_| bad("assertion signature invalid"))?;

        // FAPI2: aud は issuer (OP 識別子) の単一文字列でなければならない。
        // token endpoint URL や配列は拒否する（OIDF array-as-audience /
        // token-endpoint-url-as-audience の負例対応）。
        let aud_ok = matches!(
            payload.get("aud"),
            Some(serde_json::Value::String(s)) if s == &p.issuer
        );
        if !aud_ok {
            return Err(bad("assertion aud must be the issuer identifier"));
        }

        // exp 検証。
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let exp = match payload.get("exp").and_then(|v| v.as_i64()) {
            Some(exp) if exp > now => exp,
            _ => return Err(bad("assertion expired")),
        };
        // exp に上限を課す。上限が無いと、長命な assertion を jti 失効(後述)後〜exp の窓で
        // リプレイでき、また jti を exp まで覚える際の保持期間も無制限になる。
        if exp > now + MAX_ASSERTION_LIFETIME_SECS {
            return Err(bad("assertion exp is too far in the future"));
        }
        // nbf 検証: 大きく未来の nbf は拒否（FAPI2: 60 秒超の clock skew は不可）。
        if let Some(nbf) = payload.get("nbf").and_then(|v| v.as_i64()) {
            if nbf > now + 60 {
                return Err(bad("assertion nbf too far in the future"));
            }
        }

        // jti 単回（リプレイ防止）。
        let jti = payload.get("jti").and_then(|v| v.as_str()).unwrap_or("");
        if jti.is_empty() {
            return Err(bad("assertion jti missing"));
        }
        // jti を assertion の有効期間いっぱい（exp まで）覚える。固定 300s だと exp > now+300 の
        // とき、jti 失効後〜exp の窓で同一 assertion をリプレイできていた。上限は exp 検証で担保。
        let jti_ttl = std::time::Duration::from_secs((exp - now).max(0) as u64);
        if !self.jti.claim(&format!("cjwt:{jti}"), jti_ttl).await {
            return Err(bad("assertion jti replay"));
        }

        Ok(client)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::es256::b64url_encode;
    use crate::model::JwkPub;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::{Signature, SigningKey};

    const ISS: &str = "https://op.example.com";

    fn provider() -> Provider {
        Provider::new(ISS)
    }

    fn secret_client(id: &str, secret: &str, method: &str) -> Client {
        Client {
            client_id: id.into(),
            redirect_uris: vec![],
            token_endpoint_auth_method: method.into(),
            client_secret: Some(secret.into()),
            grant_types: vec![],
            post_logout_redirect_uris: vec![],
            dpop_bound: false,
            jwks: vec![],
            require_par: false,
            require_pkce: false,
            id_token_signed_response_alg: None,
        }
    }

    fn input(assertion: Option<&str>, body: Option<(&str, &str)>, basic: Option<(&str, &str)>) -> ClientAuthInput {
        ClientAuthInput {
            basic: basic.map(|(i, s)| (i.into(), s.into())),
            body_client_id: body.map(|(i, _)| i.into()),
            client_assertion: assertion.map(str::to_string),
        }
    }

    #[test]
    fn secret_eq_is_value_equality() {
        assert!(secret_eq("hunter2", "hunter2"));
        assert!(!secret_eq("hunter2", "hunter3"));
        assert!(!secret_eq("hunter2", "hunter2x")); // 長さ違い
    }

    #[tokio::test]
    async fn secret_basic_unknown_client_rejected() {
        let p = provider();
        assert!(ClientSecretBasic
            .authenticate(&p, &input(None, None, Some(("ghost", "x"))))
            .await
            .is_err());
    }

    #[tokio::test]
    async fn none_auth_rejects_confidential_client() {
        let p = provider().with_client(secret_client("rp", "s", "client_secret_basic"));
        assert!(NoneAuth
            .authenticate(&p, &input(None, Some(("rp", "")), None))
            .await
            .is_err());
    }

    fn pkjwt_client(id: &str, key: &SigningKey, kid: &str) -> Client {
        let pt = key.verifying_key().to_encoded_point(false);
        Client {
            client_id: id.into(),
            redirect_uris: vec![],
            token_endpoint_auth_method: "private_key_jwt".into(),
            client_secret: None,
            grant_types: vec![],
            post_logout_redirect_uris: vec![],
            dpop_bound: false,
            jwks: vec![JwkPub {
                kid: kid.into(),
                x: b64url_encode(pt.x().unwrap()),
                y: b64url_encode(pt.y().unwrap()),
            }],
            require_par: false,
            require_pkce: false,
            id_token_signed_response_alg: None,
        }
    }

    fn assertion(key: &SigningKey, kid: &str, alg: &str, claims: serde_json::Value) -> String {
        let header = serde_json::json!({ "alg": alg, "typ": "JWT", "kid": kid });
        let h = b64url_encode(serde_json::to_vec(&header).unwrap());
        let pl = b64url_encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{h}.{pl}");
        let sig: Signature = key.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64url_encode(sig.to_bytes()))
    }

    fn good_claims(id: &str, jti: &str) -> serde_json::Value {
        let exp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 300;
        serde_json::json!({ "iss": id, "sub": id, "aud": ISS, "exp": exp, "jti": jti })
    }

    #[tokio::test]
    async fn pkjwt_accepts_valid_assertion() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let p = provider().with_client(pkjwt_client("rp", &key, "k1"));
        let a = assertion(&key, "k1", "ES256", good_claims("rp", "j1"));
        assert!(PrivateKeyJwt::default()
            .authenticate(&p, &input(Some(&a), None, None))
            .await
            .is_ok());
    }

    #[tokio::test]
    async fn pkjwt_rejects_alg_aud_and_expiry() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let p = provider().with_client(pkjwt_client("rp", &key, "k1"));
        let auth = PrivateKeyJwt::default();
        // alg != ES256
        let none_alg = assertion(&key, "k1", "none", good_claims("rp", "ja"));
        assert!(auth.authenticate(&p, &input(Some(&none_alg), None, None)).await.is_err());
        // aud が issuer 以外
        let mut c = good_claims("rp", "jb");
        c["aud"] = serde_json::json!("https://evil");
        let wrong_aud = assertion(&key, "k1", "ES256", c);
        assert!(auth.authenticate(&p, &input(Some(&wrong_aud), None, None)).await.is_err());
        // 期限切れ
        let mut c2 = good_claims("rp", "jc");
        c2["exp"] = serde_json::json!(1000);
        let expired = assertion(&key, "k1", "ES256", c2);
        assert!(auth.authenticate(&p, &input(Some(&expired), None, None)).await.is_err());
    }

    #[tokio::test]
    async fn pkjwt_rejects_exp_too_far_in_future() {
        // exp が上限(60分)を超える assertion は拒否する（#6 回帰）。
        let key = SigningKey::random(&mut rand_core::OsRng);
        let p = provider().with_client(pkjwt_client("rp", &key, "k1"));
        let auth = PrivateKeyJwt::default();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut c = good_claims("rp", "far");
        c["exp"] = serde_json::json!(now + 7200); // 2h > 上限1h
        let far = assertion(&key, "k1", "ES256", c);
        assert!(auth.authenticate(&p, &input(Some(&far), None, None)).await.is_err());
    }

    #[tokio::test]
    async fn pkjwt_rejects_jti_replay() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let p = provider().with_client(pkjwt_client("rp", &key, "k1"));
        let auth = PrivateKeyJwt::default();
        let a1 = assertion(&key, "k1", "ES256", good_claims("rp", "dup"));
        let a2 = assertion(&key, "k1", "ES256", good_claims("rp", "dup"));
        assert!(auth.authenticate(&p, &input(Some(&a1), None, None)).await.is_ok());
        assert!(auth.authenticate(&p, &input(Some(&a2), None, None)).await.is_err());
    }

    #[tokio::test]
    async fn pkjwt_rejects_iss_sub_mismatch_and_bad_signature() {
        let key = SigningKey::random(&mut rand_core::OsRng);
        let other = SigningKey::random(&mut rand_core::OsRng);
        let p = provider().with_client(pkjwt_client("rp", &key, "k1"));
        let auth = PrivateKeyJwt::default();
        // iss != sub
        let mut c = good_claims("rp", "je");
        c["iss"] = serde_json::json!("other");
        let mismatch = assertion(&key, "k1", "ES256", c);
        assert!(auth.authenticate(&p, &input(Some(&mismatch), None, None)).await.is_err());
        // 別鍵署名（署名検証で落ちる）
        let bad_sig = assertion(&other, "k1", "ES256", good_claims("rp", "jf"));
        assert!(auth.authenticate(&p, &input(Some(&bad_sig), None, None)).await.is_err());
    }
}
