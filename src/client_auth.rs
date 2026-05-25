//! token endpoint のクライアント認証方式。
//! node-oidc-provider の `shared/client_auth.js` 相当。
//! private_key_jwt / client_secret_jwt を足す時はこの trait に impl を増やす。

use crate::error::OAuthError;
use crate::model::Client;
use crate::provider::Provider;
use async_trait::async_trait;

/// token endpoint から渡る認証材料。
pub struct ClientAuthInput {
    /// Authorization: Basic ... をデコードした (id, secret)。
    pub basic: Option<(String, String)>,
    /// body の client_id（public client / client_secret_post）。
    pub body_client_id: Option<String>,
    /// body の client_secret（client_secret_post）。
    pub body_client_secret: Option<String>,
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
            .clients
            .get(id)
            .cloned()
            .ok_or_else(|| OAuthError::InvalidClient(format!("unknown client {id}")))?;
        if !client.is_public() {
            return Err(OAuthError::InvalidClient(
                "client requires authentication".into(),
            ));
        }
        Ok(client)
    }
}

/// token_endpoint_auth_method = client_secret_post（client_id/secret を body で送る）。
pub struct ClientSecretPost;
#[async_trait]
impl ClientAuthMethod for ClientSecretPost {
    fn method(&self) -> &'static str {
        "client_secret_post"
    }
    async fn authenticate(&self, p: &Provider, input: &ClientAuthInput) -> Result<Client, OAuthError> {
        let id = input
            .body_client_id
            .as_deref()
            .ok_or_else(|| OAuthError::InvalidClient("client_id required".into()))?;
        let secret = input
            .body_client_secret
            .as_deref()
            .ok_or_else(|| OAuthError::InvalidClient("client_secret required".into()))?;
        let client = p
            .clients
            .get(id)
            .cloned()
            .ok_or_else(|| OAuthError::InvalidClient(format!("unknown client {id}")))?;
        match &client.client_secret {
            Some(s) if s == secret => Ok(client),
            _ => Err(OAuthError::InvalidClient("bad client secret".into())),
        }
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
            .clients
            .get(id)
            .cloned()
            .ok_or_else(|| OAuthError::InvalidClient(format!("unknown client {id}")))?;
        match &client.client_secret {
            Some(s) if s == secret => Ok(client),
            _ => Err(OAuthError::InvalidClient("bad client secret".into())),
        }
    }
}

/// token_endpoint_auth_method = private_key_jwt（RFC 7523, ES256）。
pub struct PrivateKeyJwt {
    seen_jti: std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
}

impl Default for PrivateKeyJwt {
    fn default() -> Self {
        Self { seen_jti: std::sync::Mutex::new(std::collections::HashMap::new()) }
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
        let client = p.clients.get(sub).cloned().ok_or_else(|| bad("unknown client"))?;
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
        match payload.get("exp").and_then(|v| v.as_i64()) {
            Some(exp) if exp > now => {}
            _ => return Err(bad("assertion expired")),
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
        {
            let mut seen = self.seen_jti.lock().unwrap();
            let inst = std::time::Instant::now();
            seen.retain(|_, exp| *exp > inst);
            if seen.contains_key(jti) {
                return Err(bad("assertion jti replay"));
            }
            seen.insert(jti.to_string(), inst + std::time::Duration::from_secs(300));
        }

        Ok(client)
    }
}
