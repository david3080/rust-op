//! grant_type ごとのハンドラ。node-oidc-provider の `actions/grants/*` 相当。
//! ciba を足す時はこの trait に impl を増やし Provider に登録する。

use crate::ciba::CibaStatus;
use crate::error::OAuthError;
use crate::jws::b64url;
use crate::model::{AccessToken, Client, RefreshToken, TokenResponse};
use crate::provider::Provider;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

#[async_trait]
pub trait GrantHandler: Send + Sync {
    fn grant_type(&self) -> &'static str;
    async fn handle(
        &self,
        p: &Provider,
        client: &Client,
        form: &HashMap<String, String>,
        dpop_jkt: Option<String>,
    ) -> Result<TokenResponse, OAuthError>;
}

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn opaque() -> String {
    uuid::Uuid::new_v4().simple().to_string()
}

fn has_scope(scope: &str, want: &str) -> bool {
    scope.split_whitespace().any(|s| s == want)
}

/// access token を保存し、id_token(ES256)を署名して返す。両 grant で共通。
#[allow(clippy::too_many_arguments)]
async fn issue_access_and_id(
    p: &Provider,
    client_id: &str,
    account_id: &str,
    scope: &str,
    nonce: Option<&str>,
    auth_time: Option<u64>,
    acr: Option<&str>,
    dpop_jkt: Option<String>,
    id_token_alg: Option<&str>,
) -> (String, String) {
    let access_token = opaque();
    p.store
        .save_access_token(AccessToken {
            token: access_token.clone(),
            client_id: client_id.to_string(),
            account_id: account_id.to_string(),
            scope: scope.to_string(),
            jkt: dpop_jkt,
        })
        .await;

    let iat = now();
    let mut claims = serde_json::json!({
        "iss": p.issuer,
        "sub": account_id,
        "aud": client_id,
        "iat": iat,
        "exp": iat + 3600,
        // at_hash (OIDC Core 3.1.3.6): ES256 は SHA-256 の左 128bit を base64url。
        "at_hash": at_hash(&access_token),
    });
    if let Some(n) = nonce {
        claims["nonce"] = serde_json::json!(n);
    }
    if let Some(t) = auth_time {
        claims["auth_time"] = serde_json::json!(t);
    }
    if let Some(a) = acr {
        claims["acr"] = serde_json::json!(a);
    }
    let id_token = p.signer_for(id_token_alg).sign(&claims);
    (access_token, id_token)
}

/// at_hash: access_token の ASCII を SHA-256 し、左半分(128bit=16byte)を base64url。
fn at_hash(access_token: &str) -> String {
    let digest = Sha256::digest(access_token.as_bytes());
    b64url(&digest[..16])
}

/// offline_access scope があればリフレッシュトークンを発行・保存して返す。
async fn maybe_issue_refresh(
    p: &Provider,
    client_id: &str,
    account_id: &str,
    scope: &str,
) -> Option<String> {
    if !has_scope(scope, "offline_access") {
        return None;
    }
    let token = opaque();
    p.store
        .save_refresh_token(RefreshToken {
            token: token.clone(),
            client_id: client_id.to_string(),
            account_id: account_id.to_string(),
            scope: scope.to_string(),
        })
        .await;
    Some(token)
}

pub struct AuthorizationCodeGrant;

#[async_trait]
impl GrantHandler for AuthorizationCodeGrant {
    fn grant_type(&self) -> &'static str {
        "authorization_code"
    }

    async fn handle(
        &self,
        p: &Provider,
        client: &Client,
        form: &HashMap<String, String>,
        dpop_jkt: Option<String>,
    ) -> Result<TokenResponse, OAuthError> {
        let code_val = form
            .get("code")
            .ok_or_else(|| OAuthError::InvalidRequest("code required".into()))?;
        let code = p
            .store
            .take_code(code_val)
            .await
            .ok_or_else(|| OAuthError::InvalidGrant("code not found or already used".into()))?;

        if code.client_id != client.client_id {
            return Err(OAuthError::InvalidGrant("code issued to another client".into()));
        }
        if code.expires_at < now() {
            return Err(OAuthError::InvalidGrant("authorization code expired".into()));
        }

        let redirect_uri = form
            .get("redirect_uri")
            .ok_or_else(|| OAuthError::InvalidRequest("redirect_uri required".into()))?;
        if *redirect_uri != code.redirect_uri {
            return Err(OAuthError::InvalidGrant("redirect_uri mismatch".into()));
        }

        // PKCE 検証 (S256)。
        if let Some(challenge) = &code.code_challenge {
            let verifier = form
                .get("code_verifier")
                .ok_or_else(|| OAuthError::InvalidGrant("code_verifier required".into()))?;
            let computed = b64url(Sha256::digest(verifier.as_bytes()));
            if &computed != challenge {
                return Err(OAuthError::InvalidGrant("PKCE verification failed".into()));
            }
        }

        // DPoP key binding (RFC 9449 §10): PAR/authorize で dpop_jkt 指定時は
        // token の DPoP proof の jkt と一致必須。不一致は invalid_dpop_proof。
        if let Some(want_jkt) = &code.dpop_jkt {
            match &dpop_jkt {
                Some(got) if got == want_jkt => {}
                _ => {
                    return Err(OAuthError::InvalidDpopProof(
                        "DPoP proof jkt does not match dpop_jkt bound at authorization".into(),
                    ))
                }
            }
        }

        let token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };
        let (access_token, id_token) = issue_access_and_id(
            p,
            &client.client_id,
            &code.account_id,
            &code.scope,
            code.nonce.as_deref(),
            Some(code.auth_time),
            code.acr.as_deref(),
            dpop_jkt,
            client.id_token_signed_response_alg.as_deref(),
        )
        .await;
        let refresh_token =
            maybe_issue_refresh(p, &client.client_id, &code.account_id, &code.scope).await;
        // 再利用時に失効させるため、発行トークンをコードに紐付ける。
        p.store
            .link_issued_tokens(code_val, &access_token, refresh_token.as_deref())
            .await;

        Ok(TokenResponse {
            access_token,
            token_type: token_type.into(),
            expires_in: 3600,
            scope: code.scope,
            id_token: Some(id_token),
            refresh_token,
        })
    }
}

pub struct RefreshTokenGrant;

#[async_trait]
impl GrantHandler for RefreshTokenGrant {
    fn grant_type(&self) -> &'static str {
        "refresh_token"
    }

    async fn handle(
        &self,
        p: &Provider,
        client: &Client,
        form: &HashMap<String, String>,
        dpop_jkt: Option<String>,
    ) -> Result<TokenResponse, OAuthError> {
        let rt_val = form
            .get("refresh_token")
            .ok_or_else(|| OAuthError::InvalidRequest("refresh_token required".into()))?;
        // ローテーション: 取得と同時に消費。再利用は invalid_grant。
        let rt = p
            .store
            .take_refresh_token(rt_val)
            .await
            .ok_or_else(|| OAuthError::InvalidGrant("refresh_token not found or already used".into()))?;

        if rt.client_id != client.client_id {
            return Err(OAuthError::InvalidGrant("refresh_token issued to another client".into()));
        }

        // scope の縮小は許可、拡大は拒否（RFC 6749 §6）。指定なしは元の scope を踏襲。
        let scope = match form.get("scope") {
            Some(req) => {
                let original: Vec<&str> = rt.scope.split_whitespace().collect();
                if req.split_whitespace().all(|s| original.contains(&s)) {
                    req.clone()
                } else {
                    return Err(OAuthError::InvalidScope("scope must not exceed original".into()));
                }
            }
            None => rt.scope.clone(),
        };

        let token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };
        let (access_token, id_token) =
            issue_access_and_id(p, &client.client_id, &rt.account_id, &scope, None, None, None, dpop_jkt, client.id_token_signed_response_alg.as_deref())
                .await;
        // ローテーションした新しい refresh token を再発行。
        let refresh_token =
            maybe_issue_refresh(p, &client.client_id, &rt.account_id, &scope).await;

        Ok(TokenResponse {
            access_token,
            token_type: token_type.into(),
            expires_in: 3600,
            scope,
            id_token: Some(id_token),
            refresh_token,
        })
    }
}

/// CIBA poll: auth_req_id をポーリングし、承認済みならトークンを発行する。
pub struct CibaGrant;

#[async_trait]
impl GrantHandler for CibaGrant {
    fn grant_type(&self) -> &'static str {
        "urn:openid:params:grant-type:ciba"
    }

    async fn handle(
        &self,
        p: &Provider,
        client: &Client,
        form: &HashMap<String, String>,
        dpop_jkt: Option<String>,
    ) -> Result<TokenResponse, OAuthError> {
        let auth_req_id = form
            .get("auth_req_id")
            .ok_or_else(|| OAuthError::InvalidRequest("auth_req_id required".into()))?;
        let req = p
            .ciba
            .get(auth_req_id)
            .await
            .map_err(OAuthError::ServerError)?
            .ok_or_else(|| OAuthError::InvalidGrant("unknown auth_req_id".into()))?;

        if req.client_id != client.client_id {
            return Err(OAuthError::InvalidGrant("auth_req_id issued to another client".into()));
        }
        if req.expired() {
            p.ciba.delete(auth_req_id).await.ok();
            return Err(OAuthError::ExpiredToken("auth_req_id expired".into()));
        }

        // 状態で網羅分岐（Rust の enum match）。
        match req.status {
            CibaStatus::Pending => Err(OAuthError::AuthorizationPending(
                "authorization pending".into(),
            )),
            CibaStatus::Denied => {
                p.ciba.delete(auth_req_id).await.ok();
                Err(OAuthError::AccessDenied("end-user denied the request".into()))
            }
            CibaStatus::Approved => {
                // CIBA は単回。Approved→削除を CAS で原子化し、並行 poll での二重発行を防ぐ。
                // 消費に成功した呼び出しだけがトークンを発行できる。
                let req = p
                    .ciba
                    .consume_if_approved(auth_req_id)
                    .await
                    .map_err(OAuthError::ServerError)?
                    .ok_or_else(|| OAuthError::InvalidGrant("auth_req_id already used".into()))?;
                let token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };
                let (access_token, id_token) =
                    issue_access_and_id(p, &client.client_id, &req.account, &req.scope, None, None, None, dpop_jkt, client.id_token_signed_response_alg.as_deref())
                        .await;
                Ok(TokenResponse {
                    access_token,
                    token_type: token_type.into(),
                    expires_in: 3600,
                    scope: req.scope,
                    id_token: Some(id_token),
                    refresh_token: None,
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jws::b64url;
    use crate::model::{AuthorizationCode, Client, RefreshToken};
    use crate::provider::Provider;
    use sha2::{Digest, Sha256};

    fn provider() -> Provider {
        Provider::new("https://op.example.com")
    }

    fn client(id: &str) -> Client {
        Client {
            client_id: id.into(),
            redirect_uris: vec!["https://rp/cb".into()],
            token_endpoint_auth_method: "none".into(),
            client_secret: None,
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            post_logout_redirect_uris: vec![],
            dpop_bound: false,
            jwks: vec![],
            require_par: false,
            require_pkce: false,
            id_token_signed_response_alg: None,
        }
    }

    fn base_code(code: &str, client_id: &str) -> AuthorizationCode {
        AuthorizationCode {
            code: code.into(),
            client_id: client_id.into(),
            account_id: "user@example.com".into(),
            redirect_uri: "https://rp/cb".into(),
            scope: "openid".into(),
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            auth_time: 0,
            acr: None,
            dpop_jkt: None,
            expires_at: u64::MAX,
        }
    }

    fn rt(token: &str, client_id: &str, scope: &str) -> RefreshToken {
        RefreshToken {
            token: token.into(),
            client_id: client_id.into(),
            account_id: "user@example.com".into(),
            scope: scope.into(),
        }
    }

    fn form(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[tokio::test]
    async fn auth_code_happy_path_issues_tokens() {
        let p = provider();
        let c = client("rp");
        p.store.save_code(base_code("C1", "rp")).await;
        let f = form(&[("code", "C1"), ("redirect_uri", "https://rp/cb")]);
        let r = AuthorizationCodeGrant.handle(&p, &c, &f, None).await.unwrap();
        assert!(!r.access_token.is_empty());
        assert_eq!(r.token_type, "Bearer");
        assert!(r.id_token.is_some());
        assert!(r.refresh_token.is_none()); // offline_access 無し
    }

    #[tokio::test]
    async fn auth_code_reuse_is_rejected() {
        let p = provider();
        let c = client("rp");
        p.store.save_code(base_code("C1", "rp")).await;
        let f = form(&[("code", "C1"), ("redirect_uri", "https://rp/cb")]);
        assert!(AuthorizationCodeGrant.handle(&p, &c, &f, None).await.is_ok());
        let again = AuthorizationCodeGrant.handle(&p, &c, &f, None).await;
        assert!(matches!(again, Err(OAuthError::InvalidGrant(_))));
    }

    #[tokio::test]
    async fn auth_code_issued_to_another_client_rejected() {
        let p = provider();
        p.store.save_code(base_code("C1", "rp")).await;
        let f = form(&[("code", "C1"), ("redirect_uri", "https://rp/cb")]);
        let r = AuthorizationCodeGrant.handle(&p, &client("evil"), &f, None).await;
        assert!(matches!(r, Err(OAuthError::InvalidGrant(_))));
    }

    #[tokio::test]
    async fn auth_code_redirect_uri_mismatch_rejected() {
        let p = provider();
        let c = client("rp");
        p.store.save_code(base_code("C1", "rp")).await;
        let f = form(&[("code", "C1"), ("redirect_uri", "https://evil/cb")]);
        let r = AuthorizationCodeGrant.handle(&p, &c, &f, None).await;
        assert!(matches!(r, Err(OAuthError::InvalidGrant(_))));
    }

    #[tokio::test]
    async fn auth_code_pkce_success_and_failure() {
        let verifier = "the-verifier-string-1234567890ABCdef";
        let challenge = b64url(Sha256::digest(verifier.as_bytes()));
        let p = provider();
        let c = client("rp");

        let mut code = base_code("C1", "rp");
        code.code_challenge = Some(challenge.clone());
        p.store.save_code(code).await;
        let bad = form(&[("code", "C1"), ("redirect_uri", "https://rp/cb"), ("code_verifier", "wrong")]);
        assert!(matches!(
            AuthorizationCodeGrant.handle(&p, &c, &bad, None).await,
            Err(OAuthError::InvalidGrant(_))
        ));

        let mut code2 = base_code("C1", "rp");
        code2.code_challenge = Some(challenge);
        p.store.save_code(code2).await;
        let ok = form(&[("code", "C1"), ("redirect_uri", "https://rp/cb"), ("code_verifier", verifier)]);
        assert!(AuthorizationCodeGrant.handle(&p, &c, &ok, None).await.is_ok());
    }

    #[tokio::test]
    async fn auth_code_dpop_jkt_binding_enforced() {
        let p = provider();
        let c = client("rp");
        let mut code = base_code("C1", "rp");
        code.dpop_jkt = Some("JKT-A".into());
        p.store.save_code(code).await;
        let f = form(&[("code", "C1"), ("redirect_uri", "https://rp/cb")]);
        // 束縛済み jkt と proof jkt 不一致は拒否。
        assert!(matches!(
            AuthorizationCodeGrant.handle(&p, &c, &f, Some("JKT-B".into())).await,
            Err(OAuthError::InvalidDpopProof(_))
        ));
        // 一致なら DPoP トークンを発行。
        let mut code2 = base_code("C1", "rp");
        code2.dpop_jkt = Some("JKT-A".into());
        p.store.save_code(code2).await;
        let r = AuthorizationCodeGrant.handle(&p, &c, &f, Some("JKT-A".into())).await.unwrap();
        assert_eq!(r.token_type, "DPoP");
    }

    #[tokio::test]
    async fn auth_code_offline_access_issues_refresh() {
        let p = provider();
        let c = client("rp");
        let mut code = base_code("C1", "rp");
        code.scope = "openid offline_access".into();
        p.store.save_code(code).await;
        let f = form(&[("code", "C1"), ("redirect_uri", "https://rp/cb")]);
        let r = AuthorizationCodeGrant.handle(&p, &c, &f, None).await.unwrap();
        assert!(r.refresh_token.is_some());
    }

    #[tokio::test]
    async fn refresh_rotates_and_reuse_rejected() {
        let p = provider();
        let c = client("rp");
        p.store.save_refresh_token(rt("RT1", "rp", "openid offline_access")).await;
        let f = form(&[("refresh_token", "RT1")]);
        let r = RefreshTokenGrant.handle(&p, &c, &f, None).await.unwrap();
        assert!(r.refresh_token.is_some());
        assert_ne!(r.refresh_token.as_deref(), Some("RT1")); // ローテーション
        assert!(matches!(
            RefreshTokenGrant.handle(&p, &c, &f, None).await,
            Err(OAuthError::InvalidGrant(_))
        )); // 旧 RT 再利用は拒否
    }

    #[tokio::test]
    async fn refresh_issued_to_another_client_rejected() {
        let p = provider();
        p.store.save_refresh_token(rt("RT1", "rp", "openid")).await;
        let f = form(&[("refresh_token", "RT1")]);
        assert!(matches!(
            RefreshTokenGrant.handle(&p, &client("evil"), &f, None).await,
            Err(OAuthError::InvalidGrant(_))
        ));
    }

    #[tokio::test]
    async fn refresh_scope_widening_rejected_narrowing_ok() {
        let p = provider();
        let c = client("rp");
        p.store.save_refresh_token(rt("RT1", "rp", "openid profile")).await;
        let widen = form(&[("refresh_token", "RT1"), ("scope", "openid profile email")]);
        assert!(matches!(
            RefreshTokenGrant.handle(&p, &c, &widen, None).await,
            Err(OAuthError::InvalidScope(_))
        ));
        p.store.save_refresh_token(rt("RT2", "rp", "openid profile")).await;
        let narrow = form(&[("refresh_token", "RT2"), ("scope", "openid")]);
        let r = RefreshTokenGrant.handle(&p, &c, &narrow, None).await.unwrap();
        assert_eq!(r.scope, "openid");
    }

    // ===== CIBA grant 統合テスト（MemoryCibaStore 注入）=====
    // grant ロジックが store を正しく使うことを検証する。Firestore の updateTime CAS
    // 自体の検証ではない（そこはコードレビュー担保 / MemoryCibaStore の単体テストで補強）。
    use crate::ciba::{CibaStatus, CibaStore, MemoryCibaStore};

    async fn seed_ciba(status: CibaStatus) -> (Provider, String) {
        let store = std::sync::Arc::new(MemoryCibaStore::default());
        let id = store.create("rp", "user@example.com", "openid", "msg").await.unwrap();
        if status != CibaStatus::Pending {
            store.transition_if_pending(id.as_str(), status).await.unwrap();
        }
        let p = provider().with_ciba(store);
        (p, id.0)
    }

    #[tokio::test]
    async fn ciba_pending_returns_authorization_pending() {
        let (p, id) = seed_ciba(CibaStatus::Pending).await;
        let f = form(&[("auth_req_id", &id)]);
        assert!(matches!(
            CibaGrant.handle(&p, &client("rp"), &f, None).await,
            Err(OAuthError::AuthorizationPending(_))
        ));
    }

    #[tokio::test]
    async fn ciba_denied_returns_access_denied() {
        let (p, id) = seed_ciba(CibaStatus::Denied).await;
        let f = form(&[("auth_req_id", &id)]);
        assert!(matches!(
            CibaGrant.handle(&p, &client("rp"), &f, None).await,
            Err(OAuthError::AccessDenied(_))
        ));
    }

    #[tokio::test]
    async fn ciba_unknown_and_other_client_rejected() {
        let (p, id) = seed_ciba(CibaStatus::Approved).await;
        // 未知の auth_req_id
        let unknown = form(&[("auth_req_id", "no-such-id")]);
        assert!(matches!(
            CibaGrant.handle(&p, &client("rp"), &unknown, None).await,
            Err(OAuthError::InvalidGrant(_))
        ));
        // 別クライアントが他人の auth_req_id を使う
        let f = form(&[("auth_req_id", &id)]);
        assert!(matches!(
            CibaGrant.handle(&p, &client("evil"), &f, None).await,
            Err(OAuthError::InvalidGrant(_))
        ));
    }

    #[tokio::test]
    async fn ciba_approved_issues_tokens_once_then_rejects_reuse() {
        let (p, id) = seed_ciba(CibaStatus::Approved).await;
        let f = form(&[("auth_req_id", &id)]);
        // 1 回目: トークン発行。
        let r = CibaGrant.handle(&p, &client("rp"), &f, None).await.unwrap();
        assert!(!r.access_token.is_empty());
        assert!(r.id_token.is_some());
        assert_eq!(r.scope, "openid");
        // 2 回目（並行 poll 相当の後発）: 既に単回消費済みなので拒否。二重発行しない。
        assert!(matches!(
            CibaGrant.handle(&p, &client("rp"), &f, None).await,
            Err(OAuthError::InvalidGrant(_))
        ));
    }

    #[tokio::test]
    async fn ciba_approved_with_dpop_issues_dpop_token() {
        let (p, id) = seed_ciba(CibaStatus::Approved).await;
        let f = form(&[("auth_req_id", &id)]);
        let r = CibaGrant.handle(&p, &client("rp"), &f, Some("JKT".into())).await.unwrap();
        assert_eq!(r.token_type, "DPoP");
    }
}
