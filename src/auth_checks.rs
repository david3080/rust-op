//! 認可リクエストの検証ステップ。node-oidc-provider の
//! `actions/authorization/check_*.js` を概念トレイト 1 つ + impl 群に写したもの。
//! 実行順は意味を持つので Provider 側で Vec に順序付きで登録する。

use crate::context::AuthContext;
use crate::error::OAuthError;
use crate::provider::Provider;
use async_trait::async_trait;

#[async_trait]
pub trait AuthorizationCheck: Send + Sync {
    async fn check(&self, p: &Provider, ctx: &mut AuthContext) -> Result<(), OAuthError>;
}

/// client_id を解決する。これだけは最優先（redirect 検証より前）。
pub struct CheckClient;
#[async_trait]
impl AuthorizationCheck for CheckClient {
    async fn check(&self, p: &Provider, ctx: &mut AuthContext) -> Result<(), OAuthError> {
        let id = ctx
            .params
            .client_id
            .as_deref()
            .ok_or_else(|| OAuthError::InvalidRequest("client_id required".into()))?;
        let client = p
            .resolve_client(id)
            .await
            .ok_or_else(|| OAuthError::InvalidClient(format!("unknown client {id}")))?;
        ctx.client = Some(client);
        Ok(())
    }
}

/// redirect_uri が登録値と完全一致するか（OIDC は完全一致が必須）。
pub struct CheckRedirectUri;
#[async_trait]
impl AuthorizationCheck for CheckRedirectUri {
    async fn check(&self, _p: &Provider, ctx: &mut AuthContext) -> Result<(), OAuthError> {
        let ru = ctx
            .params
            .redirect_uri
            .as_deref()
            .ok_or_else(|| OAuthError::InvalidRequest("redirect_uri required".into()))?;
        if !ctx.client().redirect_uris.iter().any(|u| u == ru) {
            return Err(OAuthError::InvalidRequest(format!(
                "redirect_uri {ru} not registered"
            )));
        }
        ctx.redirect_uri = Some(ru.to_string());
        Ok(())
    }
}

/// response_type は v0 では code のみ受理。
pub struct CheckResponseType;
#[async_trait]
impl AuthorizationCheck for CheckResponseType {
    async fn check(&self, _p: &Provider, ctx: &mut AuthContext) -> Result<(), OAuthError> {
        match ctx.params.response_type.as_deref() {
            Some("code") => Ok(()),
            Some(other) => Err(OAuthError::UnsupportedResponseType(other.into())),
            None => Err(OAuthError::InvalidRequest("response_type required".into())),
        }
    }
}

/// scope は openid を含む必要がある（OIDC リクエスト）。
pub struct CheckScope;
#[async_trait]
impl AuthorizationCheck for CheckScope {
    async fn check(&self, _p: &Provider, ctx: &mut AuthContext) -> Result<(), OAuthError> {
        let scope = ctx.params.scope.as_deref().unwrap_or("");
        if !scope.split_whitespace().any(|s| s == "openid") {
            return Err(OAuthError::InvalidScope("openid scope required".into()));
        }
        Ok(())
    }
}

/// PKCE。public client では必須、code_challenge_method は S256 のみ。
pub struct CheckPkce;
#[async_trait]
impl AuthorizationCheck for CheckPkce {
    async fn check(&self, _p: &Provider, ctx: &mut AuthContext) -> Result<(), OAuthError> {
        // public client または FAPI(require_pkce) は PKCE 必須。
        let required = ctx.client().is_public() || ctx.client().require_pkce;
        match ctx.params.code_challenge.as_deref() {
            Some(_) => {
                let method = ctx.params.code_challenge_method.as_deref().unwrap_or("plain");
                if method != "S256" {
                    return Err(OAuthError::InvalidRequest(
                        "code_challenge_method must be S256".into(),
                    ));
                }
                Ok(())
            }
            None if required => Err(OAuthError::InvalidRequest(
                "code_challenge required".into(),
            )),
            None => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AuthParams, Client};

    fn client(public: bool, require_pkce: bool) -> Client {
        Client {
            client_id: "c".into(),
            redirect_uris: vec!["https://rp/cb".into()],
            token_endpoint_auth_method: if public { "none".into() } else { "client_secret_basic".into() },
            client_secret: if public { None } else { Some("s".into()) },
            grant_types: vec!["authorization_code".into()],
            post_logout_redirect_uris: vec![],
            dpop_bound: false,
            jwks: vec![],
            require_par: false,
            require_pkce,
            id_token_signed_response_alg: None,
        }
    }

    fn params() -> AuthParams {
        AuthParams {
            client_id: Some("c".into()),
            redirect_uri: Some("https://rp/cb".into()),
            response_type: Some("code".into()),
            scope: Some("openid".into()),
            state: None,
            nonce: None,
            prompt: None,
            max_age: None,
            acr_values: None,
            response_mode: None,
            code_challenge: Some("E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM".into()),
            code_challenge_method: Some("S256".into()),
            dpop_jkt: None,
            resource: None,
        }
    }

    /// client 解決済みの ctx を作る（redirect/pkce チェックの前提）。
    fn ctx_with(p: AuthParams, c: Client) -> AuthContext {
        let mut ctx = AuthContext::new(p);
        ctx.client = Some(c);
        ctx
    }

    #[tokio::test]
    async fn check_client_resolves_and_rejects_unknown() {
        let p = Provider::new("https://op").with_client(client(true, false));
        let mut ok = AuthContext::new(params());
        assert!(CheckClient.check(&p, &mut ok).await.is_ok());
        assert!(ok.client.is_some());

        let mut bad = AuthContext::new(AuthParams { client_id: Some("zzz".into()), ..params() });
        assert!(matches!(
            CheckClient.check(&p, &mut bad).await,
            Err(OAuthError::InvalidClient(_))
        ));
    }

    #[tokio::test]
    async fn check_redirect_uri_requires_exact_registered_match() {
        let p = Provider::new("https://op");
        let mut ok = ctx_with(params(), client(true, false));
        assert!(CheckRedirectUri.check(&p, &mut ok).await.is_ok());
        assert_eq!(ok.redirect_uri.as_deref(), Some("https://rp/cb"));

        let mut bad = ctx_with(
            AuthParams { redirect_uri: Some("https://evil/cb".into()), ..params() },
            client(true, false),
        );
        assert!(CheckRedirectUri.check(&p, &mut bad).await.is_err());
    }

    #[tokio::test]
    async fn check_response_type_code_only() {
        let p = Provider::new("https://op");
        assert!(CheckResponseType.check(&p, &mut AuthContext::new(params())).await.is_ok());
        let mut tok = AuthContext::new(AuthParams { response_type: Some("token".into()), ..params() });
        assert!(matches!(
            CheckResponseType.check(&p, &mut tok).await,
            Err(OAuthError::UnsupportedResponseType(_))
        ));
        let mut none = AuthContext::new(AuthParams { response_type: None, ..params() });
        assert!(CheckResponseType.check(&p, &mut none).await.is_err());
    }

    #[tokio::test]
    async fn check_scope_requires_openid() {
        let p = Provider::new("https://op");
        assert!(CheckScope.check(&p, &mut AuthContext::new(params())).await.is_ok());
        let mut no = AuthContext::new(AuthParams { scope: Some("profile email".into()), ..params() });
        assert!(matches!(
            CheckScope.check(&p, &mut no).await,
            Err(OAuthError::InvalidScope(_))
        ));
    }

    #[tokio::test]
    async fn check_pkce_rules() {
        let p = Provider::new("https://op");
        // public + S256 challenge → OK
        assert!(CheckPkce.check(&p, &mut ctx_with(params(), client(true, false))).await.is_ok());
        // public + challenge 無し → 必須エラー
        let no_pkce = AuthParams { code_challenge: None, code_challenge_method: None, ..params() };
        assert!(CheckPkce.check(&p, &mut ctx_with(no_pkce.clone(), client(true, false))).await.is_err());
        // confidential + challenge 無し → OK（必須でない）
        assert!(CheckPkce.check(&p, &mut ctx_with(no_pkce, client(false, false))).await.is_ok());
        // challenge あり + plain method → S256 必須エラー
        let plain = AuthParams { code_challenge_method: Some("plain".into()), ..params() };
        assert!(CheckPkce.check(&p, &mut ctx_with(plain, client(false, false))).await.is_err());
    }
}
