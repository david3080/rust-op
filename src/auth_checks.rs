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
            .clients
            .get(id)
            .cloned()
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
