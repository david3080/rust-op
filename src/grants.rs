//! grant_type ごとのハンドラ。node-oidc-provider の `actions/grants/*` 相当。
//! ciba を足す時はこの trait に impl を増やし Provider に登録する。

use crate::ciba::{self, CibaStatus};
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
    let id_token = p.signer.sign(&claims);
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
        )
        .await;
        let refresh_token =
            maybe_issue_refresh(p, &client.client_id, &code.account_id, &code.scope).await;

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
            issue_access_and_id(p, &client.client_id, &rt.account_id, &scope, None, None, None, dpop_jkt)
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
        let fs = p
            .firestore
            .as_ref()
            .ok_or_else(|| OAuthError::ServerError("CIBA requires Firestore".into()))?;
        let auth_req_id = form
            .get("auth_req_id")
            .ok_or_else(|| OAuthError::InvalidRequest("auth_req_id required".into()))?;
        let req = ciba::get(fs, auth_req_id)
            .await
            .map_err(OAuthError::ServerError)?
            .ok_or_else(|| OAuthError::InvalidGrant("unknown auth_req_id".into()))?;

        if req.client_id != client.client_id {
            return Err(OAuthError::InvalidGrant("auth_req_id issued to another client".into()));
        }
        if req.expired() {
            ciba::delete(fs, auth_req_id).await.ok();
            return Err(OAuthError::ExpiredToken("auth_req_id expired".into()));
        }

        // 状態で網羅分岐（Rust の enum match）。
        match req.status {
            CibaStatus::Pending => Err(OAuthError::AuthorizationPending(
                "authorization pending".into(),
            )),
            CibaStatus::Denied => {
                ciba::delete(fs, auth_req_id).await.ok();
                Err(OAuthError::AccessDenied("end-user denied the request".into()))
            }
            CibaStatus::Approved => {
                let token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };
                let (access_token, id_token) =
                    issue_access_and_id(p, &client.client_id, &req.account, &req.scope, None, None, None, dpop_jkt)
                        .await;
                // CIBA は単回。発行後に消費する。
                ciba::delete(fs, auth_req_id).await.ok();
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
