//! 認可リクエストの検証。node-oidc-provider の `actions/authorization/check_*.js` 由来。
//!
//! 2 フェーズ構成（typestate、context.rs 参照）:
//!   - `resolve_addressee`: CheckClient + CheckRedirectUri を融合した Phase 0→1 遷移。
//!     順序が安全性に効くのはこの境界だけなので、ここだけを型で固定する。
//!   - `AuthorizationCheck`: Phase 1 のポリシーチェック群。相互に可換（順序自由）で、
//!     `&AddressedRequest` を読むだけ。新しいチェックはこの trait に impl を増やす。

use crate::context::{AddressedRequest, RawAuthRequest};
use crate::error::OAuthError;
use crate::provider::Provider;
use async_trait::async_trait;

/// requested が登録値のいずれかと **バイト完全一致** するか。正規化・前方一致は一切しない
/// （open redirect を生む正規化の抜け道が無いことを Kani で固定する純粋述語）。
pub(crate) fn redirect_uri_registered(requested: &str, registered: &[String]) -> bool {
    registered.iter().any(|u| u == requested)
}

/// Phase 0 → Phase 1 遷移: client を解決し、redirect_uri が登録値と完全一致することを
/// 検証して `AddressedRequest` を発行する。`raw` を move で消費するため、検証前の
/// コンテキストで後段の処理を呼ぶコードはコンパイルできない。
/// ここで返るエラーを redirect で返してはならない（呼び出し側は plain 表示のみ）。
pub async fn resolve_addressee(
    p: &Provider,
    raw: RawAuthRequest,
) -> Result<AddressedRequest, OAuthError> {
    let id = raw
        .params
        .client_id
        .as_deref()
        .ok_or_else(|| OAuthError::InvalidRequest("client_id required".into()))?;
    let client = p
        .resolve_client(id)
        .await
        .ok_or_else(|| OAuthError::InvalidClient(format!("unknown client {id}")))?;

    let ru = raw
        .params
        .redirect_uri
        .as_deref()
        .ok_or_else(|| OAuthError::InvalidRequest("redirect_uri required".into()))?;
    if !redirect_uri_registered(ru, &client.redirect_uris) {
        return Err(OAuthError::InvalidRequest(format!(
            "redirect_uri {ru} not registered"
        )));
    }
    let redirect_uri = ru.to_string();
    Ok(AddressedRequest {
        params: raw.params,
        client,
        redirect_uri,
        request_uri: raw.request_uri,
    })
}

/// Phase 1 のポリシーチェック。読み取り専用・可換。
#[async_trait]
pub trait AuthorizationCheck: Send + Sync {
    async fn check(&self, p: &Provider, req: &AddressedRequest) -> Result<(), OAuthError>;
}

/// response_type は v0 では code のみ受理。
pub struct CheckResponseType;
#[async_trait]
impl AuthorizationCheck for CheckResponseType {
    async fn check(&self, _p: &Provider, req: &AddressedRequest) -> Result<(), OAuthError> {
        match req.params.response_type.as_deref() {
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
    async fn check(&self, _p: &Provider, req: &AddressedRequest) -> Result<(), OAuthError> {
        let scope = req.params.scope.as_deref().unwrap_or("");
        if !scope.split_whitespace().any(|s| s == "openid") {
            return Err(OAuthError::InvalidScope("openid scope required".into()));
        }
        Ok(())
    }
}

/// code_challenge_method が S256 として受理されるか。method 省略時の既定は plain で、これは拒否。
/// `plain` への暗黙フォールバックでダウングレードできないことを Kani で固定する純粋述語。
pub(crate) fn pkce_method_is_s256(method: Option<&str>) -> bool {
    method.unwrap_or("plain") == "S256"
}

/// PKCE。public client では必須、code_challenge_method は S256 のみ。
pub struct CheckPkce;
#[async_trait]
impl AuthorizationCheck for CheckPkce {
    async fn check(&self, _p: &Provider, req: &AddressedRequest) -> Result<(), OAuthError> {
        // public client または FAPI(require_pkce) は PKCE 必須。
        let required = req.client.is_public() || req.client.require_pkce;
        match req.params.code_challenge.as_deref() {
            Some(_) => {
                if !pkce_method_is_s256(req.params.code_challenge_method.as_deref()) {
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
            jwks_uri: None,
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

    fn raw(p: AuthParams) -> RawAuthRequest {
        RawAuthRequest { params: p, request_uri: None }
    }

    /// Phase 1 通過済みのリクエストを直接組み立てる（ポリシーチェックのテスト用）。
    fn addressed(p: AuthParams, c: Client) -> AddressedRequest {
        AddressedRequest {
            redirect_uri: "https://rp/cb".into(),
            params: p,
            client: c,
            request_uri: None,
        }
    }

    #[tokio::test]
    async fn resolve_addressee_resolves_and_rejects_unknown_client() {
        let p = Provider::new("https://op").with_client(client(true, false));
        let ok = resolve_addressee(&p, raw(params())).await;
        assert!(ok.is_ok());
        assert_eq!(ok.unwrap().redirect_uri, "https://rp/cb");

        let bad = resolve_addressee(
            &p,
            raw(AuthParams { client_id: Some("zzz".into()), ..params() }),
        )
        .await;
        assert!(matches!(bad, Err(OAuthError::InvalidClient(_))));
    }

    #[tokio::test]
    async fn resolve_addressee_requires_exact_registered_redirect() {
        let p = Provider::new("https://op").with_client(client(true, false));
        let bad = resolve_addressee(
            &p,
            raw(AuthParams { redirect_uri: Some("https://evil/cb".into()), ..params() }),
        )
        .await;
        assert!(bad.is_err());

        let none = resolve_addressee(
            &p,
            raw(AuthParams { redirect_uri: None, ..params() }),
        )
        .await;
        assert!(matches!(none, Err(OAuthError::InvalidRequest(_))));
    }

    #[tokio::test]
    async fn check_response_type_code_only() {
        let p = Provider::new("https://op");
        let ok = addressed(params(), client(true, false));
        assert!(CheckResponseType.check(&p, &ok).await.is_ok());
        let tok = addressed(AuthParams { response_type: Some("token".into()), ..params() }, client(true, false));
        assert!(matches!(
            CheckResponseType.check(&p, &tok).await,
            Err(OAuthError::UnsupportedResponseType(_))
        ));
        let none = addressed(AuthParams { response_type: None, ..params() }, client(true, false));
        assert!(CheckResponseType.check(&p, &none).await.is_err());
    }

    #[tokio::test]
    async fn check_scope_requires_openid() {
        let p = Provider::new("https://op");
        assert!(CheckScope.check(&p, &addressed(params(), client(true, false))).await.is_ok());
        let no = addressed(AuthParams { scope: Some("profile email".into()), ..params() }, client(true, false));
        assert!(matches!(
            CheckScope.check(&p, &no).await,
            Err(OAuthError::InvalidScope(_))
        ));
    }

    #[tokio::test]
    async fn check_pkce_rules() {
        let p = Provider::new("https://op");
        // public + S256 challenge → OK
        assert!(CheckPkce.check(&p, &addressed(params(), client(true, false))).await.is_ok());
        // public + challenge 無し → 必須エラー
        let no_pkce = AuthParams { code_challenge: None, code_challenge_method: None, ..params() };
        assert!(CheckPkce.check(&p, &addressed(no_pkce.clone(), client(true, false))).await.is_err());
        // confidential + challenge 無し → OK（必須でない）
        assert!(CheckPkce.check(&p, &addressed(no_pkce, client(false, false))).await.is_ok());
        // challenge あり + plain method → S256 必須エラー
        let plain = AuthParams { code_challenge_method: Some("plain".into()), ..params() };
        assert!(CheckPkce.check(&p, &addressed(plain, client(false, false))).await.is_err());
    }
}
