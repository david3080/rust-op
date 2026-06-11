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
    resource: Option<&str>,
    authorization_details: Option<&str>,
) -> (String, String) {
    let access_token = opaque();
    p.store
        .save_access_token(AccessToken {
            token: access_token.clone(),
            client_id: client_id.to_string(),
            account_id: account_id.to_string(),
            scope: scope.to_string(),
            jkt: dpop_jkt,
            aud: resource.map(str::to_string),
            acr: acr.map(str::to_string),
            auth_time,
            authorization_details: authorization_details.map(str::to_string),
            mandate_consumed: false,
        })
        .await;
    // 監査イベント（Cloud Logging metric/alert 用）。sub は擬似化して平文 PII をログに残さない。
    tracing::info!(event = "token_issued", client_id = %client_id, sub = %crate::web::pseudonymize_sub(account_id), scope = %scope);

    let iat = now();
    let mut claims = serde_json::json!({
        "iss": p.issuer,
        "sub": account_id,
        "aud": client_id,
        "iat": iat,
        "exp": iat + 900,
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
    let id_token = p.signer_for(id_token_alg).sign(&claims).await;
    (access_token, id_token)
}

/// at_hash: access_token の ASCII を SHA-256 し、左半分(128bit=16byte)を base64url。
fn at_hash(access_token: &str) -> String {
    let digest = Sha256::digest(access_token.as_bytes());
    b64url(&digest[..16])
}

/// offline_access scope があればリフレッシュトークンを発行・保存して返す（新規 family を採番）。
/// authorize/CIBA からの初回発行に使う（ローテーションは handle 側で直接行う）。
#[allow(clippy::too_many_arguments)]
async fn maybe_issue_refresh(
    p: &Provider,
    client_id: &str,
    account_id: &str,
    scope: &str,
    resource: Option<&str>,
    acr: Option<&str>,
    auth_time: Option<u64>,
    jkt: Option<&str>,
    is_public: bool,
) -> Option<String> {
    if !has_scope(scope, "offline_access") {
        return None;
    }
    // B-5: public client は DPoP 束縛(jkt)が無い限り refresh を発行しない。発行してしまうと
    // client 認証も鍵束縛も無い bearer 長命資格情報になり、#41 で refresh 時に拒否する対象を
    // そもそも作らない（発行時点で塞ぐ）。
    if jkt.is_none() && is_public {
        return None;
    }
    let token = opaque();
    p.store
        .save_refresh_token(RefreshToken {
            token: token.clone(),
            client_id: client_id.to_string(),
            account_id: account_id.to_string(),
            scope: scope.to_string(),
            resource: resource.map(str::to_string),
            jkt: jkt.map(str::to_string),
            acr: acr.map(str::to_string),
            auth_time,
            family_id: opaque(),
            used: false,
            replaced_by: None,
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
            dpop_jkt.clone(),
            client.id_token_signed_response_alg.as_deref(),
            code.resource.as_deref(),
            None,
        )
        .await;
        // RFC 9449 §5: DPoP proof を伴う発行では refresh token も同じ鍵に束縛する。
        let refresh_token = maybe_issue_refresh(
            p,
            &client.client_id,
            &code.account_id,
            &code.scope,
            code.resource.as_deref(),
            code.acr.as_deref(),
            Some(code.auth_time),
            dpop_jkt.as_deref(),
            client.is_public(),
        )
        .await;
        // 再利用時に失効させるため、発行トークンをコードに紐付ける。
        p.store
            .link_issued_tokens(code_val, &access_token, refresh_token.as_deref())
            .await;

        Ok(TokenResponse {
            access_token,
            token_type: token_type.into(),
            expires_in: 900,
            scope: code.scope,
            id_token: Some(id_token),
            refresh_token,
            authorization_details: None,
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

        // 消費前に所有者と DPoP 束縛を検証する。検証失敗で被害者の RT をローテーション消費
        // （=失効）させないため、まず get で参照して通過したものだけ take で単回消費する。
        let pre = p
            .store
            .get_refresh_token(rt_val)
            .await
            .ok_or_else(|| OAuthError::InvalidGrant("refresh_token not found or already used".into()))?;

        if pre.client_id != client.client_id {
            return Err(OAuthError::InvalidGrant("refresh_token issued to another client".into()));
        }

        // DPoP 束縛 (RFC 9449 §5): 発行時に鍵束縛された RT は、提示 proof の jkt が一致必須。
        // 盗難 RT を攻撃者の鍵へ付け替える攻撃を防ぐ。束縛なしの RT は public client では拒否
        // （client 認証が無く、束縛も無ければ bearer 長命資格情報になってしまうため）。
        match (&pre.jkt, &dpop_jkt) {
            (Some(bound), Some(got)) if bound == got => {}
            (Some(_), _) => {
                return Err(OAuthError::InvalidDpopProof(
                    "DPoP proof jkt does not match the key bound to this refresh token".into(),
                ))
            }
            (None, _) if client.is_public() => {
                return Err(OAuthError::InvalidGrant(
                    "refresh token for a public client must be DPoP-bound".into(),
                ))
            }
            (None, _) => {}
        }

        // B-4 再利用検知（OAuth Security BCP）: 消費済み(used)の RT が再提示されたら盗難
        // （系列の分岐）とみなし、系列全体を失効してアラートする。delete でなく used マークで
        // 残しているからこそ検知できる（盗難者・正規ユーザ双方が再認証を強いられる）。
        if pre.used {
            tracing::warn!(
                event = "refresh_reuse_detected",
                client_id = %client.client_id,
                family = %pre.family_id,
                sub = %crate::web::pseudonymize_sub(&pre.account_id)
            );
            p.store.revoke_refresh_family(rt_val).await;
            return Err(OAuthError::InvalidGrant(
                "refresh token reuse detected; token family revoked".into(),
            ));
        }

        // scope の縮小は許可、拡大は拒否（RFC 6749 §6）。指定なしは元の scope を踏襲。
        let scope = match form.get("scope") {
            Some(req) => {
                let original: Vec<&str> = pre.scope.split_whitespace().collect();
                if req.split_whitespace().all(|s| original.contains(&s)) {
                    req.clone()
                } else {
                    return Err(OAuthError::InvalidScope("scope must not exceed original".into()));
                }
            }
            None => pre.scope.clone(),
        };

        // ローテーション: 新 RT を先に採番（offline_access がある時）し、old を used=true に
        // CAS。CAS 敗北（並行/競合）は invalid_grant。delete ではなく used マーク + replaced_by
        // 連結なので、後で old が再提示されたら再利用検知できる。
        let new_refresh = has_scope(&scope, "offline_access").then(opaque);
        if !p.store.mark_refresh_used(rt_val, new_refresh.as_deref()).await {
            return Err(OAuthError::InvalidGrant("refresh_token not found or already used".into()));
        }

        let token_type = if dpop_jkt.is_some() { "DPoP" } else { "Bearer" };
        // 認証コンテキスト(acr/auth_time)は再認証しないので元の RT から引き継ぐ。
        let (access_token, id_token) =
            issue_access_and_id(p, &client.client_id, &pre.account_id, &scope, None, pre.auth_time, pre.acr.as_deref(), dpop_jkt, client.id_token_signed_response_alg.as_deref(), pre.resource.as_deref(), None)
                .await;
        // 新 RT を保存。aud(resource)/acr/auth_time/DPoP 束縛(jkt) と family_id を継承
        // （系列は chain 全体で 1 つ。再利用検知時にまとめて失効する）。
        if let Some(new_token) = &new_refresh {
            p.store
                .save_refresh_token(RefreshToken {
                    token: new_token.clone(),
                    client_id: client.client_id.clone(),
                    account_id: pre.account_id.clone(),
                    scope: scope.clone(),
                    resource: pre.resource.clone(),
                    jkt: pre.jkt.clone(),
                    acr: pre.acr.clone(),
                    auth_time: pre.auth_time,
                    family_id: pre.family_id.clone(),
                    used: false,
                    replaced_by: None,
                })
                .await;
        }
        let refresh_token = new_refresh;

        Ok(TokenResponse {
            access_token,
            token_type: token_type.into(),
            expires_in: 900,
            scope,
            id_token: Some(id_token),
            refresh_token,
            authorization_details: None,
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
                    issue_access_and_id(p, &client.client_id, &req.account, &req.scope, None, None, None, dpop_jkt, client.id_token_signed_response_alg.as_deref(), None, req.authorization_details.as_deref())
                        .await;
                // 承認時の authorization_details を JSON 配列としてレスポンスへ載せる（RFC 9396）。
                let ad_value = req
                    .authorization_details
                    .as_deref()
                    .and_then(|s| serde_json::from_str::<serde_json::Value>(s).ok());
                Ok(TokenResponse {
                    access_token,
                    token_type: token_type.into(),
                    expires_in: 900,
                    scope: req.scope,
                    id_token: Some(id_token),
                    refresh_token: None,
                    authorization_details: ad_value,
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
            resource: None,
            expires_at: u64::MAX,
        }
    }

    fn rt(token: &str, client_id: &str, scope: &str) -> RefreshToken {
        RefreshToken {
            token: token.into(),
            client_id: client_id.into(),
            account_id: "user@example.com".into(),
            scope: scope.into(),
            resource: None,
            jkt: None,
            acr: None,
            auth_time: None,
            family_id: "fam-test".into(),
            used: false,
            replaced_by: None,
        }
    }

    /// DPoP 鍵に束縛された refresh token（public client の通常経路）。
    fn rt_bound(token: &str, client_id: &str, scope: &str, jkt: &str) -> RefreshToken {
        RefreshToken { jkt: Some(jkt.into()), ..rt(token, client_id, scope) }
    }

    /// client_secret_basic の confidential client（client 認証が防壁。DPoP 束縛は任意）。
    fn confidential_client(id: &str) -> Client {
        Client {
            token_endpoint_auth_method: "client_secret_basic".into(),
            client_secret: Some("s3cret".into()),
            ..client(id)
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

    // 回帰: 盗んだ refresh token を攻撃者の DPoP 鍵に付け替える攻撃が拒否される（RFC 9449 §5）。
    // 元は PoC（攻撃成立）として書いた。jkt 束縛照合の追加により InvalidDpopProof で弾かれる。
    #[tokio::test]
    async fn regression_stolen_refresh_token_cannot_rebind_to_attacker_key() {
        let p = provider();
        // 本番 mobile-rp / demo-rp と同じ: public(none) かつ dpop_bound=true。
        let mut c = client("mobile-rp");
        c.dpop_bound = true;

        // 被害者の RT は発行時に被害者の鍵へ束縛済み（mobile-rp は dpop_bound ゆえ常に束縛）。
        p.store
            .save_refresh_token(rt_bound("STOLEN_RT", "mobile-rp", "openid offline_access", "VICTIM-KEY"))
            .await;

        // 攻撃者は自分の鍵の proof を提示（token endpoint が検証して注入する jkt は攻撃者鍵）。
        let r = RefreshTokenGrant
            .handle(&p, &c, &form(&[("refresh_token", "STOLEN_RT")]), Some("ATTACKER-KEY".into()))
            .await;
        assert!(
            matches!(r, Err(OAuthError::InvalidDpopProof(_))),
            "別鍵への付け替えは拒否されるべき"
        );
        // 被害者の RT は消費されていない（DoS 防止）。正規の鍵でなら依然使える。
        assert!(p.store.get_refresh_token("STOLEN_RT").await.is_some());
    }

    // 正規経路: 一致する鍵なら成功し、ローテーション後の RT も同じ鍵束縛を引き継ぐ。
    #[tokio::test]
    async fn refresh_with_matching_dpop_key_succeeds_and_keeps_binding() {
        let p = provider();
        let mut c = client("mobile-rp");
        c.dpop_bound = true;
        p.store
            .save_refresh_token(rt_bound("RT1", "mobile-rp", "openid offline_access", "KEY-A"))
            .await;
        let r = RefreshTokenGrant
            .handle(&p, &c, &form(&[("refresh_token", "RT1")]), Some("KEY-A".into()))
            .await
            .unwrap();
        assert_eq!(r.token_type, "DPoP");
        // 発行された access token が同じ鍵に cnf.jkt 束縛されている。
        let at = p.store.get_access_token(&r.access_token).await.unwrap();
        assert_eq!(at.jkt.as_deref(), Some("KEY-A"));
        // ローテーションした新 RT も KEY-A 束縛を引き継ぐ。
        let new_rt = r.refresh_token.unwrap();
        assert_eq!(p.store.get_refresh_token(&new_rt).await.unwrap().jkt.as_deref(), Some("KEY-A"));
    }

    // public client の束縛なし RT は拒否（client 認証が無く bearer 長命資格情報になるため）。
    #[tokio::test]
    async fn refresh_unbound_for_public_client_rejected() {
        let p = provider();
        let c = client("mobile-rp"); // public(none)
        p.store.save_refresh_token(rt("RT1", "mobile-rp", "openid offline_access")).await;
        let r = RefreshTokenGrant
            .handle(&p, &c, &form(&[("refresh_token", "RT1")]), None)
            .await;
        assert!(matches!(r, Err(OAuthError::InvalidGrant(_))));
    }

    // confidential client は束縛なし RT でも client 認証が防壁になるため許可（標準 Bearer）。
    #[tokio::test]
    async fn refresh_unbound_for_confidential_client_allowed() {
        let p = provider();
        let c = confidential_client("conf-rp");
        p.store.save_refresh_token(rt("RT1", "conf-rp", "openid offline_access")).await;
        let r = RefreshTokenGrant
            .handle(&p, &c, &form(&[("refresh_token", "RT1")]), None)
            .await
            .unwrap();
        assert_eq!(r.token_type, "Bearer");
    }

    // 対照: authorization_code 経路は元から jkt 照合あり（refresh も同等になったことの確認）。
    #[tokio::test]
    async fn contrast_auth_code_rejects_mismatched_dpop_jkt() {
        let p = provider();
        let c = client("mobile-rp");
        let mut code = base_code("C1", "mobile-rp");
        code.dpop_jkt = Some("VICTIM-KEY-THUMBPRINT".into());
        p.store.save_code(code).await;
        let f = form(&[("code", "C1"), ("redirect_uri", "https://rp/cb")]);
        let r = AuthorizationCodeGrant
            .handle(&p, &c, &f, Some("ATTACKER-KEY-THUMBPRINT".into()))
            .await;
        assert!(matches!(r, Err(OAuthError::InvalidDpopProof(_))));
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
        // DPoP 束縛して発行（public client は B-5 で束縛必須）。
        let p = provider();
        let c = client("rp");
        let mut code = base_code("C1", "rp");
        code.scope = "openid offline_access".into();
        code.dpop_jkt = Some("KEY-A".into());
        p.store.save_code(code).await;
        let f = form(&[("code", "C1"), ("redirect_uri", "https://rp/cb")]);
        let r = AuthorizationCodeGrant.handle(&p, &c, &f, Some("KEY-A".into())).await.unwrap();
        assert!(r.refresh_token.is_some());
    }

    // B-5: public client + offline_access + DPoP 束縛なし → refresh を発行しない（発行時点で塞ぐ）。
    #[tokio::test]
    async fn offline_access_public_unbound_issues_no_refresh() {
        let p = provider();
        let c = client("rp"); // public(none)
        let mut code = base_code("C1", "rp");
        code.scope = "openid offline_access".into();
        p.store.save_code(code).await;
        let f = form(&[("code", "C1"), ("redirect_uri", "https://rp/cb")]);
        let r = AuthorizationCodeGrant.handle(&p, &c, &f, None).await.unwrap();
        assert!(r.refresh_token.is_none());
    }

    // B-5: confidential client は束縛なしでも refresh 発行（client 認証が防壁）。
    #[tokio::test]
    async fn offline_access_confidential_unbound_issues_refresh() {
        let p = provider();
        let c = confidential_client("conf-rp");
        let mut code = base_code("C1", "conf-rp");
        code.scope = "openid offline_access".into();
        p.store.save_code(code).await;
        let f = form(&[("code", "C1"), ("redirect_uri", "https://rp/cb")]);
        let r = AuthorizationCodeGrant.handle(&p, &c, &f, None).await.unwrap();
        assert!(r.refresh_token.is_some());
    }

    // B-4: 消費済み RT の再提示 → 再利用検知 → invalid_grant、かつ系列全体を失効する。
    #[tokio::test]
    async fn refresh_reuse_detected_revokes_family() {
        let p = provider();
        let c = client("mobile-rp");
        p.store
            .save_refresh_token(rt_bound("RT1", "mobile-rp", "openid offline_access", "KEY-A"))
            .await;
        let f = form(&[("refresh_token", "RT1")]);
        // 正常ローテーション: RT1 -> RT2（RT1 は used、replaced_by=RT2）。
        let r1 = RefreshTokenGrant.handle(&p, &c, &f, Some("KEY-A".into())).await.unwrap();
        let rt2 = r1.refresh_token.clone().unwrap();
        // RT1 を再提示 → 再利用検知 → invalid_grant。
        let reuse = RefreshTokenGrant.handle(&p, &c, &f, Some("KEY-A".into())).await;
        assert!(matches!(reuse, Err(OAuthError::InvalidGrant(_))));
        // 系列失効: 後継 RT2 も無効化されている。
        let f2 = form(&[("refresh_token", rt2.as_str())]);
        let after = RefreshTokenGrant.handle(&p, &c, &f2, Some("KEY-A".into())).await;
        assert!(matches!(after, Err(OAuthError::InvalidGrant(_))));
    }

    // B-4: ローテーション後の新 RT は同じ family_id を継承する。
    #[tokio::test]
    async fn refresh_rotation_inherits_family() {
        let p = provider();
        let c = client("mobile-rp");
        p.store
            .save_refresh_token(rt_bound("RT1", "mobile-rp", "openid offline_access", "KEY-A"))
            .await;
        let fam = p.store.get_refresh_token("RT1").await.unwrap().family_id;
        let r = RefreshTokenGrant
            .handle(&p, &c, &form(&[("refresh_token", "RT1")]), Some("KEY-A".into()))
            .await
            .unwrap();
        let rt2 = r.refresh_token.unwrap();
        assert_eq!(p.store.get_refresh_token(&rt2).await.unwrap().family_id, fam);
    }

    #[tokio::test]
    async fn refresh_rotates_and_reuse_rejected() {
        let p = provider();
        let c = client("rp");
        p.store.save_refresh_token(rt_bound("RT1", "rp", "openid offline_access", "KEY-A")).await;
        let f = form(&[("refresh_token", "RT1")]);
        let r = RefreshTokenGrant.handle(&p, &c, &f, Some("KEY-A".into())).await.unwrap();
        assert!(r.refresh_token.is_some());
        assert_ne!(r.refresh_token.as_deref(), Some("RT1")); // ローテーション
        assert!(matches!(
            RefreshTokenGrant.handle(&p, &c, &f, Some("KEY-A".into())).await,
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
        p.store.save_refresh_token(rt_bound("RT1", "rp", "openid profile", "KEY-A")).await;
        let widen = form(&[("refresh_token", "RT1"), ("scope", "openid profile email")]);
        assert!(matches!(
            RefreshTokenGrant.handle(&p, &c, &widen, Some("KEY-A".into())).await,
            Err(OAuthError::InvalidScope(_))
        ));
        p.store.save_refresh_token(rt_bound("RT2", "rp", "openid profile", "KEY-A")).await;
        let narrow = form(&[("refresh_token", "RT2"), ("scope", "openid")]);
        let r = RefreshTokenGrant.handle(&p, &c, &narrow, Some("KEY-A".into())).await.unwrap();
        assert_eq!(r.scope, "openid");
    }

    // ===== CIBA grant 統合テスト（MemoryCibaStore 注入）=====
    // grant ロジックが store を正しく使うことを検証する。Firestore の updateTime CAS
    // 自体の検証ではない（そこはコードレビュー担保 / MemoryCibaStore の単体テストで補強）。
    use crate::ciba::{CibaStatus, CibaStore, MemoryCibaStore};

    async fn seed_ciba(status: CibaStatus) -> (Provider, String) {
        let store = std::sync::Arc::new(MemoryCibaStore::default());
        let id = store.create("rp", "user@example.com", "openid", "msg", None).await.unwrap();
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
