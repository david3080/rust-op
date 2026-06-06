//! 制御つき動的クライアント登録 (Controlled DCR, RFC 7591) の中核ロジック。
//!
//! Initial Access Token (IAT) の発行/ハッシュと、登録メタデータの検証を担う。
//! セキュリティ核なので「純粋関数＋単体テスト」で固める（Firestore I/O・HTTP は別層）。
//!
//! 設計方針:
//! - IAT は CSPRNG。**保存はハッシュのみ**（DB が漏れても使えるトークンは出ない）。
//! - IAT に制約（許可 redirect ホスト / 許可 grant_type）を埋め、**正しい IAT でも
//!   制約を超える登録は拒否**する。
//! - 登録クライアントは **private_key_jwt（jwks 必須・client_secret なし）** 既定。
//!   → OP は公開鍵しか持たず「クライアント秘密の漏洩」というカテゴリ自体を消す。
//! - redirect_uri は **https＋許可ホスト**（DCR 最大の攻撃面＝コード窃取の足場を塞ぐ）。
#![allow(dead_code)] // エンドポイント/ストアからの利用は後続 PR で配線する。

use crate::model::{Client, JwkPub};
use sha2::{Digest, Sha256};

/// IAT の制約（発行時に埋め込み、登録時に強制する）。
pub struct IatConstraints {
    /// 登録を許す redirect_uri のホスト名（完全一致）。
    pub allowed_redirect_hosts: Vec<String>,
    /// 許す grant_type。
    pub allowed_grant_types: Vec<String>,
}

/// RP が提示する登録メタデータ（RFC 7591 の部分集合）。
pub struct RegistrationRequest {
    pub client_name: Option<String>,
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub jwks: Vec<JwkPub>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DcrError {
    NoRedirectUris,
    InsecureRedirectUri(String),
    RedirectHostNotAllowed(String),
    MissingJwks,
    GrantTypeNotAllowed(String),
}

impl DcrError {
    /// RFC 7591 のエラーコード（invalid_redirect_uri / invalid_client_metadata）。
    pub fn code(&self) -> &'static str {
        match self {
            DcrError::NoRedirectUris
            | DcrError::InsecureRedirectUri(_)
            | DcrError::RedirectHostNotAllowed(_) => "invalid_redirect_uri",
            DcrError::MissingJwks | DcrError::GrantTypeNotAllowed(_) => "invalid_client_metadata",
        }
    }
}

/// CSPRNG で Initial Access Token を生成し、(生トークン, 保存用ハッシュ) を返す。
/// 生トークンは発行時に **1 回だけ** 呼び出し側へ渡す。保存はハッシュのみ。
pub fn gen_initial_access_token() -> (String, String) {
    use rand_core::RngCore;
    let mut b = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut b);
    let token = crate::es256::b64url_encode(b);
    let hash = hash_token(&token);
    (token, hash)
}

/// トークンの保存用ハッシュ（SHA-256 → base64url）。DB には生トークンを置かない。
pub fn hash_token(token: &str) -> String {
    crate::es256::b64url_encode(Sha256::digest(token.as_bytes()))
}

/// 登録要求を IAT 制約に照らして検証し、保存用の Client を組み立てる。
/// client_id は呼び出し側が採番して渡す（衝突しない一意値）。
pub fn validate_registration(
    client_id: &str,
    req: &RegistrationRequest,
    c: &IatConstraints,
) -> Result<Client, DcrError> {
    // redirect_uri: 1 つ以上、https、許可ホスト内。
    if req.redirect_uris.is_empty() {
        return Err(DcrError::NoRedirectUris);
    }
    for uri in &req.redirect_uris {
        let host = https_host(uri).ok_or_else(|| DcrError::InsecureRedirectUri(uri.clone()))?;
        if !c.allowed_redirect_hosts.iter().any(|h| h.eq_ignore_ascii_case(host)) {
            return Err(DcrError::RedirectHostNotAllowed(host.to_string()));
        }
    }
    // private_key_jwt 前提: 公開鍵(jwks)必須＝OP は秘密を持たない。
    if req.jwks.is_empty() {
        return Err(DcrError::MissingJwks);
    }
    // grant_type: 指定があれば許可集合の部分集合。無指定は authorization_code。
    let grant_types = if req.grant_types.is_empty() {
        vec!["authorization_code".to_string()]
    } else {
        for g in &req.grant_types {
            if !c.allowed_grant_types.iter().any(|a| a == g) {
                return Err(DcrError::GrantTypeNotAllowed(g.clone()));
            }
        }
        req.grant_types.clone()
    };
    Ok(Client {
        client_id: client_id.to_string(),
        redirect_uris: req.redirect_uris.clone(),
        post_logout_redirect_uris: vec![],
        token_endpoint_auth_method: "private_key_jwt".into(),
        client_secret: None,
        grant_types,
        dpop_bound: true,
        jwks: req.jwks.clone(),
        require_par: true,
        require_pkce: true,
        id_token_signed_response_alg: None,
    })
}

/// uri が https かつ正常なら、そのホスト名(ポート除く)を返す。http / fragment 付き / 空は None。
///
/// セキュリティ上の要: authority に userinfo(`user:pass@host`)を含むものは拒否する。
/// これを許すと `https://rp.example.com:x@evil.com/cb` のように、本関数は許可ホスト
/// (`rp.example.com`)を返すのにブラウザは `@` 以降(`evil.com`)を実ホストとして解釈し、
/// 許可リストを抜けて認可コードを攻撃者へ送れてしまう(ホスト偽装)。
fn https_host(uri: &str) -> Option<&str> {
    if uri.contains('#') {
        return None; // redirect_uri に fragment は不可（RFC 6749 §3.1.2）。
    }
    let rest = uri.strip_prefix("https://")?;
    let authority = rest.split('/').next().unwrap_or(rest);
    if authority.contains('@') {
        return None; // userinfo 付きは不可（ホスト偽装の足場）。
    }
    let host = authority.split(':').next().unwrap_or(authority);
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwk() -> JwkPub {
        JwkPub { kid: "k1".into(), x: "x".into(), y: "y".into() }
    }

    fn constraints() -> IatConstraints {
        IatConstraints {
            allowed_redirect_hosts: vec!["rp.example.com".into()],
            allowed_grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        }
    }

    fn req(redirect: &[&str], grants: &[&str], jwks: Vec<JwkPub>) -> RegistrationRequest {
        RegistrationRequest {
            client_name: Some("My RP".into()),
            redirect_uris: redirect.iter().map(|s| s.to_string()).collect(),
            grant_types: grants.iter().map(|s| s.to_string()).collect(),
            jwks,
        }
    }

    #[test]
    fn valid_registration_builds_private_key_jwt_client() {
        let r = req(&["https://rp.example.com/cb"], &["authorization_code"], vec![jwk()]);
        let c = validate_registration("cid-1", &r, &constraints()).unwrap();
        assert_eq!(c.client_id, "cid-1");
        assert_eq!(c.token_endpoint_auth_method, "private_key_jwt");
        assert!(c.client_secret.is_none());
        assert_eq!(c.jwks.len(), 1);
        // FAPI2 既定（PKCE/PAR/DPoP）。
        assert!(c.require_pkce && c.require_par && c.dpop_bound);
        assert_eq!(c.redirect_uris, vec!["https://rp.example.com/cb"]);
    }

    #[test]
    fn rejects_http_redirect() {
        let r = req(&["http://rp.example.com/cb"], &[], vec![jwk()]);
        assert!(matches!(
            validate_registration("c", &r, &constraints()),
            Err(DcrError::InsecureRedirectUri(_))
        ));
    }

    #[test]
    fn rejects_redirect_with_fragment() {
        let r = req(&["https://rp.example.com/cb#frag"], &[], vec![jwk()]);
        assert!(matches!(
            validate_registration("c", &r, &constraints()),
            Err(DcrError::InsecureRedirectUri(_))
        ));
    }

    #[test]
    fn rejects_redirect_host_not_in_allowlist() {
        let r = req(&["https://evil.example.com/cb"], &[], vec![jwk()]);
        assert!(matches!(
            validate_registration("c", &r, &constraints()),
            Err(DcrError::RedirectHostNotAllowed(_))
        ));
    }

    #[test]
    fn rejects_empty_redirect() {
        let r = req(&[], &[], vec![jwk()]);
        assert!(matches!(
            validate_registration("c", &r, &constraints()),
            Err(DcrError::NoRedirectUris)
        ));
    }

    #[test]
    fn rejects_missing_jwks() {
        let r = req(&["https://rp.example.com/cb"], &[], vec![]);
        assert!(matches!(
            validate_registration("c", &r, &constraints()),
            Err(DcrError::MissingJwks)
        ));
    }

    #[test]
    fn rejects_disallowed_grant_type() {
        let r = req(&["https://rp.example.com/cb"], &["client_credentials"], vec![jwk()]);
        assert!(matches!(
            validate_registration("c", &r, &constraints()),
            Err(DcrError::GrantTypeNotAllowed(_))
        ));
    }

    #[test]
    fn rejects_userinfo_host_spoof_with_port() {
        // https_host が許可ホストを返すのにブラウザは evil.com を実ホストと見る古典的バイパス。
        let r = req(&["https://rp.example.com:x@evil.com/cb"], &[], vec![jwk()]);
        assert!(matches!(
            validate_registration("c", &r, &constraints()),
            Err(DcrError::InsecureRedirectUri(_))
        ));
    }

    #[test]
    fn rejects_userinfo_host_spoof_without_port() {
        let r = req(&["https://rp.example.com@evil.com/cb"], &[], vec![jwk()]);
        assert!(matches!(
            validate_registration("c", &r, &constraints()),
            Err(DcrError::InsecureRedirectUri(_))
        ));
    }

    #[test]
    fn allows_uppercase_host_case_insensitively() {
        // ホスト名は DNS 上ケース非依存。許可ホストの大文字表記は同一ホストとして通す。
        let r = req(&["https://RP.EXAMPLE.COM/cb"], &[], vec![jwk()]);
        assert!(validate_registration("c", &r, &constraints()).is_ok());
    }

    #[test]
    fn empty_grant_defaults_to_authorization_code() {
        let r = req(&["https://rp.example.com/cb"], &[], vec![jwk()]);
        let c = validate_registration("c", &r, &constraints()).unwrap();
        assert_eq!(c.grant_types, vec!["authorization_code"]);
    }

    #[test]
    fn allows_multiple_allowed_grants() {
        let r = req(
            &["https://rp.example.com/cb"],
            &["authorization_code", "refresh_token"],
            vec![jwk()],
        );
        let c = validate_registration("c", &r, &constraints()).unwrap();
        assert_eq!(c.grant_types, vec!["authorization_code", "refresh_token"]);
    }

    #[test]
    fn allows_redirect_host_with_port_and_path() {
        let mut con = constraints();
        con.allowed_redirect_hosts = vec!["rp.example.com".into()];
        let r = req(&["https://rp.example.com:8443/a/b/cb"], &[], vec![jwk()]);
        assert!(validate_registration("c", &r, &con).is_ok());
    }

    #[test]
    fn iat_is_random_hashed_and_not_stored_raw() {
        let (t1, h1) = gen_initial_access_token();
        let (t2, _h2) = gen_initial_access_token();
        assert_ne!(t1, t2); // 毎回異なる
        assert_ne!(t1, h1); // 保存ハッシュ != 生トークン
        assert_eq!(h1, hash_token(&t1)); // ハッシュは決定的（照合用）
        // 生トークンを知らなければハッシュから復元できない（一方向）。
        assert_ne!(hash_token("guess"), h1);
    }
}
