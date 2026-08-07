//! 制御つき動的クライアント登録 (Controlled DCR, RFC 7591) の中核ロジック。
//!
//! Initial Access Token (IAT) の発行/ハッシュと、登録メタデータの検証を担う。
//! セキュリティ核なので「純粋関数＋単体テスト」で固める（Firestore I/O・HTTP は別層）。
//!
//! 設計方針:
//! - IAT は CSPRNG。**保存はハッシュのみ**（DB が漏れても使えるトークンは出ない）。
//! - IAT に制約（許可 redirect ホスト / 許可 grant_type / 認証プロファイル）を埋め、
//!   **正しい IAT でも制約を超える登録は拒否**する。認証プロファイルは RP が選ぶのではなく
//!   管理者が mint 時に固定する（[`ClientProfile`] 参照。弱いプロファイルへの自己ダウン
//!   グレードを防ぐ）。既定は **ConfidentialKey = private_key_jwt（jwks 必須・
//!   client_secret なし）**——OP は公開鍵しか持たず「クライアント秘密の漏洩」という
//!   カテゴリ自体を消す設計を基本線とする。
//! - redirect_uri は **https＋許可ホスト**（DCR 最大の攻撃面＝コード窃取の足場を塞ぐ）。

use crate::model::{Client, JwkPub};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// DCR で発行するクライアントの認証プロファイル。管理者が mint 時に選び、IAT に固定する
/// （RP がリクエストで選ぶものではない——弱いプロファイルへの自己ダウングレードを防ぐ）。
///
/// 3種は既存の静的クライアントが実例そのもの: Public = demo-rp/mobile-rp、
/// ConfidentialSecret = qm-rp（FAPI2厳格設定を満たせない外部RP向け）、
/// ConfidentialKey = 従来のDCR既定（private_key_jwt、FAPI2相当）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientProfile {
    /// token_endpoint_auth_method=none。PKCE は is_public() 経由で常時必須、jwks 不要。
    Public,
    /// token_endpoint_auth_method=client_secret_basic。secret は登録時に1回だけ生成し
    /// 平文をRPへ返す（保存はハッシュのみ）。PKCE 必須、PAR/DPoP は要求しない。
    ConfidentialSecret,
    /// token_endpoint_auth_method=private_key_jwt。jwks/jwks_uri 必須、PAR+PKCE+DPoP 必須
    /// （FAPI2相当。既存の唯一のDCR挙動と同一）。
    ConfidentialKey,
}

/// IAT の制約（発行時に埋め込み、登録時に強制する）。
#[derive(Serialize, Deserialize)]
pub struct IatConstraints {
    /// 登録を許す redirect_uri のホスト名（完全一致）。
    pub allowed_redirect_hosts: Vec<String>,
    /// 許す grant_type。
    pub allowed_grant_types: Vec<String>,
    /// 発行するクライアントの認証プロファイル。
    ///
    /// `#[serde(default)]` は **片方向の互換性のみ** 提供する: 新バイナリが（本フィールド
    /// 導入前に mint された）旧レコードを読む場合は ConfidentialKey にフォールバックし正しく
    /// 動く。逆方向——Blue/Green ロールバックで旧バイナリに戻り、本フィールド導入後に
    /// mint された未消費の Public/ConfidentialSecret 向け IAT を読む場合——は非対応:
    /// 旧バイナリの `IatConstraints` 型には `profile` が無いため serde が単に無視し、
    /// 旧バイナリの登録ロジックは常に private_key_jwt 前提で jwks を要求する。この場合
    /// RP の登録は `MissingJwks` で拒否される（**fail-closed**——誤って弱いプロファイルの
    /// クライアントが発行されるわけではない）。mint は低頻度の管理者操作で IAT の TTL も
    /// 短い（既定24h）ため実害は限定的だが、ロールバックの直後は再 mint が必要になりうる。
    #[serde(default = "default_profile")]
    pub profile: ClientProfile,
}

fn default_profile() -> ClientProfile {
    ClientProfile::ConfidentialKey
}

/// RP が提示する登録メタデータ（RFC 7591 の部分集合）。
pub struct RegistrationRequest {
    pub redirect_uris: Vec<String>,
    pub grant_types: Vec<String>,
    pub jwks: Vec<JwkPub>,
    /// inline jwks の代わりに JWKS エンドポイントで鍵を提示する場合（RFC 7591）。
    pub jwks_uri: Option<String>,
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

    /// error_description 用の人間可読メッセージ。
    pub fn description(&self) -> String {
        match self {
            DcrError::NoRedirectUris => "at least one redirect_uri is required".into(),
            DcrError::InsecureRedirectUri(u) => {
                format!("redirect_uri must be https without fragment or userinfo: {u}")
            }
            DcrError::RedirectHostNotAllowed(h) => {
                format!("redirect_uri host not allowed by the initial access token: {h}")
            }
            DcrError::MissingJwks => "a jwks with at least one EC P-256 key is required".into(),
            DcrError::GrantTypeNotAllowed(g) => {
                format!("grant_type not allowed by the initial access token: {g}")
            }
        }
    }
}

/// RFC 7517 JWK Set から ES256(EC P-256) 公開鍵だけを抽出する。
///
/// 登録境界での鍵検証も兼ねる: x/y が base64url として復号でき、かつ有効な P-256 点を
/// 成すものだけ受理する。これで「登録成功(201) = private_key_jwt が動くクライアント」を
/// 保証し、壊れた鍵が登録を通過してから token endpoint で無言失敗する事故を防ぐ。
/// kty!=EC / crv!=P-256 / kid 空 / 復号不能な鍵は捨てる（残り 0 個なら
/// validate_registration が MissingJwks で弾く）。
pub fn jwks_from_jwk_set(jwks: Option<&serde_json::Value>) -> Vec<JwkPub> {
    let keys = match jwks.and_then(|v| v.get("keys")).and_then(|v| v.as_array()) {
        Some(k) => k,
        None => return vec![],
    };
    keys.iter()
        .filter_map(|k| {
            if k.get("kty")?.as_str()? != "EC" || k.get("crv")?.as_str()? != "P-256" {
                return None;
            }
            let kid = k.get("kid")?.as_str()?;
            if kid.is_empty() {
                return None;
            }
            let x = k.get("x")?.as_str()?;
            let y = k.get("y")?.as_str()?;
            // 登録時に x/y が有効な P-256 点を成すか検証する（壊れた鍵を 201 にしない）。
            let xb = crate::es256::b64url_decode(x).ok()?;
            let yb = crate::es256::b64url_decode(y).ok()?;
            crate::es256::verifying_key_from_xy(&xb, &yb).ok()?;
            Some(JwkPub { kid: kid.to_string(), x: x.to_string(), y: y.to_string() })
        })
        .collect()
}

/// CSPRNG で 256bit トークンを生成し、(生トークン, 保存用ハッシュ) を返す。
/// 生トークンは発行/登録時に **1 回だけ** 呼び出し側へ渡す。保存はハッシュのみ。
/// Initial Access Token の発行と、ConfidentialSecret プロファイルの client_secret 生成の
/// 両方から使う汎用プリミティブ（トークンの性質はどちらも同じ: ランダム・単回表示・ハッシュ保存）。
pub fn gen_random_token() -> (String, String) {
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

/// 登録の成果物。ConfidentialSecret プロファイルの場合のみ `raw_client_secret` が
/// Some になる（RP へ返す一度きりの平文。`client.client_secret` にはハッシュのみを持つ）。
pub struct RegistrationOutcome {
    pub client: Client,
    pub raw_client_secret: Option<String>,
}

/// 登録要求を IAT 制約に照らして検証し、保存用の Client を組み立てる。
/// client_id は呼び出し側が採番して渡す（衝突しない一意値）。
/// token_endpoint_auth_method は RP のリクエストではなく IAT の `profile` で決まる
/// （弱いプロファイルへの自己ダウングレードを防ぐ——他のフィールドの許可リスト検証と同じ設計）。
pub fn validate_registration(
    client_id: &str,
    req: &RegistrationRequest,
    c: &IatConstraints,
) -> Result<RegistrationOutcome, DcrError> {
    // redirect_uri: 1 つ以上、https、許可ホスト内。全プロファイル共通。
    if req.redirect_uris.is_empty() {
        return Err(DcrError::NoRedirectUris);
    }
    for uri in &req.redirect_uris {
        let host = https_host(uri).ok_or_else(|| DcrError::InsecureRedirectUri(uri.clone()))?;
        if !c.allowed_redirect_hosts.iter().any(|h| h.eq_ignore_ascii_case(host)) {
            return Err(DcrError::RedirectHostNotAllowed(host.to_string()));
        }
    }
    // grant_type: 指定があれば許可集合の部分集合。無指定は authorization_code。全プロファイル共通。
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

    let base = Client {
        client_id: client_id.to_string(),
        redirect_uris: req.redirect_uris.clone(),
        post_logout_redirect_uris: vec![],
        token_endpoint_auth_method: String::new(), // プロファイル毎に下で設定
        client_secret: None,
        grant_types,
        dpop_bound: false,
        jwks: vec![],
        jwks_uri: None,
        require_par: false,
        require_pkce: false,
        id_token_signed_response_alg: None,
    };

    match c.profile {
        ClientProfile::ConfidentialKey => {
            // private_key_jwt 前提: 公開鍵が必須＝OP は秘密を持たない。inline jwks か
            // jwks_uri のどちらかで公開鍵を提示すること（鍵ローテーション運用なら jwks_uri）。
            if req.jwks.is_empty() && req.jwks_uri.as_deref().map(str::is_empty).unwrap_or(true) {
                return Err(DcrError::MissingJwks);
            }
            Ok(RegistrationOutcome {
                client: Client {
                    token_endpoint_auth_method: "private_key_jwt".into(),
                    dpop_bound: true,
                    jwks: req.jwks.clone(),
                    jwks_uri: req.jwks_uri.clone(),
                    require_par: true,
                    require_pkce: true,
                    ..base
                },
                raw_client_secret: None,
            })
        }
        ClientProfile::ConfidentialSecret => {
            // qm-rp（静的クライアント）と同じ設定: client_secret_basic + PKCE 必須、
            // PAR/DPoP は要求しない（対応できない外部RP向けプロファイル）。
            let (raw, hash) = gen_random_token();
            Ok(RegistrationOutcome {
                client: Client {
                    token_endpoint_auth_method: "client_secret_basic".into(),
                    client_secret: Some(hash),
                    require_pkce: true,
                    ..base
                },
                raw_client_secret: Some(raw),
            })
        }
        ClientProfile::Public => {
            // demo-rp/mobile-rp と同じ設定: token_endpoint_auth_method=none、DPoP束縛あり
            // （publicクライアントはPKCEだけでは認可コード窃取に対する保護止まりなので、
            // アクセストークン自体もDPoPで送信者拘束する）。
            // PKCE は is_public() 経由で常時強制されるため require_pkce は不要。
            Ok(RegistrationOutcome {
                client: Client {
                    token_endpoint_auth_method: "none".into(),
                    dpop_bound: true,
                    ..base
                },
                raw_client_secret: None,
            })
        }
    }
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
            profile: ClientProfile::ConfidentialKey,
        }
    }

    fn req(redirect: &[&str], grants: &[&str], jwks: Vec<JwkPub>) -> RegistrationRequest {
        RegistrationRequest {
            redirect_uris: redirect.iter().map(|s| s.to_string()).collect(),
            grant_types: grants.iter().map(|s| s.to_string()).collect(),
            jwks,
            jwks_uri: None,
        }
    }

    #[test]
    fn valid_registration_builds_private_key_jwt_client() {
        let r = req(&["https://rp.example.com/cb"], &["authorization_code"], vec![jwk()]);
        let out = validate_registration("cid-1", &r, &constraints()).unwrap();
        let c = out.client;
        assert_eq!(c.client_id, "cid-1");
        assert_eq!(c.token_endpoint_auth_method, "private_key_jwt");
        assert!(c.client_secret.is_none());
        assert_eq!(c.jwks.len(), 1);
        // FAPI2 既定（PKCE/PAR/DPoP）。
        assert!(c.require_pkce && c.require_par && c.dpop_bound);
        assert_eq!(c.redirect_uris, vec!["https://rp.example.com/cb"]);
        assert!(out.raw_client_secret.is_none(), "ConfidentialKeyはsecretを発行しない");
    }

    // B-6: inline jwks の代わりに jwks_uri で登録できる（鍵ローテーション運用）。
    #[test]
    fn registration_with_jwks_uri_only_is_accepted() {
        let r = RegistrationRequest {
            redirect_uris: vec!["https://rp.example.com/cb".into()],
            grant_types: vec![],
            jwks: vec![],
            jwks_uri: Some("https://rp.example.com/jwks".into()),
        };
        let c = validate_registration("cid-2", &r, &constraints()).unwrap().client;
        assert_eq!(c.token_endpoint_auth_method, "private_key_jwt");
        assert_eq!(c.jwks_uri.as_deref(), Some("https://rp.example.com/jwks"));
        assert!(c.jwks.is_empty());
    }

    #[test]
    fn confidential_secret_profile_issues_hashed_secret_and_raw_once() {
        let mut con = constraints();
        con.profile = ClientProfile::ConfidentialSecret;
        let r = req(&["https://rp.example.com/cb"], &[], vec![]); // jwks不要
        let out = validate_registration("cid-3", &r, &con).unwrap();
        assert_eq!(out.client.token_endpoint_auth_method, "client_secret_basic");
        assert!(out.client.require_pkce);
        assert!(!out.client.require_par && !out.client.dpop_bound);
        let raw = out.raw_client_secret.expect("ConfidentialSecretは平文secretを1回返す");
        // 保存されるのはハッシュのみ（平文そのものではない）。
        assert_eq!(out.client.client_secret.as_deref(), Some(hash_token(&raw).as_str()));
        assert_ne!(out.client.client_secret.as_deref(), Some(raw.as_str()));
    }

    #[test]
    fn public_profile_issues_none_auth_without_secret_or_jwks() {
        let mut con = constraints();
        con.profile = ClientProfile::Public;
        let r = req(&["https://rp.example.com/cb"], &[], vec![]); // jwks不要
        let out = validate_registration("cid-4", &r, &con).unwrap();
        assert_eq!(out.client.token_endpoint_auth_method, "none");
        assert!(out.client.client_secret.is_none());
        assert!(out.client.jwks.is_empty() && out.client.jwks_uri.is_none());
        assert!(!out.client.require_par);
        assert!(out.client.dpop_bound, "publicクライアントはdemo-rp/mobile-rpと同様DPoP束縛する");
        assert!(out.raw_client_secret.is_none());
    }

    // B-6: jwks も jwks_uri も無いと拒否（OP は秘密を持たないので公開鍵が必須）。
    #[test]
    fn registration_without_any_key_source_is_rejected() {
        let r = RegistrationRequest {
            redirect_uris: vec!["https://rp.example.com/cb".into()],
            grant_types: vec![],
            jwks: vec![],
            jwks_uri: None,
        };
        assert!(matches!(
            validate_registration("c", &r, &constraints()),
            Err(DcrError::MissingJwks)
        ));
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
        let c = validate_registration("c", &r, &constraints()).unwrap().client;
        assert_eq!(c.grant_types, vec!["authorization_code"]);
    }

    #[test]
    fn allows_multiple_allowed_grants() {
        let r = req(
            &["https://rp.example.com/cb"],
            &["authorization_code", "refresh_token"],
            vec![jwk()],
        );
        let c = validate_registration("c", &r, &constraints()).unwrap().client;
        assert_eq!(c.grant_types, vec!["authorization_code", "refresh_token"]);
    }

    #[test]
    fn allows_redirect_host_with_port_and_path() {
        let mut con = constraints();
        con.allowed_redirect_hosts = vec!["rp.example.com".into()];
        let r = req(&["https://rp.example.com:8443/a/b/cb"], &[], vec![jwk()]);
        assert!(validate_registration("c", &r, &con).is_ok());
    }

    /// 有効な P-256 公開鍵の (x, y) を base64url で返す。
    fn valid_ec_xy() -> (String, String) {
        use crate::es256::b64url_encode;
        use p256::ecdsa::SigningKey;
        let key = SigningKey::random(&mut rand_core::OsRng);
        let pt = key.verifying_key().to_encoded_point(false);
        (b64url_encode(pt.x().unwrap()), b64url_encode(pt.y().unwrap()))
    }

    #[test]
    fn jwks_extracts_valid_ec_p256_key() {
        let (x, y) = valid_ec_xy();
        let set = serde_json::json!({
            "keys": [{ "kty": "EC", "crv": "P-256", "kid": "k1", "x": x, "y": y }]
        });
        let keys = jwks_from_jwk_set(Some(&set));
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].kid, "k1");
    }

    #[test]
    fn jwks_rejects_non_ec_and_wrong_curve() {
        let (x, y) = valid_ec_xy();
        // RSA 鍵と P-384 鍵は捨てる。
        let set = serde_json::json!({
            "keys": [
                { "kty": "RSA", "kid": "r", "n": "abc", "e": "AQAB" },
                { "kty": "EC", "crv": "P-384", "kid": "p384", "x": x, "y": y },
            ]
        });
        assert!(jwks_from_jwk_set(Some(&set)).is_empty());
    }

    #[test]
    fn jwks_rejects_missing_kid_and_malformed_coords() {
        let (x, y) = valid_ec_xy();
        // kid 空。
        let no_kid = serde_json::json!({
            "keys": [{ "kty": "EC", "crv": "P-256", "kid": "", "x": x, "y": y }]
        });
        assert!(jwks_from_jwk_set(Some(&no_kid)).is_empty());
        // x が不正な長さ（P-256 点を成さない）→ 登録時検証で落ちる。
        let bad = serde_json::json!({
            "keys": [{ "kty": "EC", "crv": "P-256", "kid": "k", "x": "AAAA", "y": "AAAA" }]
        });
        assert!(jwks_from_jwk_set(Some(&bad)).is_empty());
    }

    #[test]
    fn jwks_handles_missing_jwks_field() {
        assert!(jwks_from_jwk_set(None).is_empty());
        assert!(jwks_from_jwk_set(Some(&serde_json::json!({}))).is_empty());
    }

    #[test]
    fn iat_is_random_hashed_and_not_stored_raw() {
        let (t1, h1) = gen_random_token();
        let (t2, _h2) = gen_random_token();
        assert_ne!(t1, t2); // 毎回異なる
        assert_ne!(t1, h1); // 保存ハッシュ != 生トークン
        assert_eq!(h1, hash_token(&t1)); // ハッシュは決定的（照合用）
        // 生トークンを知らなければハッシュから復元できない（一方向）。
        assert_ne!(hash_token("guess"), h1);
    }
}
