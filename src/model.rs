//! データ（構造体・列挙型）。振る舞いは trait 側（auth_checks/grants/...）に置く。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// クライアントの公開鍵（private_key_jwt 検証用、ES256/P-256）。
#[derive(Clone, Debug)]
pub struct JwkPub {
    pub kid: String,
    pub x: String,
    pub y: String,
}

/// 登録済みクライアント。node-oidc-provider の `models/client.js` 相当の最小版。
#[derive(Clone, Debug)]
pub struct Client {
    pub client_id: String,
    pub redirect_uris: Vec<String>,
    /// "none" | "client_secret_basic" | "client_secret_post" | "private_key_jwt"
    pub token_endpoint_auth_method: String,
    pub client_secret: Option<String>,
    pub grant_types: Vec<String>,
    /// RP-Initiated Logout の許可リダイレクト先（オープンリダイレクト防止）。
    pub post_logout_redirect_uris: Vec<String>,
    /// true なら token endpoint で DPoP proof を要求し access token を jkt に束縛する。
    pub dpop_bound: bool,
    /// private_key_jwt 用の公開鍵集合。
    pub jwks: Vec<JwkPub>,
    /// FAPI: PAR 必須。
    pub require_par: bool,
    /// FAPI: PKCE 必須。
    pub require_pkce: bool,
    /// id_token の署名 alg（OIDC `id_token_signed_response_alg`）。None は既定（ES256）。
    pub id_token_signed_response_alg: Option<String>,
}

impl Client {
    pub fn is_public(&self) -> bool {
        self.token_endpoint_auth_method == "none"
    }
    pub fn allows_grant(&self, gt: &str) -> bool {
        self.grant_types.iter().any(|g| g == gt)
    }
}

/// /authorize に来たクエリパラメータ。
#[derive(Clone, Debug, Deserialize)]
pub struct AuthParams {
    pub client_id: Option<String>,
    pub redirect_uri: Option<String>,
    pub response_type: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub prompt: Option<String>,
    pub max_age: Option<String>,
    pub acr_values: Option<String>,
    pub response_mode: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    /// DPoP key binding (RFC 9449 §10): 認可コード/トークンを特定 jkt に束縛する要求。
    pub dpop_jkt: Option<String>,
}

/// ログイン待ちの認可リクエスト。node-oidc-provider の Interaction 相当。
/// resume のために元クエリを丸ごと保存する。
#[derive(Clone, Debug)]
pub struct Interaction {
    pub uid: String,
    pub raw_query: String,
    /// ログイン完了で埋まる。
    pub account_id: Option<String>,
    /// ログイン完了時刻（epoch 秒）。id_token の auth_time に使う。
    pub auth_time: Option<u64>,
    /// PAR 由来なら元の request_uri。resume → コード発行時に削除して単回化する。
    pub request_uri: Option<String>,
}

/// SSO 用セッション（cookie sid → account）。
#[derive(Clone, Debug)]
pub struct Session {
    pub sid: String,
    pub account_id: String,
    pub auth_time: u64,
}

/// 発行した認可コード。1 回で消費する。
#[derive(Clone, Debug)]
pub struct AuthorizationCode {
    pub code: String,
    pub client_id: String,
    pub account_id: String,
    pub redirect_uri: String,
    pub scope: String,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub auth_time: u64,
    pub acr: Option<String>,
    /// DPoP key binding: PAR/authorize で dpop_jkt 指定時、token の proof jkt と一致必須。
    pub dpop_jkt: Option<String>,
    /// FAPI: 認可コードは短命。epoch 秒。
    pub expires_at: u64,
}

/// オペーク access token。
#[derive(Clone, Debug)]
pub struct AccessToken {
    pub token: String,
    pub client_id: String,
    pub account_id: String,
    pub scope: String,
    /// DPoP 束縛時の JWK Thumbprint（cnf.jkt）。
    pub jkt: Option<String>,
}

/// リフレッシュトークン。使用時にローテーション（消費して新規発行）する。
#[derive(Clone, Debug)]
pub struct RefreshToken {
    pub token: String,
    pub client_id: String,
    pub account_id: String,
    pub scope: String,
}

/// ユーザーアカウント。claims は OIDC の claim マップ。
#[derive(Clone, Debug)]
pub struct Account {
    pub sub: String,
    pub claims: HashMap<String, serde_json::Value>,
}

/// token endpoint の成功レスポンス。
#[derive(Serialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}
