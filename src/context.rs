//! 認可リクエストのパイプライン用コンテキスト。
//! 各 AuthorizationCheck が `&mut AuthContext` を順に enrich していく
//! (node-oidc-provider の Koa ctx 書き換えスタイルを Rust に写したもの)。

use crate::model::{AuthParams, Client};

pub struct AuthContext {
    pub params: AuthParams,
    /// check_client で解決。
    pub client: Option<Client>,
    /// check_redirect_uri で検証済みの値。
    pub redirect_uri: Option<String>,
    /// ログイン済みなら埋まる。
    pub account_id: Option<String>,
    /// ログイン時刻（epoch 秒）。
    pub auth_time: Option<u64>,
}

impl AuthContext {
    pub fn new(params: AuthParams) -> Self {
        Self {
            params,
            client: None,
            redirect_uri: None,
            account_id: None,
            auth_time: None,
        }
    }

    pub fn client(&self) -> &Client {
        self.client.as_ref().expect("client resolved by check_client")
    }
}
