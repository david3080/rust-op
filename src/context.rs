//! 認可リクエストのフェーズ型コンテキスト（typestate）。
//!
//! OAuth の安全規律「redirect_uri の検証前にエラーを redirect で返してはならない
//! （open redirector 化する）」を型で強制する。
//!   Phase 0: `RawAuthRequest`   … 生のリクエスト。エラーは plain 表示のみ可能。
//!   Phase 1: `AddressedRequest` … client 解決 + redirect_uri 検証済みの証明書。
//!                                 これを持つ場合のみ error redirect が許される。
//! 遷移は `auth_checks::resolve_addressee` が `RawAuthRequest` を **move で消費**して
//! 行うため、検証前の古いコンテキストが遷移後に生き残ることはない。
//! Phase 1 以降のチェック（response_type / scope / pkce）は相互に可換なので
//! フェーズは分けず、`&AddressedRequest` を読むだけの検証として並べる。

use crate::model::{AuthParams, Client};

/// Phase 0: パース直後の認可リクエスト。redirect 先は一切信用できない。
pub struct RawAuthRequest {
    pub params: AuthParams,
    /// PAR 由来なら元の request_uri。コード発行時に削除して単回化する。
    pub request_uri: Option<String>,
}

/// Phase 1: client が解決され redirect_uri が登録値と完全一致することを検証済み。
/// `client` / `redirect_uri` が Option でない = 「未解決のまま後段に進む」状態が
/// 表現不可能であることが、旧 AuthContext の `expect` 2 本を置き換える。
pub struct AddressedRequest {
    pub params: AuthParams,
    pub client: Client,
    pub redirect_uri: String,
    /// PAR 由来なら元の request_uri（Phase 0 から引き継ぎ）。
    pub request_uri: Option<String>,
}
