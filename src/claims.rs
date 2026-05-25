//! scope → 解放する claim 名のマッピング（OIDC Core 5.4）。
//! node-oidc-provider の `claims` 設定相当。

pub const PROFILE: &[&str] = &[
    "name", "family_name", "given_name", "middle_name", "nickname",
    "preferred_username", "profile", "picture", "website", "gender",
    "birthdate", "zoneinfo", "locale", "updated_at",
];
pub const EMAIL: &[&str] = &["email", "email_verified"];

/// ユーザーが自身で編集できる claim（本人性に関わる email/sub 等は含めない）。
pub const EDITABLE: &[&str] =
    &["name", "nickname", "birthdate", "gender", "zoneinfo", "locale"];
pub const ADDRESS: &[&str] = &["address"];
pub const PHONE: &[&str] = &["phone_number", "phone_number_verified"];

/// 与えられた scope 文字列で解放してよい claim 名の集合（sub は常に含む）。
pub fn claim_names_for_scopes(scope: &str) -> Vec<&'static str> {
    let mut out = vec!["sub"];
    for s in scope.split_whitespace() {
        match s {
            "profile" => out.extend_from_slice(PROFILE),
            "email" => out.extend_from_slice(EMAIL),
            "address" => out.extend_from_slice(ADDRESS),
            "phone" => out.extend_from_slice(PHONE),
            _ => {}
        }
    }
    out
}

/// discovery の claims_supported 用（全 scope の和集合 + sub）。
pub fn all_supported_claims() -> Vec<&'static str> {
    let mut out = vec!["sub"];
    out.extend_from_slice(PROFILE);
    out.extend_from_slice(EMAIL);
    out.extend_from_slice(ADDRESS);
    out.extend_from_slice(PHONE);
    out
}
