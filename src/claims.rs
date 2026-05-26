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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sub_always_included_even_without_scopes() {
        assert_eq!(claim_names_for_scopes(""), vec!["sub"]);
        assert_eq!(claim_names_for_scopes("openid"), vec!["sub"]);
    }

    #[test]
    fn unknown_scopes_ignored() {
        assert_eq!(claim_names_for_scopes("openid bogus foobar"), vec!["sub"]);
    }

    #[test]
    fn profile_email_release_their_claims() {
        let p = claim_names_for_scopes("openid profile");
        assert!(p.contains(&"sub") && p.contains(&"name") && p.contains(&"birthdate"));
        assert!(!p.contains(&"email")); // email scope 無しでは出さない
        let e = claim_names_for_scopes("openid email");
        assert!(e.contains(&"email") && e.contains(&"email_verified"));
        assert!(!e.contains(&"name"));
    }

    #[test]
    fn all_scopes_union_is_superset_and_has_no_leak_beyond_supported() {
        let all = claim_names_for_scopes("openid profile email address phone");
        for c in [
            "sub", "name", "email", "email_verified", "address", "phone_number",
            "phone_number_verified",
        ] {
            assert!(all.contains(&c), "missing {c}");
        }
        // 解放集合は discovery の claims_supported に収まる（漏洩なし）。
        let supported = all_supported_claims();
        for c in &all {
            assert!(supported.contains(c), "{c} not in claims_supported");
        }
    }
}
