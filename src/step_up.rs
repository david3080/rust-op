//! OAuth 2.0 Step Up Authentication Challenge (RFC 9470)。
//!
//! リソースサーバ(RS)が「この操作にはより強い/新しいユーザー認証が必要」と判断したとき、
//! 401 とともに返す `WWW-Authenticate` チャレンジを組み立てる primitive。
//! OP 側(rust-op)はこのチャレンジを発行しない（acr_values/max_age を受けて authorize で
//! 再認証を行う側）。分離 RS がこの値を使ってクライアントに step-up を要求する。
//!
//! 例:
//! ```text
//! WWW-Authenticate: DPoP error="insufficient_user_authentication",
//!   error_description="...", acr_values="urn:...:bronze", max_age=300
//! ```

/// insufficient_user_authentication チャレンジの `WWW-Authenticate` ヘッダ値を作る。
/// scheme は "Bearer" か "DPoP"。acr_values は要求する acr（空/None は省略）、
/// max_age は要求する最大認証経過秒（None は省略）。文字列パラメータは quoted、
/// max_age は数値トークン（RFC 9470 の例に倣う）。
#[allow(dead_code)] // 分離 RS が使う primitive。OP 自身は発行しない。
pub fn insufficient_user_authentication(
    scheme: &str,
    acr_values: Option<&str>,
    max_age: Option<u64>,
) -> String {
    let mut s = format!(
        "{scheme} error=\"insufficient_user_authentication\", \
error_description=\"stronger or more recent user authentication is required\""
    );
    if let Some(a) = acr_values.filter(|a| !a.is_empty()) {
        s.push_str(&format!(", acr_values=\"{a}\""));
    }
    if let Some(m) = max_age {
        s.push_str(&format!(", max_age={m}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_minimal_challenge() {
        let h = insufficient_user_authentication("Bearer", None, None);
        assert!(h.starts_with("Bearer "));
        assert!(h.contains("error=\"insufficient_user_authentication\""));
        assert!(!h.contains("acr_values"));
        assert!(!h.contains("max_age"));
    }

    #[test]
    fn includes_acr_values_and_max_age() {
        let h = insufficient_user_authentication("DPoP", Some("urn:acr:bronze"), Some(300));
        assert!(h.starts_with("DPoP "));
        assert!(h.contains("acr_values=\"urn:acr:bronze\""));
        assert!(h.contains("max_age=300")); // 数値は quote しない
    }

    #[test]
    fn empty_acr_values_is_omitted() {
        let h = insufficient_user_authentication("Bearer", Some(""), None);
        assert!(!h.contains("acr_values"));
    }
}
