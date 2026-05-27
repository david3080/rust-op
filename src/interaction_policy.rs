//! prompt / max_age を解釈して「ログイン画面を出すか / 既存セッションで進むか /
//! エラーを返すか」を決める。node-oidc-provider の interaction policy 相当。
//!
//! prompt は有限の取りうる値なので enum で表す（state を enum で、の方針）。

use crate::error::OAuthError;
use crate::model::{AuthParams, Session};

#[derive(Debug, PartialEq)]
pub enum Prompt {
    None,
    Login,
    Consent,
    SelectAccount,
}

impl Prompt {
    /// prompt パラメータ（空白区切り）を enum 集合に解釈する。未知値は無視。
    pub fn parse_set(prompt: Option<&str>) -> Vec<Prompt> {
        prompt
            .unwrap_or("")
            .split_whitespace()
            .filter_map(|s| match s {
                "none" => Some(Prompt::None),
                "login" => Some(Prompt::Login),
                "consent" => Some(Prompt::Consent),
                "select_account" => Some(Prompt::SelectAccount),
                _ => None,
            })
            .collect()
    }
}

/// authorize がログイン段階で取りうる結果。
pub enum AuthDecision {
    /// 既存セッションで認証済みとして進む。
    UseSession { account_id: String, auth_time: u64 },
    /// ログイン画面を出す（再認証含む）。
    Login,
    /// リダイレクトでエラーを返す（prompt=none で未認証など）。
    Error(OAuthError),
}

/// セッションが max_age を満たすか（指定なしは常に有効）。
fn fresh_enough(session: &Session, max_age: Option<u64>, now: u64) -> bool {
    match max_age {
        Some(ma) => now.saturating_sub(session.auth_time) <= ma,
        None => true,
    }
}

pub fn decide(params: &AuthParams, session: Option<&Session>, now: u64) -> AuthDecision {
    let prompts = Prompt::parse_set(params.prompt.as_deref());
    let want_none = prompts.contains(&Prompt::None);
    let want_login = prompts.contains(&Prompt::Login);
    let max_age = params.max_age.as_deref().and_then(|s| s.parse::<u64>().ok());

    // prompt=none は他の値と併用不可 (OIDC Core 3.1.2.1)。
    if want_none && prompts.len() > 1 {
        return AuthDecision::Error(OAuthError::InvalidRequest(
            "prompt=none must not be combined with other values".into(),
        ));
    }

    if want_none {
        // UI を一切出してはいけない。有効なセッションが無ければ login_required。
        return match session {
            Some(s) if fresh_enough(s, max_age, now) => AuthDecision::UseSession {
                account_id: s.account_id.clone(),
                auth_time: s.auth_time,
            },
            _ => AuthDecision::Error(OAuthError::LoginRequired(
                "no active session for prompt=none".into(),
            )),
        };
    }

    // prompt=login、または max_age 超過なら強制再認証。
    if want_login {
        return AuthDecision::Login;
    }
    match session {
        Some(s) if fresh_enough(s, max_age, now) => AuthDecision::UseSession {
            account_id: s.account_id.clone(),
            auth_time: s.auth_time,
        },
        _ => AuthDecision::Login,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn params(prompt: Option<&str>, max_age: Option<&str>) -> AuthParams {
        AuthParams {
            client_id: Some("c".into()),
            redirect_uri: None,
            response_type: Some("code".into()),
            scope: Some("openid".into()),
            state: None,
            nonce: None,
            prompt: prompt.map(str::to_string),
            max_age: max_age.map(str::to_string),
            acr_values: None,
            response_mode: None,
            code_challenge: None,
            code_challenge_method: None,
            dpop_jkt: None,
            resource: None,
        }
    }

    fn session(auth_time: u64) -> Session {
        Session { sid: "sid".into(), account_id: "alice".into(), auth_time }
    }

    #[test]
    fn parse_set_ignores_unknown_and_collects_known() {
        let got = Prompt::parse_set(Some("login consent bogus none"));
        assert!(got.contains(&Prompt::Login));
        assert!(got.contains(&Prompt::Consent));
        assert!(got.contains(&Prompt::None));
        assert_eq!(got.len(), 3); // bogus は無視
    }

    #[test]
    fn parse_set_empty_when_absent() {
        assert!(Prompt::parse_set(None).is_empty());
    }

    #[test]
    fn no_session_no_prompt_shows_login() {
        assert!(matches!(decide(&params(None, None), None, 1000), AuthDecision::Login));
    }

    #[test]
    fn fresh_session_reused() {
        let s = session(1000);
        match decide(&params(None, None), Some(&s), 1500) {
            AuthDecision::UseSession { account_id, auth_time } => {
                assert_eq!(account_id, "alice");
                assert_eq!(auth_time, 1000);
            }
            _ => panic!("expected UseSession"),
        }
    }

    #[test]
    fn prompt_login_forces_reauth_even_with_session() {
        let s = session(1000);
        assert!(matches!(decide(&params(Some("login"), None), Some(&s), 1001), AuthDecision::Login));
    }

    #[test]
    fn prompt_none_without_session_is_login_required() {
        match decide(&params(Some("none"), None), None, 1000) {
            AuthDecision::Error(OAuthError::LoginRequired(_)) => {}
            _ => panic!("expected LoginRequired"),
        }
    }

    #[test]
    fn prompt_none_with_fresh_session_uses_it() {
        let s = session(1000);
        assert!(matches!(
            decide(&params(Some("none"), None), Some(&s), 1100),
            AuthDecision::UseSession { .. }
        ));
    }

    #[test]
    fn prompt_none_combined_with_others_is_invalid_request() {
        match decide(&params(Some("none login"), None), None, 1000) {
            AuthDecision::Error(OAuthError::InvalidRequest(_)) => {}
            _ => panic!("expected InvalidRequest"),
        }
    }

    #[test]
    fn max_age_exceeded_forces_login() {
        let s = session(1000);
        // now - auth_time = 200 > max_age 100
        assert!(matches!(decide(&params(None, Some("100")), Some(&s), 1200), AuthDecision::Login));
    }

    #[test]
    fn max_age_within_window_reuses_session() {
        let s = session(1000);
        assert!(matches!(
            decide(&params(None, Some("100")), Some(&s), 1050),
            AuthDecision::UseSession { .. }
        ));
    }

    #[test]
    fn prompt_none_with_stale_session_is_login_required() {
        let s = session(1000);
        // max_age 10 を超過 → prompt=none では UI を出せず login_required
        match decide(&params(Some("none"), Some("10")), Some(&s), 1100) {
            AuthDecision::Error(OAuthError::LoginRequired(_)) => {}
            _ => panic!("expected LoginRequired"),
        }
    }
}
