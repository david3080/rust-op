//! 永続化の概念トレイト（node-oidc-provider の Adapter 相当）と In-memory 実装。
//! Firestore 等に差し替える時はこの trait の別 impl を 1 個書くだけ。

use crate::model::*;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;

#[async_trait]
pub trait Store: Send + Sync {
    async fn save_interaction(&self, i: Interaction);
    async fn get_interaction(&self, uid: &str) -> Option<Interaction>;
    /// interaction を単回消費（削除）する。削除に成功（=この呼び出しが初回）したら true、
    /// 既に無い（消費済み/未存在）なら false。authorize_resume で「1認証=1コード」を保証する。
    async fn consume_interaction(&self, uid: &str) -> bool;

    async fn save_session(&self, s: Session);
    async fn get_session(&self, sid: &str) -> Option<Session>;
    async fn delete_session(&self, sid: &str);

    async fn save_code(&self, c: AuthorizationCode);
    /// 認可コードを消費する。初回は使用済みマークして返す。
    /// 再利用（既に使用済み）を検出したら、そのコードで発行したトークンを失効させ None を返す
    /// （RFC 6749 §4.1.2: コード再利用時は発行済みトークンを revoke すべき）。
    async fn take_code(&self, code: &str) -> Option<AuthorizationCode>;
    /// 発行した access/refresh token をコードに紐付ける（再利用時の失効対象を記録）。
    async fn link_issued_tokens(&self, code: &str, access_token: &str, refresh_token: Option<&str>);

    async fn save_access_token(&self, t: AccessToken);
    async fn get_access_token(&self, token: &str) -> Option<AccessToken>;
    /// アクセストークンを失効（削除）する（RFC 7009）。未知でも no-op。
    async fn revoke_access_token(&self, token: &str);
    /// mandate の単回消費。`mandate_consumed: false → true` を CAS で 1 回だけ成功させる。
    /// 成功: Ok(true)、既消費/無効トークン: Ok(false)。
    async fn consume_mandate_if_unused(&self, token: &str) -> Result<bool, String>;

    async fn save_refresh_token(&self, t: RefreshToken);
    /// 消費せず参照する（失効時の所有者確認用・再利用検知の used 判定用）。
    async fn get_refresh_token(&self, token: &str) -> Option<RefreshToken>;
    /// リフレッシュトークンを失効（削除）する（RFC 7009）。未知でも no-op。
    async fn revoke_refresh_token(&self, token: &str);
    /// ローテーション消費（OAuth Security BCP 再利用検知）: `used=false` の RT を `used=true`
    /// にし `replaced_by` を記録する CAS。この呼び出しが初めて used 化したら true（=ローテーション
    /// 成功）、既に used or 競合敗北 or 未存在なら false。delete でなく used マークで残すことで、
    /// 後の再提示を「再利用」として検知できる。
    async fn mark_refresh_used(&self, token: &str, replaced_by: Option<&str>) -> bool;
    /// 再利用検知時に系列を失効する。start から `replaced_by` を辿り各 RT を削除する
    /// （盗難者・正規ユーザ双方の RT を無効化＝再認証を強制）。
    async fn revoke_refresh_family(&self, start_token: &str);

    /// sub からアカウントを解決。未登録なら自動生成する（PoC 用）。
    async fn find_account(&self, sub: &str) -> Account;
}

/// MemoryStore 内部のコード記録。使用済みフラグと発行トークンを保持し、再利用失効に使う。
struct CodeRecord {
    code: AuthorizationCode,
    used: bool,
    issued_access: Option<String>,
    issued_refresh: Option<String>,
}

#[derive(Default)]
pub struct MemoryStore {
    interactions: Mutex<HashMap<String, Interaction>>,
    sessions: Mutex<HashMap<String, Session>>,
    codes: Mutex<HashMap<String, CodeRecord>>,
    access_tokens: Mutex<HashMap<String, AccessToken>>,
    refresh_tokens: Mutex<HashMap<String, RefreshToken>>,
}

#[async_trait]
impl Store for MemoryStore {
    async fn save_interaction(&self, i: Interaction) {
        self.interactions.lock().unwrap().insert(i.uid.clone(), i);
    }
    async fn get_interaction(&self, uid: &str) -> Option<Interaction> {
        self.interactions.lock().unwrap().get(uid).cloned()
    }
    async fn consume_interaction(&self, uid: &str) -> bool {
        self.interactions.lock().unwrap().remove(uid).is_some()
    }
    async fn save_session(&self, s: Session) {
        self.sessions.lock().unwrap().insert(s.sid.clone(), s);
    }
    async fn get_session(&self, sid: &str) -> Option<Session> {
        self.sessions.lock().unwrap().get(sid).cloned()
    }
    async fn delete_session(&self, sid: &str) {
        self.sessions.lock().unwrap().remove(sid);
    }
    async fn save_code(&self, c: AuthorizationCode) {
        self.codes.lock().unwrap().insert(
            c.code.clone(),
            CodeRecord { code: c, used: false, issued_access: None, issued_refresh: None },
        );
    }
    async fn take_code(&self, code: &str) -> Option<AuthorizationCode> {
        // 失効対象を lock 内で収集し、lock 解放後にトークンマップを触る（ロック順序固定）。
        let revoke = {
            let mut codes = self.codes.lock().unwrap();
            let rec = codes.get_mut(code)?;
            if rec.used {
                let r = (rec.issued_access.take(), rec.issued_refresh.take());
                Some(r)
            } else {
                rec.used = true;
                return Some(rec.code.clone());
            }
        };
        if let Some((at, rt)) = revoke {
            if let Some(at) = at {
                self.access_tokens.lock().unwrap().remove(&at);
            }
            if let Some(rt) = rt {
                self.refresh_tokens.lock().unwrap().remove(&rt);
            }
        }
        None
    }
    async fn link_issued_tokens(&self, code: &str, access_token: &str, refresh_token: Option<&str>) {
        if let Some(rec) = self.codes.lock().unwrap().get_mut(code) {
            rec.issued_access = Some(access_token.to_string());
            rec.issued_refresh = refresh_token.map(str::to_string);
        }
    }
    async fn save_access_token(&self, t: AccessToken) {
        self.access_tokens.lock().unwrap().insert(t.token.clone(), t);
    }
    async fn get_access_token(&self, token: &str) -> Option<AccessToken> {
        self.access_tokens.lock().unwrap().get(token).cloned()
    }
    async fn revoke_access_token(&self, token: &str) {
        self.access_tokens.lock().unwrap().remove(token);
    }
    async fn consume_mandate_if_unused(&self, token: &str) -> Result<bool, String> {
        let mut map = self.access_tokens.lock().unwrap();
        match map.get_mut(token) {
            Some(at) if !at.mandate_consumed => {
                at.mandate_consumed = true;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    async fn save_refresh_token(&self, t: RefreshToken) {
        self.refresh_tokens.lock().unwrap().insert(t.token.clone(), t);
    }
    async fn get_refresh_token(&self, token: &str) -> Option<RefreshToken> {
        self.refresh_tokens.lock().unwrap().get(token).cloned()
    }
    async fn revoke_refresh_token(&self, token: &str) {
        self.refresh_tokens.lock().unwrap().remove(token);
    }
    async fn mark_refresh_used(&self, token: &str, replaced_by: Option<&str>) -> bool {
        let mut map = self.refresh_tokens.lock().unwrap();
        match map.get_mut(token) {
            Some(rt) if !rt.used => {
                rt.used = true;
                rt.replaced_by = replaced_by.map(str::to_string);
                true
            }
            _ => false,
        }
    }
    async fn revoke_refresh_family(&self, start_token: &str) {
        let mut map = self.refresh_tokens.lock().unwrap();
        let mut cur = Some(start_token.to_string());
        let mut guard = 0;
        while let Some(t) = cur {
            guard += 1;
            if guard > 64 {
                break; // 系列長の安全上限（壊れた replaced_by ループ対策）
            }
            cur = map.remove(&t).and_then(|rt| rt.replaced_by);
        }
    }
    async fn find_account(&self, sub: &str) -> Account {
        account_for(sub)
    }
}

/// sub から標準 claim 一式を持つ Account を生成（PoC のダミー値）。
/// MemoryStore / FirestoreStore 共通。claim の scope 絞りは userinfo 側で行う。
pub fn account_for(sub: &str) -> Account {
    let email = if sub.contains('@') {
        sub.to_string()
    } else {
        format!("{sub}@example.com")
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut claims = HashMap::new();
    let mut put = |k: &str, v: serde_json::Value| {
        claims.insert(k.to_string(), v);
    };
    put("sub", serde_json::json!(sub));
    put("name", serde_json::json!(sub));
    put("given_name", serde_json::json!(sub));
    put("family_name", serde_json::json!("User"));
    put("middle_name", serde_json::json!("Test"));
    put("nickname", serde_json::json!(sub));
    put("preferred_username", serde_json::json!(sub));
    put("profile", serde_json::json!(format!("https://example.com/u/{sub}")));
    put("picture", serde_json::json!("https://example.com/avatar.png"));
    put("website", serde_json::json!("https://example.com"));
    put("gender", serde_json::json!("other"));
    put("birthdate", serde_json::json!("2000-01-01"));
    put("zoneinfo", serde_json::json!("Asia/Tokyo"));
    put("locale", serde_json::json!("ja-JP"));
    put("updated_at", serde_json::json!(now));
    put("email", serde_json::json!(email));
    put("email_verified", serde_json::json!(true));
    put(
        "address",
        serde_json::json!({
            "formatted": "Tokyo, Japan",
            "country": "JP",
            "locality": "Tokyo",
            "postal_code": "100-0001",
        }),
    );
    put("phone_number", serde_json::json!("+81-3-0000-0000"));
    put("phone_number_verified", serde_json::json!(false));
    Account { sub: sub.to_string(), claims }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(c: &str) -> AuthorizationCode {
        AuthorizationCode {
            code: c.into(),
            client_id: "cl".into(),
            account_id: "a".into(),
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

    fn at(t: &str) -> AccessToken {
        AccessToken { token: t.into(), client_id: "cl".into(), account_id: "a".into(), scope: "openid".into(), jkt: None, aud: None, acr: None, auth_time: None, authorization_details: None, mandate_consumed: false }
    }

    #[tokio::test]
    async fn consume_mandate_is_single_use() {
        let s = MemoryStore::default();
        s.save_access_token(at("AT1")).await;
        // 初回成功、2 回目以降は失敗（先勝ち）。
        assert!(s.consume_mandate_if_unused("AT1").await.unwrap());
        assert!(!s.consume_mandate_if_unused("AT1").await.unwrap());
        // 未知トークンも false。
        assert!(!s.consume_mandate_if_unused("UNKNOWN").await.unwrap());
        // 消費フラグが永続化されている。
        assert!(s.get_access_token("AT1").await.unwrap().mandate_consumed);
    }

    #[tokio::test]
    async fn code_reuse_revokes_issued_tokens() {
        let s = MemoryStore::default();
        s.save_code(code("C1")).await;
        s.save_access_token(at("AT1")).await;
        s.save_refresh_token(RefreshToken { token: "RT1".into(), client_id: "cl".into(), account_id: "a".into(), scope: "openid".into(), resource: None, jkt: None, acr: None, auth_time: None, family_id: "fam1".into(), used: false, replaced_by: None }).await;
        s.link_issued_tokens("C1", "AT1", Some("RT1")).await;

        // 初回消費は成功し、発行トークンは生きている。
        assert!(s.take_code("C1").await.is_some());
        assert!(s.get_access_token("AT1").await.is_some());

        // 再利用は拒否（None）され、発行済みトークンが失効する。
        assert!(s.take_code("C1").await.is_none());
        assert!(s.get_access_token("AT1").await.is_none());
        assert!(s.get_refresh_token("RT1").await.is_none());
    }

    #[tokio::test]
    async fn unknown_code_returns_none() {
        let s = MemoryStore::default();
        assert!(s.take_code("nope").await.is_none());
    }

    #[tokio::test]
    async fn revoke_access_token_removes_it() {
        let s = MemoryStore::default();
        s.save_access_token(at("AT1")).await;
        assert!(s.get_access_token("AT1").await.is_some());
        s.revoke_access_token("AT1").await;
        assert!(s.get_access_token("AT1").await.is_none());
        // 未知トークンの失効は no-op（パニックしない）。
        s.revoke_access_token("nope").await;
    }

    #[tokio::test]
    async fn get_refresh_token_peeks_without_consuming() {
        let s = MemoryStore::default();
        s.save_refresh_token(RefreshToken { token: "RT1".into(), client_id: "cl".into(), account_id: "a".into(), scope: "openid".into(), resource: None, jkt: None, acr: None, auth_time: None, family_id: "fam1".into(), used: false, replaced_by: None }).await;
        // peek は消費しない。
        assert!(s.get_refresh_token("RT1").await.is_some());
        assert!(s.get_refresh_token("RT1").await.is_some());
        // revoke で消える。
        s.revoke_refresh_token("RT1").await;
        assert!(s.get_refresh_token("RT1").await.is_none());
    }

    #[tokio::test]
    async fn consume_interaction_is_single_use() {
        let s = MemoryStore::default();
        s.save_interaction(Interaction {
            uid: "U1".into(),
            raw_query: String::new(),
            account_id: Some("a".into()),
            auth_time: None,
            request_uri: None,
        })
        .await;
        assert!(s.consume_interaction("U1").await); // 初回: 消費成功
        assert!(!s.consume_interaction("U1").await); // 2回目: 既に無い（リプレイ拒否）
        assert!(!s.consume_interaction("nope").await); // 未知も false
    }
}
