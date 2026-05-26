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

    async fn save_refresh_token(&self, t: RefreshToken);
    /// リフレッシュトークンは使用時にローテーション（取得と同時に削除）。
    async fn take_refresh_token(&self, token: &str) -> Option<RefreshToken>;

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
    async fn save_refresh_token(&self, t: RefreshToken) {
        self.refresh_tokens.lock().unwrap().insert(t.token.clone(), t);
    }
    async fn take_refresh_token(&self, token: &str) -> Option<RefreshToken> {
        self.refresh_tokens.lock().unwrap().remove(token)
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
            expires_at: u64::MAX,
        }
    }

    fn at(t: &str) -> AccessToken {
        AccessToken { token: t.into(), client_id: "cl".into(), account_id: "a".into(), scope: "openid".into(), jkt: None }
    }

    #[tokio::test]
    async fn code_reuse_revokes_issued_tokens() {
        let s = MemoryStore::default();
        s.save_code(code("C1")).await;
        s.save_access_token(at("AT1")).await;
        s.save_refresh_token(RefreshToken { token: "RT1".into(), client_id: "cl".into(), account_id: "a".into(), scope: "openid".into() }).await;
        s.link_issued_tokens("C1", "AT1", Some("RT1")).await;

        // 初回消費は成功し、発行トークンは生きている。
        assert!(s.take_code("C1").await.is_some());
        assert!(s.get_access_token("AT1").await.is_some());

        // 再利用は拒否（None）され、発行済みトークンが失効する。
        assert!(s.take_code("C1").await.is_none());
        assert!(s.get_access_token("AT1").await.is_none());
        assert!(s.take_refresh_token("RT1").await.is_none());
    }

    #[tokio::test]
    async fn unknown_code_returns_none() {
        let s = MemoryStore::default();
        assert!(s.take_code("nope").await.is_none());
    }
}
