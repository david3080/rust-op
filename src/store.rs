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
    /// 認可コードは 1 回で消費（取得と同時に削除）。
    async fn take_code(&self, code: &str) -> Option<AuthorizationCode>;

    async fn save_access_token(&self, t: AccessToken);
    async fn get_access_token(&self, token: &str) -> Option<AccessToken>;

    async fn save_refresh_token(&self, t: RefreshToken);
    /// リフレッシュトークンは使用時にローテーション（取得と同時に削除）。
    async fn take_refresh_token(&self, token: &str) -> Option<RefreshToken>;

    /// sub からアカウントを解決。未登録なら自動生成する（PoC 用）。
    async fn find_account(&self, sub: &str) -> Account;
}

#[derive(Default)]
pub struct MemoryStore {
    interactions: Mutex<HashMap<String, Interaction>>,
    sessions: Mutex<HashMap<String, Session>>,
    codes: Mutex<HashMap<String, AuthorizationCode>>,
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
        self.codes.lock().unwrap().insert(c.code.clone(), c);
    }
    async fn take_code(&self, code: &str) -> Option<AuthorizationCode> {
        self.codes.lock().unwrap().remove(code)
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
