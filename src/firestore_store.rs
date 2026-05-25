//! Store トレイトの Firestore 実装。ゼロスケールでもインスタンス跨ぎで
//! セッション/コード/トークンを永続化する（TS の FirestoreAdapter 相当）。
//! interactions / sessions / authCodes / accessTokens / refreshTokens を保存。
//! find_account は static（accounts/{email} は別 collection で registration.rs が管理）。

use crate::firestore::{self as fs_h, Firestore};
use crate::model::*;
use crate::store::{account_for, Store};
use async_trait::async_trait;
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const INTERACTION_TTL: u64 = 3600;
const SESSION_TTL: u64 = 7 * 24 * 3600;
const ACCESS_TTL: u64 = 3600;
const REFRESH_TTL: u64 = 14 * 24 * 3600;

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn doc_expired(fields: &Value) -> bool {
    fs_h::field_ts_secs(fields, "expiresAt").unwrap_or(0) < now()
}

pub struct FirestoreStore {
    fs: Arc<Firestore>,
}

impl FirestoreStore {
    pub fn new(fs: Arc<Firestore>) -> Self {
        Self { fs }
    }
}

#[async_trait]
impl Store for FirestoreStore {
    async fn save_interaction(&self, i: Interaction) {
        let mut f = json!({
            "rawQuery": fs_h::s(&i.raw_query),
            "expiresAt": fs_h::ts(&fs_h::rfc3339(now() + INTERACTION_TTL)),
        });
        if let Some(a) = &i.account_id {
            f["accountId"] = fs_h::s(a);
        }
        if let Some(t) = i.auth_time {
            f["authTime"] = fs_h::int(t);
        }
        let _ = self.fs.set_doc("interactions", &i.uid, f).await;
    }

    async fn get_interaction(&self, uid: &str) -> Option<Interaction> {
        let f = self.fs.get_doc("interactions", uid).await.ok()??;
        if doc_expired(&f) {
            return None;
        }
        Some(Interaction {
            uid: uid.to_string(),
            raw_query: fs_h::field_str(&f, "rawQuery").unwrap_or("").to_string(),
            account_id: fs_h::field_str(&f, "accountId").map(str::to_string),
            auth_time: fs_h::field_u64(&f, "authTime"),
        })
    }

    async fn save_session(&self, s: Session) {
        let f = json!({
            "accountId": fs_h::s(&s.account_id),
            "authTime": fs_h::int(s.auth_time),
            "expiresAt": fs_h::ts(&fs_h::rfc3339(now() + SESSION_TTL)),
        });
        let _ = self.fs.set_doc("sessions", &s.sid, f).await;
    }

    async fn get_session(&self, sid: &str) -> Option<Session> {
        let f = self.fs.get_doc("sessions", sid).await.ok()??;
        if doc_expired(&f) {
            return None;
        }
        Some(Session {
            sid: sid.to_string(),
            account_id: fs_h::field_str(&f, "accountId").unwrap_or("").to_string(),
            auth_time: fs_h::field_u64(&f, "authTime").unwrap_or(0),
        })
    }

    async fn delete_session(&self, sid: &str) {
        let _ = self.fs.delete_doc("sessions", sid).await;
    }

    async fn save_code(&self, c: AuthorizationCode) {
        let mut f = json!({
            "clientId": fs_h::s(&c.client_id),
            "accountId": fs_h::s(&c.account_id),
            "redirectUri": fs_h::s(&c.redirect_uri),
            "scope": fs_h::s(&c.scope),
            "authTime": fs_h::int(c.auth_time),
            "expiresAt": fs_h::ts(&fs_h::rfc3339(c.expires_at)),
        });
        if let Some(v) = &c.nonce {
            f["nonce"] = fs_h::s(v);
        }
        if let Some(v) = &c.code_challenge {
            f["codeChallenge"] = fs_h::s(v);
        }
        if let Some(v) = &c.code_challenge_method {
            f["codeChallengeMethod"] = fs_h::s(v);
        }
        if let Some(v) = &c.acr {
            f["acr"] = fs_h::s(v);
        }
        let _ = self.fs.set_doc("authCodes", &c.code, f).await;
    }

    async fn take_code(&self, code: &str) -> Option<AuthorizationCode> {
        let f = self.fs.get_doc("authCodes", code).await.ok()??;
        let _ = self.fs.delete_doc("authCodes", code).await;
        // 期限チェックは grant 側（code.expires_at）。ここでは復元のみ。
        Some(AuthorizationCode {
            code: code.to_string(),
            client_id: fs_h::field_str(&f, "clientId").unwrap_or("").to_string(),
            account_id: fs_h::field_str(&f, "accountId").unwrap_or("").to_string(),
            redirect_uri: fs_h::field_str(&f, "redirectUri").unwrap_or("").to_string(),
            scope: fs_h::field_str(&f, "scope").unwrap_or("").to_string(),
            nonce: fs_h::field_str(&f, "nonce").map(str::to_string),
            code_challenge: fs_h::field_str(&f, "codeChallenge").map(str::to_string),
            code_challenge_method: fs_h::field_str(&f, "codeChallengeMethod").map(str::to_string),
            auth_time: fs_h::field_u64(&f, "authTime").unwrap_or(0),
            acr: fs_h::field_str(&f, "acr").map(str::to_string),
            expires_at: fs_h::field_ts_secs(&f, "expiresAt").unwrap_or(0),
        })
    }

    async fn save_access_token(&self, t: AccessToken) {
        let mut f = json!({
            "clientId": fs_h::s(&t.client_id),
            "accountId": fs_h::s(&t.account_id),
            "scope": fs_h::s(&t.scope),
            "expiresAt": fs_h::ts(&fs_h::rfc3339(now() + ACCESS_TTL)),
        });
        if let Some(jkt) = &t.jkt {
            f["jkt"] = fs_h::s(jkt);
        }
        let _ = self.fs.set_doc("accessTokens", &t.token, f).await;
    }

    async fn get_access_token(&self, token: &str) -> Option<AccessToken> {
        let f = self.fs.get_doc("accessTokens", token).await.ok()??;
        if doc_expired(&f) {
            return None;
        }
        Some(AccessToken {
            token: token.to_string(),
            client_id: fs_h::field_str(&f, "clientId").unwrap_or("").to_string(),
            account_id: fs_h::field_str(&f, "accountId").unwrap_or("").to_string(),
            scope: fs_h::field_str(&f, "scope").unwrap_or("").to_string(),
            jkt: fs_h::field_str(&f, "jkt").map(str::to_string),
        })
    }

    async fn save_refresh_token(&self, t: RefreshToken) {
        let f = json!({
            "clientId": fs_h::s(&t.client_id),
            "accountId": fs_h::s(&t.account_id),
            "scope": fs_h::s(&t.scope),
            "expiresAt": fs_h::ts(&fs_h::rfc3339(now() + REFRESH_TTL)),
        });
        let _ = self.fs.set_doc("refreshTokens", &t.token, f).await;
    }

    async fn take_refresh_token(&self, token: &str) -> Option<RefreshToken> {
        let f = self.fs.get_doc("refreshTokens", token).await.ok()??;
        let _ = self.fs.delete_doc("refreshTokens", token).await;
        if doc_expired(&f) {
            return None;
        }
        Some(RefreshToken {
            token: token.to_string(),
            client_id: fs_h::field_str(&f, "clientId").unwrap_or("").to_string(),
            account_id: fs_h::field_str(&f, "accountId").unwrap_or("").to_string(),
            scope: fs_h::field_str(&f, "scope").unwrap_or("").to_string(),
        })
    }

    async fn find_account(&self, sub: &str) -> Account {
        // 静的デフォルトの上に、ユーザーが保存した編集可能 claim を重ねる。
        let mut account = account_for(sub);
        if let Ok(profile) = crate::registration::get_profile(&*self.fs, sub).await {
            for (k, v) in profile {
                account.claims.insert(k, json!(v));
            }
        }
        account
    }
}
