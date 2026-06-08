//! Store トレイトの Firestore 実装。ゼロスケールでもインスタンス跨ぎで
//! セッション/コード/トークンを永続化する（TS の FirestoreAdapter 相当）。
//! interactions / sessions / authCodes / accessTokens / refreshTokens を保存。
//! find_account は static（accounts/{email} は別 collection で registration.rs が管理）。

use crate::firestore::{self as fs_h, Firestore};
use crate::model::*;
use crate::store::Store;
use async_trait::async_trait;
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

const INTERACTION_TTL: u64 = 3600;
const SESSION_TTL: u64 = 7 * 24 * 3600;
const ACCESS_TTL: u64 = 900;
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

    /// updateTime CAS で単回削除する。削除に成功（=この呼び出しが初回）したら削除直前の
    /// fields を返す。並行リクエスト/リプレイでは高々 1 回だけ Some を返す（未存在/負け/Err は
    /// None）。単回消費（RT ローテーション / interaction 消費）の唯一の原始操作。
    async fn cas_take(&self, col: &str, id: &str) -> Option<Value> {
        let (f, update_time) = self.fs.get_doc_with_update_time(col, id).await.ok()??;
        match self.fs.delete_doc_if_unchanged(col, id, &update_time).await {
            Ok(true) => Some(f),
            _ => None,
        }
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
        if let Some(ru) = &i.request_uri {
            f["requestUri"] = fs_h::s(ru);
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
            request_uri: fs_h::field_str(&f, "requestUri").map(str::to_string),
        })
    }

    async fn consume_interaction(&self, uid: &str) -> bool {
        // updateTime CAS で単回削除（並行 resume / リプレイで高々 1 回だけ成功）。
        self.cas_take("interactions", uid).await.is_some()
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
            // 再利用検出用。消費後も削除せず used=true にし、発行トークンを紐付ける。
            "used": fs_h::b(false),
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
        if let Some(v) = &c.dpop_jkt {
            f["dpopJkt"] = fs_h::s(v);
        }
        if let Some(v) = &c.resource {
            f["resource"] = fs_h::s(v);
        }
        let _ = self.fs.set_doc("authCodes", &c.code, f).await;
    }

    async fn take_code(&self, code: &str) -> Option<AuthorizationCode> {
        // updateTime CAS で単回消費を原子化する。get→write の間に別リクエストが消費した
        // 場合は CAS が負け、二重発行を防ぐ（consume_mandate_if_unused / CIBA と同型）。
        let (mut f, update_time) =
            self.fs.get_doc_with_update_time("authCodes", code).await.ok()??;
        let used = f
            .get("used")
            .and_then(|v| v.get("booleanValue"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if used {
            // 再利用: このコードで発行したトークンを失効させ拒否する（RFC 6749 §4.1.2）。
            if let Some(at) = fs_h::field_str(&f, "issuedAccessToken") {
                let _ = self.fs.delete_doc("accessTokens", at).await;
            }
            if let Some(rt) = fs_h::field_str(&f, "issuedRefreshToken") {
                let _ = self.fs.delete_doc("refreshTokens", rt).await;
            }
            return None;
        }
        // 初回消費: used=true を CAS で書く。並行消費に負けたら（Ok(false)/Err）None を返す。
        f["used"] = fs_h::b(true);
        match self.fs.set_doc_if_unchanged("authCodes", code, f.clone(), &update_time).await {
            Ok(true) => {}
            _ => return None,
        }
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
            dpop_jkt: fs_h::field_str(&f, "dpopJkt").map(str::to_string),
            resource: fs_h::field_str(&f, "resource").map(str::to_string),
            expires_at: fs_h::field_ts_secs(&f, "expiresAt").unwrap_or(0),
        })
    }

    async fn link_issued_tokens(&self, code: &str, access_token: &str, refresh_token: Option<&str>) {
        let mut f = json!({ "issuedAccessToken": fs_h::s(access_token) });
        if let Some(rt) = refresh_token {
            f["issuedRefreshToken"] = fs_h::s(rt);
        }
        let _ = self.fs.merge_doc("authCodes", code, f).await;
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
        if let Some(aud) = &t.aud {
            f["aud"] = fs_h::s(aud);
        }
        if let Some(acr) = &t.acr {
            f["acr"] = fs_h::s(acr);
        }
        if let Some(at) = t.auth_time {
            f["authTime"] = fs_h::int(at);
        }
        if let Some(ad) = &t.authorization_details {
            f["authorizationDetails"] = fs_h::s(ad);
        }
        if t.mandate_consumed {
            f["mandateConsumed"] = fs_h::b(true);
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
            aud: fs_h::field_str(&f, "aud").map(str::to_string),
            acr: fs_h::field_str(&f, "acr").map(str::to_string),
            auth_time: fs_h::field_u64(&f, "authTime"),
            authorization_details: fs_h::field_str(&f, "authorizationDetails")
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            mandate_consumed: fs_h::field_bool(&f, "mandateConsumed").unwrap_or(false),
        })
    }

    async fn revoke_access_token(&self, token: &str) {
        let _ = self.fs.delete_doc("accessTokens", token).await;
    }

    /// updateTime CAS で mandate_consumed: false → true を 1 回だけ成功させる。
    async fn consume_mandate_if_unused(&self, token: &str) -> Result<bool, String> {
        let (mut f, update_time) = match self
            .fs
            .get_doc_with_update_time("accessTokens", token)
            .await?
        {
            Some(x) => x,
            None => return Ok(false),
        };
        if doc_expired(&f) {
            return Ok(false);
        }
        if fs_h::field_bool(&f, "mandateConsumed").unwrap_or(false) {
            return Ok(false);
        }
        f["mandateConsumed"] = fs_h::b(true);
        self.fs
            .set_doc_if_unchanged("accessTokens", token, f, &update_time)
            .await
    }

    async fn save_refresh_token(&self, t: RefreshToken) {
        let mut f = json!({
            "clientId": fs_h::s(&t.client_id),
            "accountId": fs_h::s(&t.account_id),
            "scope": fs_h::s(&t.scope),
            "expiresAt": fs_h::ts(&fs_h::rfc3339(now() + REFRESH_TTL)),
        });
        if let Some(r) = &t.resource {
            f["resource"] = fs_h::s(r);
        }
        if let Some(acr) = &t.acr {
            f["acr"] = fs_h::s(acr);
        }
        if let Some(at) = t.auth_time {
            f["authTime"] = fs_h::int(at);
        }
        let _ = self.fs.set_doc("refreshTokens", &t.token, f).await;
    }

    async fn take_refresh_token(&self, token: &str) -> Option<RefreshToken> {
        // 使用時ローテーション = CAS で単回消費。get_doc + 無条件 delete だと同一 RT の並行
        // リクエストが両方 Some を得て二重発行する（cas_take が単回性を保証）。
        // 不変量: 同一 token への take_refresh_token が Some を返すのは高々 1 回。
        let f = self.cas_take("refreshTokens", token).await?;
        if doc_expired(&f) {
            return None;
        }
        Some(RefreshToken {
            token: token.to_string(),
            client_id: fs_h::field_str(&f, "clientId").unwrap_or("").to_string(),
            account_id: fs_h::field_str(&f, "accountId").unwrap_or("").to_string(),
            scope: fs_h::field_str(&f, "scope").unwrap_or("").to_string(),
            resource: fs_h::field_str(&f, "resource").map(str::to_string),
            acr: fs_h::field_str(&f, "acr").map(str::to_string),
            auth_time: fs_h::field_u64(&f, "authTime"),
        })
    }

    async fn get_refresh_token(&self, token: &str) -> Option<RefreshToken> {
        let f = self.fs.get_doc("refreshTokens", token).await.ok()??;
        if doc_expired(&f) {
            return None;
        }
        Some(RefreshToken {
            token: token.to_string(),
            client_id: fs_h::field_str(&f, "clientId").unwrap_or("").to_string(),
            account_id: fs_h::field_str(&f, "accountId").unwrap_or("").to_string(),
            scope: fs_h::field_str(&f, "scope").unwrap_or("").to_string(),
            resource: fs_h::field_str(&f, "resource").map(str::to_string),
            acr: fs_h::field_str(&f, "acr").map(str::to_string),
            auth_time: fs_h::field_u64(&f, "authTime"),
        })
    }

    async fn revoke_refresh_token(&self, token: &str) {
        let _ = self.fs.delete_doc("refreshTokens", token).await;
    }

    async fn find_account(&self, sub: &str) -> Account {
        // 保存済みの編集可能 claim（profiles/{email}）。未保存なら空。
        let saved = crate::registration::get_profile(&self.fs, sub)
            .await
            .unwrap_or_default();
        // 実データ（sub / email / email_verified / 保存済み編集 claim）のみを返す。
        // 未設定 claim はダミーで埋めず欠落させる（OP は“真の属性”だけを主張する）。
        let mut claims: HashMap<String, Value> = HashMap::new();
        claims.insert("sub".to_string(), json!(sub));
        if sub.contains('@') {
            claims.insert("email".to_string(), json!(sub));
            // 登録時にメール確認を経ている（registration の email-challenge/verify）。
            claims.insert("email_verified".to_string(), json!(true));
        }
        for (k, v) in saved {
            claims.insert(k, json!(v));
        }
        Account { sub: sub.to_string(), claims }
    }
}
