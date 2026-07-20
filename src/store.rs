//! 永続化の概念トレイト（node-oidc-provider の Adapter 相当）と In-memory 実装。
//! Firestore 等に差し替える時はこの trait の別 impl を 1 個書くだけ。

use crate::model::*;
use async_trait::async_trait;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// UNIX 秒。MemoryStore の期限判定に使う(grants 側の now() と同一基準)。
fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// レコード種別ごとの保持上限(UNIX 秒)。**全ストア実装が参照する唯一の定義**で、
/// FirestoreStore の expiresAt もここを使う。バックエンドごとに数値を書くと
/// 「片方だけ直して忘れる」ドリフトが起きるため、判断を 1 箇所に集約する。
///
/// これはストアの保持期間であって、トークン自体の有効期限(署名 JWT の exp や
/// AuthorizationCode::expires_at)とは別概念。前者は容量を守る番人、後者は
/// プロトコル上の失効。code は自身の expires_at を持つのでここには置かない。
pub const INTERACTION_TTL_SECS: u64 = 3600; // ログイン完了までの猶予(1時間)
pub const SESSION_TTL_SECS: u64 = 7 * 24 * 3600; // ブラウザセッション(7日)
pub const ACCESS_TTL_SECS: u64 = 900; // access token(15分、grants の expires_in と一致)
pub const REFRESH_TTL_SECS: u64 = 14 * 24 * 3600; // refresh token(14日)

/// 値に絶対失効時刻を添えるラッパー。expires_at(UNIX 秒)を過ぎたら失効とみなす。
struct Expiring<T> {
    value: T,
    expires_at: u64,
}
impl<T> Expiring<T> {
    fn new(value: T, expires_at: u64) -> Self {
        Expiring { value, expires_at }
    }
    fn alive(&self) -> bool {
        self.expires_at > now_secs()
    }
}

/// HashMap から期限切れエントリを物理削除する(active sweep の実体)。
fn retain_alive<K, V>(map: &mut HashMap<K, Expiring<V>>) {
    let cutoff = now_secs();
    map.retain(|_, e| e.expires_at > cutoff);
}

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

    /// 期限切れエントリを物理削除する(active sweep)。既定は no-op。
    /// In-memory 実装のみ意味を持つ(Firestore 等は TTL ポリシーで自己失効するため)。
    /// Provider の定期タスクが呼ぶ。
    async fn sweep_expired(&self) {}
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
    interactions: Mutex<HashMap<String, Expiring<Interaction>>>,
    sessions: Mutex<HashMap<String, Expiring<Session>>>,
    codes: Mutex<HashMap<String, Expiring<CodeRecord>>>,
    access_tokens: Mutex<HashMap<String, Expiring<AccessToken>>>,
    refresh_tokens: Mutex<HashMap<String, Expiring<RefreshToken>>>,
}



#[async_trait]
impl Store for MemoryStore {
    async fn save_interaction(&self, i: Interaction) {
        let exp = now_secs() + INTERACTION_TTL_SECS;
        self.interactions.lock().unwrap().insert(i.uid.clone(), Expiring::new(i, exp));
    }
    async fn get_interaction(&self, uid: &str) -> Option<Interaction> {
        let mut map = self.interactions.lock().unwrap();
        match map.get(uid) {
            Some(e) if e.alive() => Some(e.value.clone()),
            Some(_) => {
                map.remove(uid); // lazy: 期限切れは取得時に除去
                None
            }
            None => None,
        }
    }
    async fn consume_interaction(&self, uid: &str) -> bool {
        // 期限切れの消費は「既に無い」と同義(false)。単回消費の意味論を保つ。
        match self.interactions.lock().unwrap().remove(uid) {
            Some(e) => e.alive(),
            None => false,
        }
    }
    async fn save_session(&self, s: Session) {
        let exp = now_secs() + SESSION_TTL_SECS;
        self.sessions.lock().unwrap().insert(s.sid.clone(), Expiring::new(s, exp));
    }
    async fn get_session(&self, sid: &str) -> Option<Session> {
        let mut map = self.sessions.lock().unwrap();
        match map.get(sid) {
            Some(e) if e.alive() => Some(e.value.clone()),
            Some(_) => {
                map.remove(sid);
                None
            }
            None => None,
        }
    }
    async fn delete_session(&self, sid: &str) {
        self.sessions.lock().unwrap().remove(sid);
    }
    async fn save_code(&self, c: AuthorizationCode) {
        // code 自身の expires_at をストア TTL にも流用する(二重管理を避ける)。
        // 再利用検知のため used 化後も expires_at までは保持する(削除しない)。
        let exp = c.expires_at;
        let key = c.code.clone();
        self.codes.lock().unwrap().insert(
            key,
            Expiring::new(
                CodeRecord { code: c, used: false, issued_access: None, issued_refresh: None },
                exp,
            ),
        );
    }
    async fn take_code(&self, code: &str) -> Option<AuthorizationCode> {
        // 失効対象を lock 内で収集し、lock 解放後にトークンマップを触る（ロック順序固定）。
        let revoke = {
            let mut codes = self.codes.lock().unwrap();
            let entry = codes.get_mut(code)?;
            if !entry.alive() {
                // 期限切れコードは未知と同義。lazy 削除して None。
                codes.remove(code);
                return None;
            }
            let rec = &mut entry.value;
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
        if let Some(entry) = self.codes.lock().unwrap().get_mut(code) {
            entry.value.issued_access = Some(access_token.to_string());
            entry.value.issued_refresh = refresh_token.map(str::to_string);
        }
    }
    async fn save_access_token(&self, t: AccessToken) {
        let exp = now_secs() + ACCESS_TTL_SECS;
        self.access_tokens.lock().unwrap().insert(t.token.clone(), Expiring::new(t, exp));
    }
    async fn get_access_token(&self, token: &str) -> Option<AccessToken> {
        let mut map = self.access_tokens.lock().unwrap();
        match map.get(token) {
            Some(e) if e.alive() => Some(e.value.clone()),
            Some(_) => {
                map.remove(token); // lazy 失効: introspection 等が期限切れを active 扱いしない
                None
            }
            None => None,
        }
    }
    async fn revoke_access_token(&self, token: &str) {
        self.access_tokens.lock().unwrap().remove(token);
    }
    async fn consume_mandate_if_unused(&self, token: &str) -> Result<bool, String> {
        let mut map = self.access_tokens.lock().unwrap();
        match map.get_mut(token) {
            Some(e) if e.alive() && !e.value.mandate_consumed => {
                e.value.mandate_consumed = true;
                Ok(true)
            }
            _ => Ok(false),
        }
    }
    async fn save_refresh_token(&self, t: RefreshToken) {
        let exp = now_secs() + REFRESH_TTL_SECS;
        self.refresh_tokens.lock().unwrap().insert(t.token.clone(), Expiring::new(t, exp));
    }
    async fn get_refresh_token(&self, token: &str) -> Option<RefreshToken> {
        let mut map = self.refresh_tokens.lock().unwrap();
        match map.get(token) {
            Some(e) if e.alive() => Some(e.value.clone()),
            Some(_) => {
                map.remove(token);
                None
            }
            None => None,
        }
    }
    async fn revoke_refresh_token(&self, token: &str) {
        self.refresh_tokens.lock().unwrap().remove(token);
    }
    async fn mark_refresh_used(&self, token: &str, replaced_by: Option<&str>) -> bool {
        let mut map = self.refresh_tokens.lock().unwrap();
        match map.get_mut(token) {
            Some(e) if e.alive() && !e.value.used => {
                e.value.used = true;
                e.value.replaced_by = replaced_by.map(str::to_string);
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
            cur = map.remove(&t).and_then(|e| e.value.replaced_by);
        }
    }
    async fn find_account(&self, sub: &str) -> Account {
        account_for(sub)
    }

    /// 全マップから期限切れを物理削除(retain_alive の実体)。ロックは各マップ毎に
    /// 短時間で取得・解放し、保持順序を固定してデッドロックを避ける。
    async fn sweep_expired(&self) {
        retain_alive(&mut self.interactions.lock().unwrap());
        retain_alive(&mut self.sessions.lock().unwrap());
        retain_alive(&mut self.codes.lock().unwrap());
        retain_alive(&mut self.access_tokens.lock().unwrap());
        retain_alive(&mut self.refresh_tokens.lock().unwrap());
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

    fn rtok(token: &str, replaced_by: Option<&str>, used: bool) -> RefreshToken {
        RefreshToken {
            token: token.into(), client_id: "cl".into(), account_id: "a".into(),
            scope: "openid offline_access".into(), resource: None, jkt: None, acr: None,
            auth_time: None, family_id: "fam".into(), used,
            replaced_by: replaced_by.map(str::to_string),
        }
    }

    // B-4: mark_refresh_used は単回消費（CAS）。最初の 1 回だけ true、replaced_by は初回値が残る。
    #[tokio::test]
    async fn mark_refresh_used_is_single_use() {
        let s = MemoryStore::default();
        s.save_refresh_token(rtok("RT1", None, false)).await;
        assert!(s.mark_refresh_used("RT1", Some("RT2")).await); // 初回成功
        for _ in 0..5 {
            assert!(!s.mark_refresh_used("RT1", Some("RTx")).await); // 以降は負け
        }
        let rt = s.get_refresh_token("RT1").await.unwrap();
        assert!(rt.used);
        assert_eq!(rt.replaced_by.as_deref(), Some("RT2")); // 初回の連結が保たれる
        assert!(!s.mark_refresh_used("UNKNOWN", None).await); // 未存在も false
    }

    // B-4: revoke_refresh_family は replaced_by 連鎖を辿り family 全体を削除する（任意長）。
    #[tokio::test]
    async fn revoke_family_deletes_entire_chain() {
        for n in 1..=8usize {
            let s = MemoryStore::default();
            for i in 1..=n {
                let rb = if i < n { Some(format!("RT{}", i + 1)) } else { None };
                s.save_refresh_token(rtok(&format!("RT{i}"), rb.as_deref(), i < n)).await;
            }
            s.revoke_refresh_family("RT1").await;
            for i in 1..=n {
                assert!(s.get_refresh_token(&format!("RT{i}")).await.is_none(), "n={n} RT{i} 残存");
            }
        }
    }

    // B-4: replaced_by が循環していても停止する（無限ループ・ハングしない）。
    #[tokio::test]
    async fn revoke_family_cyclic_chain_terminates() {
        let s = MemoryStore::default();
        s.save_refresh_token(rtok("RT1", Some("RT2"), true)).await;
        s.save_refresh_token(rtok("RT2", Some("RT1"), true)).await; // RT1<->RT2 循環
        s.revoke_refresh_family("RT1").await; // 停止すること自体が検証点
        assert!(s.get_refresh_token("RT1").await.is_none());
        assert!(s.get_refresh_token("RT2").await.is_none());
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

    // 保持期間はレコード種別ごとに異なる。DEFAULT 一律にすると session が 15 分で
    // 切れる/refresh が仕様より長生きする、といった不一致が起きるので固定する。
    // FirestoreStore も同じ定数を参照しており、この表がバックエンド間の唯一の合意点。
    #[tokio::test]
    async fn store_ttl_is_per_record_type() {
        let s = MemoryStore::default();
        let base = now_secs();

        s.save_session(Session { sid: "S1".into(), account_id: "a".into(), auth_time: 0 }).await;
        let session_exp = s.sessions.lock().unwrap().get("S1").unwrap().expires_at;
        assert!(session_exp >= base + SESSION_TTL_SECS, "session は 7 日保持(15 分ではない)");

        s.save_interaction(Interaction {
            uid: "U1".into(),
            raw_query: String::new(),
            account_id: None,
            auth_time: None,
            request_uri: None,
        })
        .await;
        let inter_exp = s.interactions.lock().unwrap().get("U1").unwrap().expires_at;
        assert!(inter_exp >= base + INTERACTION_TTL_SECS, "interaction は 1 時間保持");

        s.save_access_token(at("AT1")).await;
        let at_exp = s.access_tokens.lock().unwrap().get("AT1").unwrap().expires_at;
        assert!(at_exp >= base + ACCESS_TTL_SECS && at_exp < base + SESSION_TTL_SECS);

        s.save_refresh_token(rtok("RT1", None, false)).await;
        let rt_exp = s.refresh_tokens.lock().unwrap().get("RT1").unwrap().expires_at;
        assert!(rt_exp >= base + REFRESH_TTL_SECS, "refresh は 14 日保持");
    }

    // code は自身の expires_at を保持期間に流用する(二重管理しない)。
    // interaction/session/token は構造体に期限を持たないので上の定数表を使う、という非対称の確認。
    #[tokio::test]
    async fn code_uses_its_own_expires_at_as_retention() {
        let s = MemoryStore::default();
        let mut c = code("C1");
        c.expires_at = now_secs() + 42;
        s.save_code(c).await;
        assert_eq!(s.codes.lock().unwrap().get("C1").unwrap().expires_at, now_secs() + 42);
    }

    // 期限切れ access token は取得時に None(lazy 失効)。introspection が active 扱いしない根拠。
    #[tokio::test]
    async fn expired_access_token_is_none_on_get() {
        let s = MemoryStore::default();
        // 過去に失効するエントリを直接投入(save は now+TTL になるため内部 API で細工)。
        s.access_tokens
            .lock()
            .unwrap()
            .insert("AT_OLD".into(), Expiring::new(at("AT_OLD"), now_secs().saturating_sub(1)));
        assert!(s.get_access_token("AT_OLD").await.is_none());
        // lazy 削除されている(マップから消える)。
        assert!(!s.access_tokens.lock().unwrap().contains_key("AT_OLD"));
    }

    // 生きている access token は取得できる(誤って消さない)。
    #[tokio::test]
    async fn live_access_token_survives() {
        let s = MemoryStore::default();
        s.save_access_token(at("AT_NEW")).await; // now + 900s
        assert!(s.get_access_token("AT_NEW").await.is_some());
    }

    // active sweep は期限切れだけを物理削除し、生存エントリは残す。
    #[tokio::test]
    async fn sweep_removes_only_expired() {
        let s = MemoryStore::default();
        s.save_access_token(at("LIVE")).await; // 生存
        s.access_tokens
            .lock()
            .unwrap()
            .insert("DEAD".into(), Expiring::new(at("DEAD"), now_secs().saturating_sub(1)));
        s.sweep_expired().await;
        assert!(s.access_tokens.lock().unwrap().contains_key("LIVE"));
        assert!(!s.access_tokens.lock().unwrap().contains_key("DEAD"));
    }

    // 期限切れ interaction の消費は false(単回消費の意味論を壊さない)。
    #[tokio::test]
    async fn expired_interaction_consume_is_false() {
        let s = MemoryStore::default();
        s.interactions.lock().unwrap().insert(
            "U_OLD".into(),
            Expiring::new(
                Interaction {
                    uid: "U_OLD".into(),
                    raw_query: String::new(),
                    account_id: Some("a".into()),
                    auth_time: None,
                    request_uri: None,
                },
                now_secs().saturating_sub(1),
            ),
        );
        assert!(!s.consume_interaction("U_OLD").await);
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
