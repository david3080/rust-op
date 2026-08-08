//! アカウント無効化（disabled フラグ）とセッション/トークン失効の安全網。
//!
//! 管理者がアカウントを凍結する際、以後の新規ログイン/CIBA承認を拒否しつつ（[`crate::registration::set_disabled`]
//! と login.rs/ciba.rs 側のチェック）、既存の SSO セッション・access token・refresh token も
//! 同時に破棄する。refresh token は TTL が14日と長くローテーションもするため、これを
//! revoke しないと「凍結したのに攻撃者が最大14日間 refresh でアクセスし続けられる」という
//! 抜け穴になる（過去の実装ミス: ACCESS_TTL(15分)と混同してrefresh tokenを対象外にしていた）。
//!
//! これらは account_id → doc の逆引きインデックスを別途維持せず、既存の
//! [`crate::firestore::Firestore::query_eq`]（ciba.rs の list_pending/list_history と同じ
//! 仕組み）でその場検索する。

use crate::firestore::Firestore;
use crate::{audit_log, registration};

/// セッション/トークン失効の結果。query_errors に列挙されたコレクションは「0件だった」
/// のではなく「検索自体が失敗し存否不明」であることを示す（呼び出し側はこれを区別できる）。
#[derive(Debug, Default, PartialEq, Eq)]
pub struct RevocationCounts {
    pub sessions: usize,
    pub access_tokens: usize,
    pub refresh_tokens: usize,
    pub query_errors: Vec<&'static str>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum DisableOutcome {
    Disabled(RevocationCounts),
    /// 既に disabled=true だった場合。再実行は安全（べき等）で、セッション/トークン失効も
    /// 取りこぼしがないよう毎回試みる（前回の失効が部分的に失敗していた場合の再試行を兼ねる）。
    AlreadyDisabled(RevocationCounts),
    NotFound,
}

#[derive(Debug, PartialEq, Eq)]
pub enum EnableOutcome {
    Enabled,
    AlreadyEnabled,
    NotFound,
}

/// actor は監査ログへ記録する呼び出し主体（CLI実行なら"cli"）。
pub async fn disable_account(fs: &Firestore, actor: &str, email: &str) -> Result<DisableOutcome, String> {
    let cred = match registration::get_credential(fs, email).await? {
        Some(c) => c,
        None => return Ok(DisableOutcome::NotFound),
    };
    let already_disabled = cred.disabled;
    if !already_disabled {
        registration::set_disabled(fs, email, true).await?;
    }
    let counts = revoke_all(fs, &cred.account_id).await;
    audit_log::record(
        fs,
        actor,
        "disable_account",
        &cred.account_id,
        &format!(
            "email={email} sessions={} access_tokens={} refresh_tokens={} query_errors={:?}",
            counts.sessions, counts.access_tokens, counts.refresh_tokens, counts.query_errors
        ),
    )
    .await;
    Ok(if already_disabled {
        DisableOutcome::AlreadyDisabled(counts)
    } else {
        DisableOutcome::Disabled(counts)
    })
}

/// AlreadyEnabled(no-op)でも disable_account 同様に必ず監査ログを残す
/// （「べき等な管理操作の再実行」を disable/enable で対称に扱う）。
pub async fn enable_account(fs: &Firestore, actor: &str, email: &str) -> Result<EnableOutcome, String> {
    let cred = match registration::get_credential(fs, email).await? {
        Some(c) => c,
        None => return Ok(EnableOutcome::NotFound),
    };
    let already_enabled = !cred.disabled;
    if !already_enabled {
        registration::set_disabled(fs, email, false).await?;
    }
    audit_log::record(
        fs,
        actor,
        "enable_account",
        &cred.account_id,
        &format!("email={email} already_enabled={already_enabled}"),
    )
    .await;
    Ok(if already_enabled { EnableOutcome::AlreadyEnabled } else { EnableOutcome::Enabled })
}

/// account_id に紐づく sessions/accessTokens/refreshTokens を検索し削除する。
/// コレクション単位で query_eq 自体が失敗しても他のコレクションの失効は続ける
/// （1種類の障害で残りを諦めない）。失敗したコレクションは query_errors に記録し、
/// 呼び出し側（CLI 出力・監査ログ）へその不確実性を伝える。
async fn revoke_all(fs: &Firestore, account_id: &str) -> RevocationCounts {
    let mut counts = RevocationCounts::default();
    match revoke_by_account(fs, "sessions", account_id).await {
        Ok(n) => counts.sessions = n,
        Err(e) => {
            tracing::error!("account_admin: sessions revocation query failed for {account_id}: {e}");
            counts.query_errors.push("sessions");
        }
    }
    match revoke_by_account(fs, "accessTokens", account_id).await {
        Ok(n) => counts.access_tokens = n,
        Err(e) => {
            tracing::error!("account_admin: accessTokens revocation query failed for {account_id}: {e}");
            counts.query_errors.push("accessTokens");
        }
    }
    match revoke_by_account(fs, "refreshTokens", account_id).await {
        Ok(n) => counts.refresh_tokens = n,
        Err(e) => {
            tracing::error!("account_admin: refreshTokens revocation query failed for {account_id}: {e}");
            counts.query_errors.push("refreshTokens");
        }
    }
    counts
}

/// account_id に紐づく col の全ドキュメントを検索し削除する。1件の削除失敗で残りを
/// 諦めない（ベストエフォート。失敗したものは tracing::error に残す）。戻り値は実際に
/// 削除できた件数。
async fn revoke_by_account(fs: &Firestore, col: &str, account_id: &str) -> Result<usize, String> {
    let rows = fs.query_eq(col, "accountId", account_id).await?;
    let mut revoked = 0usize;
    for (id, _fields) in &rows {
        match fs.delete_doc(col, id).await {
            Ok(()) => revoked += 1,
            Err(e) => tracing::error!("account_admin: {col} revoke failed id={id}: {e}"),
        }
    }
    Ok(revoked)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firestore::fake_firestore;
    use crate::model::{AccessToken, RefreshToken, Session};
    use crate::store::Store;

    /// (emulator host, Firestore) を返す。host は同じ fake サーバを指す2つ目の Firestore
    /// （FirestoreStore 経由のセッション/トークン操作用）を作るために呼び出し側で使う。
    async fn setup() -> (String, Firestore) {
        let (host, _state) = fake_firestore::spawn().await;
        (host.clone(), Firestore::new_for_test("proj", host))
    }

    async fn register(fs: &Firestore, email: &str, account_id: &str) {
        let outcome = crate::webauthn::RegOutcome {
            credential_id: format!("cred-{account_id}"),
            pub_x: "x".into(),
            pub_y: "y".into(),
            sign_count: 0,
        };
        registration::save_credential(fs, email, account_id, &outcome).await.unwrap();
    }

    #[tokio::test]
    async fn disable_unknown_account_returns_not_found() {
        let (_host, fs) = setup().await;
        let out = disable_account(&fs, "cli", "nobody@example.com").await.unwrap();
        assert_eq!(out, DisableOutcome::NotFound);
    }

    #[tokio::test]
    async fn disable_revokes_sessions_access_and_refresh_tokens_but_not_other_accounts() {
        let (host, fs) = setup().await;
        register(&fs, "victim@example.com", "acc-victim").await;
        register(&fs, "other@example.com", "acc-other").await;

        let store = crate::firestore_store::FirestoreStore::new(std::sync::Arc::new(
            Firestore::new_for_test("proj", host),
        ));
        store
            .save_session(Session { sid: "sid-1".into(), account_id: "acc-victim".into(), auth_time: 0 })
            .await;
        store
            .save_session(Session { sid: "sid-other".into(), account_id: "acc-other".into(), auth_time: 0 })
            .await;
        store
            .save_access_token(AccessToken {
                token: "at-victim".into(),
                client_id: "c".into(),
                account_id: "acc-victim".into(),
                scope: "openid".into(),
                jkt: None,
                aud: None,
                acr: None,
                auth_time: None,
                authorization_details: None,
                mandate_consumed: false,
            })
            .await;
        store
            .save_refresh_token(RefreshToken {
                token: "rt-victim".into(),
                client_id: "c".into(),
                account_id: "acc-victim".into(),
                scope: "openid".into(),
                resource: None,
                jkt: None,
                acr: None,
                auth_time: None,
                family_id: "fam-1".into(),
                used: false,
                replaced_by: None,
            })
            .await;

        let out = disable_account(&fs, "cli", "victim@example.com").await.unwrap();
        assert_eq!(
            out,
            DisableOutcome::Disabled(RevocationCounts {
                sessions: 1,
                access_tokens: 1,
                refresh_tokens: 1,
                query_errors: vec![],
            })
        );

        let cred = registration::get_credential(&fs, "victim@example.com").await.unwrap().unwrap();
        assert!(cred.disabled);
        assert!(store.get_session("sid-1").await.is_none());
        assert!(store.get_access_token("at-victim").await.is_none());
        assert!(store.get_refresh_token("rt-victim").await.is_none());
        // 無関係のアカウントのセッションは残る。
        assert!(store.get_session("sid-other").await.is_some());
    }

    #[tokio::test]
    async fn disable_is_idempotent_and_reports_already_disabled() {
        let (_host, fs) = setup().await;
        register(&fs, "victim@example.com", "acc-victim").await;
        disable_account(&fs, "cli", "victim@example.com").await.unwrap();

        let out = disable_account(&fs, "cli", "victim@example.com").await.unwrap();
        assert_eq!(out, DisableOutcome::AlreadyDisabled(RevocationCounts::default()));
    }

    #[tokio::test]
    async fn reregistration_preserves_disabled_flag() {
        let (_host, fs) = setup().await;
        register(&fs, "victim@example.com", "acc-victim").await;
        disable_account(&fs, "cli", "victim@example.com").await.unwrap();

        // 機種変更等で passkey を作り直しても凍結は解除されない。
        register(&fs, "victim@example.com", "acc-victim").await;
        let cred = registration::get_credential(&fs, "victim@example.com").await.unwrap().unwrap();
        assert!(cred.disabled, "再登録で凍結が解除されてはならない");
    }

    #[tokio::test]
    async fn enable_clears_flag_and_records_audit_even_when_noop() {
        let (_host, fs) = setup().await;
        register(&fs, "victim@example.com", "acc-victim").await;

        assert_eq!(
            enable_account(&fs, "cli", "victim@example.com").await.unwrap(),
            EnableOutcome::AlreadyEnabled
        );

        disable_account(&fs, "cli", "victim@example.com").await.unwrap();
        assert_eq!(enable_account(&fs, "cli", "victim@example.com").await.unwrap(), EnableOutcome::Enabled);
        let cred = registration::get_credential(&fs, "victim@example.com").await.unwrap().unwrap();
        assert!(!cred.disabled);

        // AlreadyEnabled の no-op でも監査ログは記録される(disable側との対称性)。
        let entries = fs.query_eq("auditLog", "action", "enable_account").await.unwrap();
        assert_eq!(entries.len(), 2, "Enabled 1件 + AlreadyEnabled(no-op) 1件");
    }
}
