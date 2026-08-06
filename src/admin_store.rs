//! 管理者権限の Firestore 永続化層。
//!
//! admins/{account_id} の存在＝管理者。email ではなく account_id(UUID) をキーにするのは、
//! sub/WebAuthn user.id から email を排除した account_id 化（account_id 移行）と方針を
//! 合わせるため。role フィールドは一覧取得(query_eq)用の固定マーカー
//! （Firestore の等価クエリは値指定が必須なため "admin" という固定値で全件を引く）。

use crate::firestore::{self, Firestore};
use std::time::{SystemTime, UNIX_EPOCH};

const ADMINS: &str = "admins";
const ROLE_MARKER: &str = "admin";

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// account_id が管理者か。fail-closed: 読み取り失敗は非管理者扱い（ただし痕跡は残す）。
pub async fn is_admin(fs: &Firestore, account_id: &str) -> bool {
    match fs.get_doc(ADMINS, account_id).await {
        Ok(v) => v.is_some(),
        Err(e) => {
            eprintln!("admin_store: is_admin {account_id}: read failed: {e}");
            false
        }
    }
}

/// account_id を管理者にする。既に管理者なら grantedBy/grantedAt を上書きして冪等に成功する。
pub async fn grant_admin(fs: &Firestore, account_id: &str, granted_by: &str) -> Result<(), String> {
    fs.set_doc(
        ADMINS,
        account_id,
        serde_json::json!({
            "role": firestore::s(ROLE_MARKER),
            "grantedBy": firestore::s(granted_by),
            "grantedAt": firestore::ts(&firestore::rfc3339(now())),
        }),
    )
    .await
}

/// 現在の管理者 account_id 一覧。
pub async fn list_admins(fs: &Firestore) -> Result<Vec<String>, String> {
    let rows = fs.query_eq(ADMINS, "role", ROLE_MARKER).await?;
    Ok(rows.into_iter().map(|(id, _)| id).collect())
}

#[derive(Debug, PartialEq, Eq)]
pub enum RevokeAdminResult {
    Revoked,
    NotAdmin,
    /// 最後の1人は剥奪できない（誰も管理者でなくなる状態を防ぐ）。
    LastAdminGuard,
}

/// 与えられた管理者一覧に対して revoke を許可してよいか判定する（純粋関数）。
fn decide_revoke(admins: &[String], target: &str) -> RevokeAdminResult {
    if !admins.iter().any(|a| a == target) {
        RevokeAdminResult::NotAdmin
    } else if admins.len() <= 1 {
        RevokeAdminResult::LastAdminGuard
    } else {
        RevokeAdminResult::Revoked
    }
}

/// account_id の管理者権限を剥奪する。
pub async fn revoke_admin(fs: &Firestore, account_id: &str) -> Result<RevokeAdminResult, String> {
    let admins = list_admins(fs).await?;
    match decide_revoke(&admins, account_id) {
        RevokeAdminResult::Revoked => {
            fs.delete_doc(ADMINS, account_id).await?;
            Ok(RevokeAdminResult::Revoked)
        }
        other => Ok(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firestore::fake_firestore;

    #[tokio::test]
    async fn grant_then_is_admin_true() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        assert!(!is_admin(&fs, "u1").await);
        grant_admin(&fs, "u1", "cli").await.unwrap();
        assert!(is_admin(&fs, "u1").await);
    }

    #[tokio::test]
    async fn grant_is_idempotent() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        grant_admin(&fs, "u1", "cli").await.unwrap();
        grant_admin(&fs, "u1", "cli").await.unwrap();
        assert!(is_admin(&fs, "u1").await);
    }

    #[tokio::test]
    async fn unknown_account_is_not_admin() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        assert!(!is_admin(&fs, "nope").await);
    }

    // decide_revoke は純粋関数として単体テストする: list_admins は query_eq(runQuery) を使うが
    // fake_firestore は runQuery を実装していない（ciba.rs の list_pending/list_history と同じ
    // 既存の制約）ため、この経路自体は fake_firestore 経由の統合テスト対象外にする。
    #[test]
    fn decide_revoke_refuses_last_admin() {
        let admins = vec!["u1".to_string()];
        assert_eq!(decide_revoke(&admins, "u1"), RevokeAdminResult::LastAdminGuard);
    }

    #[test]
    fn decide_revoke_allows_when_another_admin_remains() {
        let admins = vec!["u1".to_string(), "u2".to_string()];
        assert_eq!(decide_revoke(&admins, "u1"), RevokeAdminResult::Revoked);
    }

    #[test]
    fn decide_revoke_reports_not_admin_for_unknown_target() {
        let admins = vec!["u1".to_string()];
        assert_eq!(decide_revoke(&admins, "u2"), RevokeAdminResult::NotAdmin);
    }
}
