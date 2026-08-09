//! 管理者権限の Firestore 永続化層。
//!
//! admins/_registry という単一ドキュメントに、管理者一覧を JSON 配列で丸ごと持つ。
//! 個別ドキュメント(admins/{account_id})+ query_eq(role) 方式ではなく単一ドキュメントに
//! 統合しているのは、以前の設計に2つの correctness 問題があったため:
//!
//! - is_admin は「ドキュメントの存在」だけで判定する一方、list_admins/revoke_admin は
//!   query_eq で role フィールドが特定値のものだけを数えていた。両者が別の定義を持つと、
//!   role フィールドを持たない admins/{id} ドキュメントが何らかの経路で作られた場合に
//!   is_admin だけ true になり得る。
//! - revoke の「最後の1人は剥奪できない」ガードが list_admins(read)→delete_doc(write) の
//!   2 ステップに分かれており、2 つの revoke がほぼ同時に走ると両方が「まだ2人いる」時点の
//!   一覧を読んでしまい、両方通過して管理者が 0 人になり得る（非アトミック）。
//!
//! 単一ドキュメント + updateTime CAS（[`Firestore::set_doc_if_unchanged`]）にまとめることで、
//! is_admin/list_admins が同じデータを見るようにし、grant/revoke は「読んだ版のまま書けたか」
//! で判定するため、上記の非アトミック性も解消される。CAS 衝突時は再試行ループを回さず
//! Conflict を返す（管理者の付与/剥奪は低頻度の手動操作なので、衝突時は呼び出し側=人間が
//! 再実行すれば足りる）。

use crate::firestore::{self, Firestore};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

const REGISTRY_COL: &str = "admins";
const REGISTRY_ID: &str = "_registry";

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

#[derive(Serialize, Deserialize, Clone)]
struct AdminEntry {
    account_id: String,
    granted_by: String,
    granted_at: u64,
}

/// レジストリを読む。ドキュメントが無ければ「管理者ゼロ人・未作成」として扱う。
async fn load_registry(fs: &Firestore) -> Result<(Vec<AdminEntry>, Option<String>), String> {
    match fs.get_doc_with_update_time(REGISTRY_COL, REGISTRY_ID).await? {
        Some((fields, update_time)) => Ok((parse_entries(&fields), Some(update_time))),
        None => Ok((vec![], None)),
    }
}

fn parse_entries(fields: &serde_json::Value) -> Vec<AdminEntry> {
    firestore::field_str(fields, "entries")
        .and_then(|s| serde_json::from_str::<Vec<AdminEntry>>(s).ok())
        .unwrap_or_default()
}

fn entries_field(entries: &[AdminEntry]) -> serde_json::Value {
    let json = serde_json::to_string(entries).unwrap_or_else(|_| "[]".into());
    serde_json::json!({ "entries": firestore::s(&json) })
}

/// account_id が管理者か。読み取り失敗は Err を返す（呼び出し側が「非管理者(403)」と
/// 「判定不能(503)」を区別できるようにするため、ここでは bool に丸めない）。
pub async fn is_admin(fs: &Firestore, account_id: &str) -> Result<bool, String> {
    let (entries, _) = load_registry(fs).await?;
    Ok(entries.iter().any(|e| e.account_id == account_id))
}

/// 現在の管理者 account_id 一覧。web/admin.rs::users_list が管理者バッジ表示に使う。
pub async fn list_admins(fs: &Firestore) -> Result<Vec<String>, String> {
    let (entries, _) = load_registry(fs).await?;
    Ok(entries.into_iter().map(|e| e.account_id).collect())
}

#[derive(Debug, PartialEq, Eq)]
pub enum GrantAdminResult {
    Granted,
    AlreadyAdmin,
    /// 他の書き込みと競合した。低頻度の手動操作なので呼び出し側で再実行してもらう。
    Conflict,
}

/// account_id を管理者にする。既に管理者なら書き込まず AlreadyAdmin を返す（冪等）。
pub async fn grant_admin(
    fs: &Firestore,
    account_id: &str,
    granted_by: &str,
) -> Result<GrantAdminResult, String> {
    let (mut entries, update_time) = load_registry(fs).await?;
    if entries.iter().any(|e| e.account_id == account_id) {
        return Ok(GrantAdminResult::AlreadyAdmin);
    }
    entries.push(AdminEntry {
        account_id: account_id.to_string(),
        granted_by: granted_by.to_string(),
        granted_at: now(),
    });
    let ok = match &update_time {
        Some(ut) => fs.set_doc_if_unchanged(REGISTRY_COL, REGISTRY_ID, entries_field(&entries), ut).await?,
        None => fs.create_if_absent(REGISTRY_COL, REGISTRY_ID, entries_field(&entries)).await?,
    };
    Ok(if ok { GrantAdminResult::Granted } else { GrantAdminResult::Conflict })
}

#[derive(Debug, PartialEq, Eq)]
pub enum RevokeAdminResult {
    Revoked,
    NotAdmin,
    /// 最後の1人は剥奪できない（誰も管理者でなくなる状態を防ぐ）。
    LastAdminGuard,
    /// 他の書き込みと競合した。呼び出し側で再実行してもらう。
    Conflict,
}

/// 与えられた管理者一覧に対して revoke を許可してよいか判定する（純粋関数）。
fn decide_revoke(entries: &[AdminEntry], target: &str) -> RevokeAdminResult {
    if !entries.iter().any(|e| e.account_id == target) {
        RevokeAdminResult::NotAdmin
    } else if entries.len() <= 1 {
        RevokeAdminResult::LastAdminGuard
    } else {
        RevokeAdminResult::Revoked
    }
}

/// account_id の管理者権限を剥奪する。ガード判定と削除を同じ読み取り(updateTime)の上で
/// 行い、CAS 書き込みで確定させるため、2つの revoke が競合しても両方が Revoked になることはない
/// （片方は Conflict になる）。
pub async fn revoke_admin(fs: &Firestore, account_id: &str) -> Result<RevokeAdminResult, String> {
    let (entries, update_time) = load_registry(fs).await?;
    match decide_revoke(&entries, account_id) {
        RevokeAdminResult::Revoked => {
            let remaining: Vec<AdminEntry> =
                entries.into_iter().filter(|e| e.account_id != account_id).collect();
            // decide_revoke が Revoked を返すのは entries が非空(≥2件)の場合のみなので
            // update_time は必ず Some(そのドキュメントを読んで entries を得ている)。
            let ut = update_time.ok_or_else(|| "admin_store: revoke_admin: inconsistent state".to_string())?;
            let ok = fs.set_doc_if_unchanged(REGISTRY_COL, REGISTRY_ID, entries_field(&remaining), &ut).await?;
            Ok(if ok { RevokeAdminResult::Revoked } else { RevokeAdminResult::Conflict })
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
        assert!(!is_admin(&fs, "u1").await.unwrap());
        assert_eq!(grant_admin(&fs, "u1", "cli").await.unwrap(), GrantAdminResult::Granted);
        assert!(is_admin(&fs, "u1").await.unwrap());
    }

    #[tokio::test]
    async fn grant_is_idempotent() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        assert_eq!(grant_admin(&fs, "u1", "cli").await.unwrap(), GrantAdminResult::Granted);
        assert_eq!(grant_admin(&fs, "u1", "cli").await.unwrap(), GrantAdminResult::AlreadyAdmin);
        assert!(is_admin(&fs, "u1").await.unwrap());
    }

    #[tokio::test]
    async fn unknown_account_is_not_admin() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        assert!(!is_admin(&fs, "nope").await.unwrap());
    }

    #[tokio::test]
    async fn is_admin_and_list_admins_agree() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        grant_admin(&fs, "u1", "cli").await.unwrap();
        grant_admin(&fs, "u2", "cli").await.unwrap();
        let listed = list_admins(&fs).await.unwrap();
        for id in ["u1", "u2"] {
            assert_eq!(is_admin(&fs, id).await.unwrap(), listed.iter().any(|a| a == id));
        }
    }

    #[tokio::test]
    async fn revoke_last_admin_is_refused() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        grant_admin(&fs, "u1", "cli").await.unwrap();
        assert_eq!(revoke_admin(&fs, "u1").await.unwrap(), RevokeAdminResult::LastAdminGuard);
        assert!(is_admin(&fs, "u1").await.unwrap(), "拒否されたので管理者のまま");
    }

    #[tokio::test]
    async fn revoke_succeeds_when_another_admin_remains() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        grant_admin(&fs, "u1", "cli").await.unwrap();
        grant_admin(&fs, "u2", "cli").await.unwrap();
        assert_eq!(revoke_admin(&fs, "u1").await.unwrap(), RevokeAdminResult::Revoked);
        assert!(!is_admin(&fs, "u1").await.unwrap());
        assert!(is_admin(&fs, "u2").await.unwrap());
    }

    #[tokio::test]
    async fn revoke_unknown_account_is_not_admin() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        grant_admin(&fs, "u1", "cli").await.unwrap();
        assert_eq!(revoke_admin(&fs, "nope").await.unwrap(), RevokeAdminResult::NotAdmin);
    }

    #[tokio::test]
    async fn concurrent_revoke_of_last_two_admins_only_one_succeeds() {
        // 非アトミック性の回帰テスト: u1/u2 の2人だけの状態で、両方を同時に revoke しようとしても
        // どちらか一方しか通らない(=管理者0人にはならない)。もう片方は Conflict または
        // (先に片方が抜けたあとに読めば)LastAdminGuard になる。
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        grant_admin(&fs, "u1", "cli").await.unwrap();
        grant_admin(&fs, "u2", "cli").await.unwrap();

        // 同じ版(update_time)を見た状態を模すため、先に両方の読み取りを済ませてから
        // それぞれの書き込みを行う。
        let (entries_for_u1, ut1) = load_registry(&fs).await.unwrap();
        let (entries_for_u2, ut2) = load_registry(&fs).await.unwrap();
        assert_eq!(ut1, ut2, "同じ版を読んでいる前提");

        let remaining_after_u1 =
            entries_for_u1.into_iter().filter(|e| e.account_id != "u1").collect::<Vec<_>>();
        let remaining_after_u2 =
            entries_for_u2.into_iter().filter(|e| e.account_id != "u2").collect::<Vec<_>>();
        let ut = ut1.unwrap();

        let r1 = fs
            .set_doc_if_unchanged(REGISTRY_COL, REGISTRY_ID, entries_field(&remaining_after_u1), &ut)
            .await
            .unwrap();
        let r2 = fs
            .set_doc_if_unchanged(REGISTRY_COL, REGISTRY_ID, entries_field(&remaining_after_u2), &ut)
            .await
            .unwrap();

        assert!(r1 ^ r2, "先勝ちで片方だけ成功する(両方成功/両方失敗はNG)");
        let remaining = list_admins(&fs).await.unwrap();
        assert_eq!(remaining.len(), 1, "管理者が0人になってはいけない");
    }
}
