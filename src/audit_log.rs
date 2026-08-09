//! 管理操作の監査ログ。auditLog/{auto-id} に追記専用で書く。
//! grant-admin/revoke-admin/disable-account/enable-account など、個々の管理操作から
//! 呼ばれる横断的関心事。
//!
//! 書き込み失敗で本処理自体は失敗させない（fail-open）。呼び出し側の本処理は既に
//! CAS等で保護された書き込みを完了させた後にここへ来るため、監査ログはそれを追跡する
//! 副次的な記録であり、これの失敗で本処理をロールバックする理由にはならない
//! （accountsByUuid 逆引きインデックスの書き込み失敗時と同じ方針。registration.rs 参照）。

use crate::firestore::{self, Firestore};
use serde_json::json;
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

/// actor: 操作を行った主体（CLI実行なら"cli"。将来の管理UIからならその管理者自身の account_id）。
/// action: 操作種別（例 "disable_account"）。target: 操作対象の識別子（例 account_id）。
/// detail: 人間可読の補足情報。
pub async fn record(fs: &Firestore, actor: &str, action: &str, target: &str, detail: &str) {
    let id = uuid::Uuid::new_v4().to_string();
    let fields = json!({
        "actor": firestore::s(actor),
        "action": firestore::s(action),
        "target": firestore::s(target),
        "detail": firestore::s(detail),
        "at": firestore::ts(&firestore::rfc3339(now())),
    });
    match fs.create_if_absent("auditLog", &id, fields).await {
        Ok(true) => {}
        // UUIDv4衝突は実質起こらないが、create_if_absentはOk(false)=「書き込みスキップ」を
        // 返しうる契約なので、Errだけ見ているとこのケースで監査ログが黙って欠落する。
        Ok(false) => {
            tracing::error!("audit_log: id collision, entry not written action={action} target={target} id={id}");
        }
        Err(e) => tracing::error!("audit_log: write failed action={action} target={target}: {e}"),
    }
}

pub struct AuditEntry {
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: String,
    pub at: u64,
}

fn parse_entry(fields: &serde_json::Value) -> AuditEntry {
    AuditEntry {
        actor: firestore::field_str(fields, "actor").unwrap_or("").to_string(),
        action: firestore::field_str(fields, "action").unwrap_or("").to_string(),
        target: firestore::field_str(fields, "target").unwrap_or("").to_string(),
        detail: firestore::field_str(fields, "detail").unwrap_or("").to_string(),
        at: firestore::field_ts_secs(fields, "at").unwrap_or(0),
    }
}

/// 全体の直近N件（新しい順）。auditLog は書き込みが積み重なり続ける唯一のコレクションの
/// ため、コレクション全体は取得せず Firestore 側で絞り込む（list_recent_ordered）。
pub async fn list_recent(fs: &Firestore, limit: u32) -> Result<Vec<AuditEntry>, String> {
    let rows = fs.list_recent_ordered("auditLog", "at", limit).await?;
    Ok(rows.iter().map(|(_, fields)| parse_entry(fields)).collect())
}

/// 特定target（例: account_id）に紐づく履歴（新しい順）。1対象分に限定されるため既存の
/// query_eq + クライアント側ソートで十分。
pub async fn list_for_target(fs: &Firestore, target: &str) -> Result<Vec<AuditEntry>, String> {
    let rows = fs.query_eq("auditLog", "target", target).await?;
    let mut entries: Vec<AuditEntry> = rows.iter().map(|(_, fields)| parse_entry(fields)).collect();
    entries.sort_by(|a, b| b.at.cmp(&a.at));
    Ok(entries)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firestore::fake_firestore;

    /// record() は at に now()(秒精度)しか使えず、同一テスト内で連続記録すると同一秒に
    /// なりうるため、順序を厳密に検証したいテストでは at を明示指定して直接書き込む。
    async fn record_at(fs: &Firestore, action: &str, target: &str, at: u64) {
        fs.set_doc(
            "auditLog",
            &uuid::Uuid::new_v4().to_string(),
            json!({
                "actor": firestore::s("cli"),
                "action": firestore::s(action),
                "target": firestore::s(target),
                "detail": firestore::s(""),
                "at": firestore::ts(&firestore::rfc3339(at)),
            }),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn list_recent_returns_newest_first_and_respects_limit() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        record_at(&fs, "grant_admin", "acc-1", 100).await;
        record_at(&fs, "revoke_admin", "acc-1", 300).await;
        record_at(&fs, "disable_account", "acc-2", 200).await;

        let recent = list_recent(&fs, 2).await.unwrap();
        assert_eq!(recent.len(), 2, "limitで絞られること");
        assert_eq!(recent[0].action, "revoke_admin", "at=300が最新");
        assert_eq!(recent[1].action, "disable_account", "at=200が次");
    }

    #[tokio::test]
    async fn list_for_target_filters_and_sorts_newest_first() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        record_at(&fs, "grant_admin", "acc-x", 100).await;
        record_at(&fs, "revoke_admin", "acc-x", 300).await;
        record_at(&fs, "disable_account", "acc-y", 200).await;

        let for_x = list_for_target(&fs, "acc-x").await.unwrap();
        assert_eq!(for_x.len(), 2, "acc-yのエントリは含まれない");
        assert_eq!(for_x[0].action, "revoke_admin", "新しい順であること");
        assert_eq!(for_x[1].action, "grant_admin");
        assert!(list_for_target(&fs, "acc-none").await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_recent_empty_when_no_entries() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        assert!(list_recent(&fs, 200).await.unwrap().is_empty());
    }
}
