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
