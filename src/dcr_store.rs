//! 制御つき DCR の Firestore 永続化層。
//!
//! Client は専用の Value 変換を持たないため、JSON 文字列 1 フィールド(`json`)で保存する。
//! firestore.rules は全コレクションをサーバ SA 限定にしているので、`clients/` への
//! 書き込みはこのサーバ経由のみ（クライアント直書き不可＝信頼境界が DB 側で閉じている）。

use crate::firestore::{field_str, Firestore};
use crate::model::Client;

const CLIENTS: &str = "clients";

/// DCR 登録クライアントを clients/{client_id} から読む。無ければ None。
///
/// fail-closed: 読み取り I/O 失敗・JSON 破損はいずれも None（＝unknown client 扱い）に
/// 落とす。ただし沈黙させない——どちらも eprintln で痕跡を残す。登録済みクライアントが
/// 無言で「未知」に化ける状態を切り分け可能にしておく。
pub async fn load_client(fs: &Firestore, client_id: &str) -> Option<Client> {
    let fields = match fs.get_doc(CLIENTS, client_id).await {
        Ok(Some(f)) => f,
        Ok(None) => return None,
        Err(e) => {
            eprintln!("dcr_store: load_client {client_id}: read failed: {e}");
            return None;
        }
    };
    let json = field_str(&fields, "json")?;
    match serde_json::from_str(json) {
        Ok(c) => Some(c),
        Err(e) => {
            eprintln!("dcr_store: load_client {client_id}: malformed json blob: {e}");
            None
        }
    }
}
