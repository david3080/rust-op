//! 制御つき DCR の Firestore 永続化層。
//!
//! Client は専用の Value 変換を持たないため、JSON 文字列 1 フィールド(`json`)で保存する。
//! firestore.rules は全コレクションをサーバ SA 限定にしているので、`clients/` への
//! 書き込みはこのサーバ経由のみ（クライアント直書き不可＝信頼境界が DB 側で閉じている）。

use crate::dcr::IatConstraints;
use crate::firestore::{self, field_bool, field_str, field_u64, Firestore};
use crate::model::Client;

const CLIENTS: &str = "clients";
const DCR_TOKENS: &str = "dcrTokens";

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

/// DCR 登録クライアントを clients/{client_id} へ保存する。
/// client_id は新規採番の一意値なので create_if_absent で既存を上書きしない
/// （万一の衝突は false → エラーにして静かな破壊を防ぐ）。
pub async fn save_client(fs: &Firestore, client: &Client) -> Result<(), String> {
    let json = serde_json::to_string(client).map_err(|e| format!("serialize client: {e}"))?;
    let created = fs
        .create_if_absent(
            CLIENTS,
            &client.client_id,
            serde_json::json!({ "json": firestore::s(&json) }),
        )
        .await?;
    if created {
        Ok(())
    } else {
        Err(format!("client {} already exists", client.client_id))
    }
}

/// clients/ 全件を列挙する（管理UIの一覧表示用）。壊れたJSONブロブはスキップする
/// （load_client と同じ fail-closed だが沈黙しない方針）。
pub async fn list_clients(fs: &Firestore) -> Result<Vec<Client>, String> {
    let rows = fs.list_collection(CLIENTS).await?;
    let mut out = Vec::with_capacity(rows.len());
    for (client_id, fields, _update_time) in rows {
        let json = match field_str(&fields, "json") {
            Some(j) => j,
            None => {
                eprintln!("dcr_store: list_clients {client_id}: missing json field");
                continue;
            }
        };
        match serde_json::from_str::<Client>(json) {
            Ok(c) => out.push(c),
            Err(e) => eprintln!("dcr_store: list_clients {client_id}: malformed json blob: {e}"),
        }
    }
    Ok(out)
}

/// IAT 1 件の読み出し結果（制約・期限・updateTime・reusable フラグ）。
pub struct Iat {
    pub constraints: IatConstraints,
    pub expires_at: u64,
    /// CAS 削除に使う直近の updateTime。
    pub update_time: String,
    /// true の場合は単回消費しない（期限内は再利用可）。conformance 専用。
    pub reusable: bool,
}

/// Initial Access Token を dcrTokens/{hash} へ保存する（保存は **ハッシュのみ**、生は持たない）。
/// hash は単回採番なので create_if_absent。
/// `reusable=true` は consume_iat をスキップさせる conformance 専用フラグ（短 TTL 前提）。
pub async fn put_iat(
    fs: &Firestore,
    hash: &str,
    constraints: &IatConstraints,
    expires_at: u64,
    reusable: bool,
) -> Result<(), String> {
    let cj = serde_json::to_string(constraints).map_err(|e| format!("serialize constraints: {e}"))?;
    let created = fs
        .create_if_absent(
            DCR_TOKENS,
            hash,
            serde_json::json!({
                "constraints": firestore::s(&cj),
                "expires_at": firestore::int(expires_at),
                "reusable": firestore::b(reusable),
            }),
        )
        .await?;
    if created {
        Ok(())
    } else {
        Err("initial access token already exists".into())
    }
}

/// dcrTokens/ ドキュメントの共通フィールド解析（peek_iat / list_pending_iats で共有）。
fn parse_iat_fields(fields: &serde_json::Value) -> Result<(IatConstraints, u64, bool), String> {
    let cj = field_str(fields, "constraints").ok_or("iat: missing constraints")?;
    let constraints: IatConstraints =
        serde_json::from_str(cj).map_err(|e| format!("iat constraints: {e}"))?;
    let expires_at = field_u64(fields, "expires_at").unwrap_or(0);
    let reusable = field_bool(fields, "reusable").unwrap_or(false);
    Ok((constraints, expires_at, reusable))
}

/// IAT を読むが消費はしない（制約・期限・updateTime・reusable を返す）。
/// 単回消費は検証成功後に consume_iat(CAS 削除) で行う（reusable=true なら呼ばない）。
pub async fn peek_iat(fs: &Firestore, hash: &str) -> Result<Option<Iat>, String> {
    let (fields, update_time) = match fs.get_doc_with_update_time(DCR_TOKENS, hash).await? {
        Some(x) => x,
        None => return Ok(None),
    };
    let (constraints, expires_at, reusable) = parse_iat_fields(&fields)?;
    Ok(Some(Iat { constraints, expires_at, update_time, reusable }))
}

/// IAT を単回消費する（updateTime CAS 削除）。勝てば Ok(true)、並行消費・既消費は Ok(false)。
pub async fn consume_iat(fs: &Firestore, hash: &str, update_time: &str) -> Result<bool, String> {
    fs.delete_doc_if_unchanged(DCR_TOKENS, hash, update_time).await
}

/// 未消費IATの一覧（管理UI用）。1件の読み出し結果に doc id(hash) を添えたもの。
pub struct PendingIat {
    pub hash: String,
    pub constraints: IatConstraints,
    pub expires_at: u64,
    pub reusable: bool,
    /// revoke（consume_iat の CAS 削除）に使う。
    pub update_time: String,
}

/// dcrTokens/ 全件を列挙する（管理UIの「未消費IAT一覧」表示用）。期限切れの除外はしない
/// （表示するかどうかは呼び出し側の判断に委ねる）。壊れたドキュメントはスキップする
/// （load_client/peek_iat と同じ fail-closed だが沈黙しない方針）。
pub async fn list_pending_iats(fs: &Firestore) -> Result<Vec<PendingIat>, String> {
    let rows = fs.list_collection(DCR_TOKENS).await?;
    let mut out = Vec::with_capacity(rows.len());
    for (hash, fields, update_time) in rows {
        match parse_iat_fields(&fields) {
            Ok((constraints, expires_at, reusable)) => {
                out.push(PendingIat { hash, constraints, expires_at, reusable, update_time });
            }
            Err(e) => eprintln!("dcr_store: list_pending_iats {hash}: {e}"),
        }
    }
    Ok(out)
}

/// 登録クライアントを revoke する（clients/{id} 削除）。存在したら Ok(true)、無ければ Ok(false)。
///
/// 失効の意味論（明示）: 削除後 resolve_client は None を返すため
/// **新規認可（PAR/authorize/token）と refresh（token endpoint で private_key_jwt 再認証 →
/// unknown_client）は即座に失敗**する。一方 **発行済みアクセストークンは TTL（≤900s/15分、
/// ACCESS_TTL）まで有効**——userinfo/introspection のトークン検証はクライアント存在を
/// 再解決しないため。即時に AT も殺すには AT doc の client_id クエリ削除が必要だが、
/// 15 分窓は許容として v1 では client doc 削除に留める。
pub async fn revoke_client(fs: &Firestore, client_id: &str) -> Result<bool, String> {
    let existed = fs.get_doc(CLIENTS, client_id).await?.is_some();
    if existed {
        fs.delete_doc(CLIENTS, client_id).await?;
    }
    Ok(existed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firestore::fake_firestore;
    use crate::model::Client;

    fn constraints() -> IatConstraints {
        IatConstraints {
            allowed_redirect_hosts: vec!["rp.example.com".into()],
            allowed_grant_types: vec!["authorization_code".into()],
            profile: crate::dcr::ClientProfile::ConfidentialKey,
        }
    }

    fn client(id: &str) -> Client {
        Client {
            client_id: id.to_string(),
            redirect_uris: vec!["https://rp.example.com/cb".into()],
            post_logout_redirect_uris: vec![],
            token_endpoint_auth_method: "private_key_jwt".into(),
            client_secret: None,
            grant_types: vec!["authorization_code".into()],
            dpop_bound: true,
            jwks: vec![],
            jwks_uri: None,
            require_par: true,
            require_pkce: true,
            id_token_signed_response_alg: None,
        }
    }

    #[tokio::test]
    async fn save_then_load_client_roundtrips() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);

        save_client(&fs, &client("dcr-1")).await.unwrap();
        let loaded = load_client(&fs, "dcr-1").await.unwrap();
        assert_eq!(loaded.client_id, "dcr-1");
        assert_eq!(loaded.token_endpoint_auth_method, "private_key_jwt");

        assert!(load_client(&fs, "unknown").await.is_none());
    }

    #[tokio::test]
    async fn save_client_rejects_client_id_collision() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);

        save_client(&fs, &client("dcr-dup")).await.unwrap();
        // 万一同じ client_id が再度採番されても、create_if_absent が既存を上書きしない
        // （静かな破壊を防ぐ設計。dcr_store.rs の save_client のコメント通り）。
        let second = client("dcr-dup");
        let err = save_client(&fs, &second).await.unwrap_err();
        assert!(err.contains("already exists"));
    }

    #[tokio::test]
    async fn consume_iat_succeeds_once_then_rejects_reuse() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        let hash = "hash-1";

        put_iat(&fs, hash, &constraints(), 9_999_999_999, false).await.unwrap();
        let iat = peek_iat(&fs, hash).await.unwrap().unwrap();
        assert_eq!(iat.constraints.allowed_redirect_hosts, vec!["rp.example.com"]);
        assert!(!iat.reusable);

        // 検証成功後の単回消費(CAS 削除)。
        let consumed = consume_iat(&fs, hash, &iat.update_time).await.unwrap();
        assert!(consumed, "初回消費は勝つ");

        // 同じトークンでの再利用(リプレイ)は、ドキュメントが既に消えているため負ける。
        let replay = consume_iat(&fs, hash, &iat.update_time).await.unwrap();
        assert!(!replay, "消費済み IAT の再利用は拒否される");
        assert!(peek_iat(&fs, hash).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn consume_iat_loses_when_update_time_is_stale() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        let hash = "hash-2";

        put_iat(&fs, hash, &constraints(), 9_999_999_999, false).await.unwrap();
        let stale = peek_iat(&fs, hash).await.unwrap().unwrap();
        // 間に別のリクエストが割り込んで再書き込みされた状況を模す(実際には put_iat は
        // create_if_absent なので同一ドキュメントの再書き込みは通常起きないが、
        // updateTime CAS 自体の防御が効くことを確認する)。
        let fresh = peek_iat(&fs, hash).await.unwrap().unwrap();
        assert_eq!(stale.update_time, fresh.update_time, "この時点では同一のはず");

        // 明らかに古い(存在しない)updateTime を渡すと必ず負ける。
        let lost = consume_iat(&fs, hash, "v-does-not-exist").await.unwrap();
        assert!(!lost);
        assert!(peek_iat(&fs, hash).await.unwrap().is_some(), "負けた場合は削除されない");
    }

    #[tokio::test]
    async fn put_iat_rejects_hash_collision() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        put_iat(&fs, "dup-hash", &constraints(), 1, false).await.unwrap();
        let err = put_iat(&fs, "dup-hash", &constraints(), 2, false).await.unwrap_err();
        assert!(err.contains("already exists"));
    }

    #[tokio::test]
    async fn revoke_client_deletes_and_reports_existence() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);

        assert!(!revoke_client(&fs, "nope").await.unwrap(), "存在しないクライアントは false");

        save_client(&fs, &client("dcr-rev")).await.unwrap();
        assert!(revoke_client(&fs, "dcr-rev").await.unwrap());
        assert!(load_client(&fs, "dcr-rev").await.is_none(), "失効後は解決できない");
        assert!(!revoke_client(&fs, "dcr-rev").await.unwrap(), "二重失効は false(冪等)");
    }

    #[tokio::test]
    async fn list_clients_returns_all_and_skips_malformed() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        save_client(&fs, &client("dcr-list-1")).await.unwrap();
        save_client(&fs, &client("dcr-list-2")).await.unwrap();
        // json フィールドを持たない壊れたドキュメントを直接差し込む。
        fs.set_doc(CLIENTS, "broken", serde_json::json!({})).await.unwrap();

        let mut ids: Vec<String> =
            list_clients(&fs).await.unwrap().into_iter().map(|c| c.client_id).collect();
        ids.sort();
        assert_eq!(ids, vec!["dcr-list-1", "dcr-list-2"], "壊れたドキュメントはスキップされる");
    }

    #[tokio::test]
    async fn list_clients_empty_when_none() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        assert!(list_clients(&fs).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn list_pending_iats_returns_all_with_hash_and_update_time() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        put_iat(&fs, "hash-a", &constraints(), 100, false).await.unwrap();
        put_iat(&fs, "hash-b", &constraints(), 200, true).await.unwrap();

        let mut list = list_pending_iats(&fs).await.unwrap();
        list.sort_by(|a, b| a.hash.cmp(&b.hash));
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].hash, "hash-a");
        assert_eq!(list[0].expires_at, 100);
        assert!(!list[0].reusable);
        assert!(!list[0].update_time.is_empty());
        assert_eq!(list[1].hash, "hash-b");
        assert!(list[1].reusable);
    }

    #[tokio::test]
    async fn list_pending_iats_skips_malformed_and_reflects_consume() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        put_iat(&fs, "hash-ok", &constraints(), 100, false).await.unwrap();
        // constraints フィールドを持たない壊れたドキュメントを直接差し込む。
        fs.set_doc(DCR_TOKENS, "broken", serde_json::json!({})).await.unwrap();

        let list = list_pending_iats(&fs).await.unwrap();
        assert_eq!(list.len(), 1, "壊れたドキュメントはスキップされる");
        assert_eq!(list[0].hash, "hash-ok");

        // revoke(consume_iat)後は一覧から消える(brokenは元々スキップされているので0件になる)。
        consume_iat(&fs, "hash-ok", &list[0].update_time).await.unwrap();
        assert!(list_pending_iats(&fs).await.unwrap().is_empty());
    }
}
