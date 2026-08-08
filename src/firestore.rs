//! Firestore 最小クライアント（REST + metadata サーバのアクセストークン）。
//! Cloud Run のデフォルト SA で 1 ドキュメント単位の set/get/delete のみ提供する。
//!
//! `FIRESTORE_EMULATOR_HOST`（例: `127.0.0.1:8180`）が設定されていれば、公式 SDK 群と同じ
//! 慣習に従いエミュレータへ向く（`firebase emulators:start --only firestore` 等が export する
//! 値をそのまま使える）。エミュレータ実行時は metadata サーバへは一切アクセスしない
//! （ローカルに metadata サーバは存在せず、実 GCP にも絶対に飛ばさないための分岐）。
//!
//! `FIRESTORE_DATABASE_ID`（例: `staging`）が設定されていれば、`(default)` ではなく
//! その名前付きデータベースへ向く。本番と検証環境で同一プロジェクト内の別データベースを
//! 使い分け、staging での動作確認が本番データに一切触れないようにするための分離。

use base64::Engine;
use serde_json::{json, Value};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct Firestore {
    project: String,
    database: String,
    http: reqwest::Client,
    token: Mutex<Option<(String, Instant)>>,
    emulator_host: Option<String>,
}

/// 型付きフィールド値のヘルパー（Firestore REST の Value 表現）。
pub fn s(v: &str) -> Value {
    json!({ "stringValue": v })
}
pub fn ts(v: &str) -> Value {
    json!({ "timestampValue": v })
}
pub fn b(v: bool) -> Value {
    json!({ "booleanValue": v })
}
pub fn int(v: u64) -> Value {
    json!({ "integerValue": v.to_string() })
}

/// fields から整数値（integerValue は文字列で来る）。
pub fn field_u64(fields: &Value, name: &str) -> Option<u64> {
    fields.get(name)?.get("integerValue")?.as_str()?.parse().ok()
}

/// fields から bool。未存在は None（呼び出し側が unwrap_or(false) する）。
pub fn field_bool(fields: &Value, name: &str) -> Option<bool> {
    fields.get(name)?.get("booleanValue")?.as_bool()
}

/// fields から timestampValue を epoch 秒で。
pub fn field_ts_secs(fields: &Value, name: &str) -> Option<u64> {
    Some(parse_rfc3339_secs(
        fields.get(name)?.get("timestampValue")?.as_str()?,
    ))
}

/// RFC3339 (UTC, 秒精度) を epoch 秒から組み立てる。chrono を入れずに済ます。
pub fn rfc3339(epoch_secs: u64) -> String {
    // 1970-01-01 起点の日付計算。
    let days = epoch_secs / 86400;
    let rem = epoch_secs % 86400;
    let (h, mi, sec) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{y:04}-{mo:02}-{d:02}T{h:02}:{mi:02}:{sec:02}Z")
}

// Howard Hinnant の civil_from_days アルゴリズム。
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// RFC3339 (秒精度, 末尾 Z) を epoch 秒へ。失敗時 0。
pub fn parse_rfc3339_secs(s: &str) -> u64 {
    if s.len() < 19 {
        return 0;
    }
    let num = |a: usize, b: usize| -> i64 { s[a..b].parse().unwrap_or(0) };
    let (y, mo, d) = (num(0, 4), num(5, 7), num(8, 10));
    let (h, mi, sec) = (num(11, 13), num(14, 16), num(17, 19));
    days_from_civil(y, mo as u32, d as u32) as u64 * 86400
        + (h as u64) * 3600
        + (mi as u64) * 60
        + sec as u64
}

fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = if m > 2 { m - 3 } else { m + 9 } as i64;
    let doy = (153 * mp + 2) / 5 + d as i64 - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

fn enc(id: &str) -> String {
    // ドキュメント ID をパスに埋めるため最小限の percent-encode（'@' '/' 等）。
    id.bytes()
        .map(|c| match c {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (c as char).to_string()
            }
            _ => format!("%{c:02X}"),
        })
        .collect()
}

/// 空文字列(未設定同然)を "(default)" へフォールバックせず素通しすると databases// の
/// ような壊れた URL になり全リクエストが失敗するため、空も未設定扱いにする。
/// env を直接読まない純粋関数にしているのは、値を変えたテストで set_var（並行テスト間で
/// 競合する）を使わずに済ませるため。
fn resolve_database(raw: Result<String, std::env::VarError>) -> String {
    raw.ok().filter(|v| !v.is_empty()).unwrap_or_else(|| "(default)".into())
}

impl Firestore {
    pub fn new(project: impl Into<String>) -> Self {
        let project = project.into();
        let database = resolve_database(std::env::var("FIRESTORE_DATABASE_ID"));
        // grant-admin 等の管理系CLIは起動が一瞬で終わり tracing 初期化前に走るため、
        // どの project/database へ書き込んだかが分かる唯一の手段として常に出す。
        eprintln!("firestore: project={project} database={database}");
        Self {
            project,
            database,
            http: reqwest::Client::new(),
            token: Mutex::new(None),
            emulator_host: std::env::var("FIRESTORE_EMULATOR_HOST").ok(),
        }
    }

    /// テスト専用: プロセス全体のグローバル状態である環境変数を触らずに、任意のホストへ向ける。
    /// 並行実行されるテストが FIRESTORE_EMULATOR_HOST の set/unset で競合するのを避けるため。
    #[cfg(test)]
    pub(crate) fn new_for_test(project: impl Into<String>, emulator_host: impl Into<String>) -> Self {
        Self {
            project: project.into(),
            database: "(default)".into(),
            http: reqwest::Client::new(),
            token: Mutex::new(None),
            emulator_host: Some(emulator_host.into()),
        }
    }

    pub(crate) fn project(&self) -> &str {
        &self.project
    }

    pub(crate) async fn token(&self) -> Result<String, String> {
        // エミュレータは Authorization の中身を検証しない。ここで即 return することで
        // metadata サーバへの到達を試みない（ローカルには無いので失敗するだけ）。
        if self.emulator_host.is_some() {
            return Ok("owner".to_string());
        }
        {
            let g = self.token.lock().unwrap();
            if let Some((t, exp)) = g.as_ref() {
                if *exp > Instant::now() {
                    return Ok(t.clone());
                }
            }
        }
        let resp = self
            .http
            .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
            .header("Metadata-Flavor", "Google")
            .send()
            .await
            .map_err(|e| format!("metadata: {e}"))?;
        let j: Value = resp.json().await.map_err(|e| format!("metadata json: {e}"))?;
        let tok = j["access_token"].as_str().ok_or("no access_token")?.to_string();
        let ttl = j["expires_in"].as_u64().unwrap_or(3000);
        *self.token.lock().unwrap() =
            Some((tok.clone(), Instant::now() + Duration::from_secs(ttl.saturating_sub(60))));
        Ok(tok)
    }

    // エミュレータ設定時は http://{host} へ、それ以外は実 Firestore へ。REST パス形状は同一。
    fn base_url(&self) -> String {
        self.base_url_or("firestore.googleapis.com")
    }

    /// Firestore 以外の Google API（fcm.rs 等）向け。エミュレータ設定時は同じテスト用サーバへ、
    /// それ以外は指定した実ホストへ向ける。`Firestore` は project/token を一元管理する薄い
    /// ハブとして使われているため、外部 API 呼び出し側もここ経由でホスト切替を再利用する。
    pub(crate) fn base_url_or(&self, real_host: &str) -> String {
        match &self.emulator_host {
            Some(host) => format!("http://{host}"),
            None => format!("https://{real_host}"),
        }
    }

    // ドキュメント URL にはドキュメント ID が入る。ID は accounts/profiles では email/sub（＝PII）。
    // reqwest の Error::Display は URL を ` for url (...)` として必ず付加する（0.12 系）ため、
    // この URL を使う送受信エラーは必ず `e.without_url()` でログから ID を落とす。
    fn doc_url(&self, col: &str, id: &str) -> String {
        format!(
            "{}/v1/projects/{}/databases/{}/documents/{}/{}",
            self.base_url(),
            self.project,
            self.database,
            col,
            enc(id),
        )
    }

    /// 指定 ID で create/update（PATCH は冪等）。
    pub async fn set_doc(&self, col: &str, id: &str, fields: Value) -> Result<(), String> {
        let tok = self.token().await?;
        let r = self
            .http
            .patch(self.doc_url(col, id))
            .bearer_auth(tok)
            .json(&json!({ "fields": fields }))
            .send()
            .await
            .map_err(|e| format!("set: {}", e.without_url()))?;
        if r.status().is_success() {
            Ok(())
        } else {
            Err(format!("set {} {}", r.status(), r.text().await.unwrap_or_default()))
        }
    }

    /// 指定した1フィールドだけを部分更新する(updateMask)。他のフィールドには一切触れない。
    /// `set_doc` は毎回全フィールドを送る全体置換のため、同じドキュメントへ複数の書き込み経路が
    /// 並行して「読む→1フィールドだけ変える→全体を書き戻す」をやると、後勝ちの書き込みが
    /// 相手の変更（別フィールド）を丸ごと巻き戻す事故になる。updateTime による楽観ロックCASで
    /// 守る手もあるが、実 Firestore エミュレータは updateTime の一致判定を正しく実装しておらず
    /// 常に precondition failed になる（curl で確認済み。exists 判定は正常）ため、ここでは
    /// フィールド単位の部分更新そのもので競合を起こさない設計にする。ドキュメントが存在しない
    /// 場合はエラーにする（新規作成はしない。呼び出し側は既存ドキュメントの更新用に使うこと）。
    pub async fn update_field(&self, col: &str, id: &str, field: &str, value: Value) -> Result<(), String> {
        let tok = self.token().await?;
        let r = self
            .http
            .patch(self.doc_url(col, id))
            .query(&[("updateMask.fieldPaths", field), ("currentDocument.exists", "true")])
            .bearer_auth(tok)
            .json(&json!({ "fields": { field: value } }))
            .send()
            .await
            .map_err(|e| format!("update_field: {}", e.without_url()))?;
        if r.status().is_success() {
            Ok(())
        } else {
            Err(format!("update_field {} {}", r.status(), r.text().await.unwrap_or_default()))
        }
    }

    /// ドキュメントの fields を返す（無ければ None）。
    pub async fn get_doc(&self, col: &str, id: &str) -> Result<Option<Value>, String> {
        let tok = self.token().await?;
        let r = self
            .http
            .get(self.doc_url(col, id))
            .bearer_auth(tok)
            .send()
            .await
            .map_err(|e| format!("get: {}", e.without_url()))?;
        if r.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !r.status().is_success() {
            return Err(format!("get {}", r.status()));
        }
        let j: Value = r.json().await.map_err(|e| format!("get json: {}", e.without_url()))?;
        Ok(j.get("fields").cloned())
    }

    /// fields と updateTime を返す（楽観ロック用）。
    pub async fn get_doc_with_update_time(
        &self,
        col: &str,
        id: &str,
    ) -> Result<Option<(Value, String)>, String> {
        let tok = self.token().await?;
        let r = self
            .http
            .get(self.doc_url(col, id))
            .bearer_auth(tok)
            .send()
            .await
            .map_err(|e| format!("get: {}", e.without_url()))?;
        if r.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !r.status().is_success() {
            return Err(format!("get {}", r.status()));
        }
        let j: Value = r.json().await.map_err(|e| format!("get json: {}", e.without_url()))?;
        let fields = j.get("fields").cloned().unwrap_or(Value::Null);
        let update_time = j.get("updateTime").and_then(|v| v.as_str()).unwrap_or("").to_string();
        Ok(Some((fields, update_time)))
    }

    /// updateTime が一致するときだけ全体置換する（compare-and-set）。
    /// 一致＝成功で Ok(true)、別の書き込みで更新済み（FAILED_PRECONDITION）なら Ok(false)。
    /// CIBA の「先勝ち」状態遷移に使う。
    pub async fn set_doc_if_unchanged(
        &self,
        col: &str,
        id: &str,
        fields: Value,
        update_time: &str,
    ) -> Result<bool, String> {
        let tok = self.token().await?;
        let r = self
            .http
            .patch(self.doc_url(col, id))
            .query(&[("currentDocument.updateTime", update_time)])
            .bearer_auth(tok)
            .json(&json!({ "fields": fields }))
            .send()
            .await
            .map_err(|e| format!("cas: {}", e.without_url()))?;
        if r.status().is_success() {
            return Ok(true);
        }
        // updateTime 不一致（他者が先に更新）は FAILED_PRECONDITION（400/409）。レースに負けた。
        if r.status() == reqwest::StatusCode::BAD_REQUEST
            || r.status() == reqwest::StatusCode::CONFLICT
            || r.status() == reqwest::StatusCode::PRECONDITION_FAILED
        {
            return Ok(false);
        }
        Err(format!("cas {}", r.status()))
    }

    /// ドキュメントが存在しないときだけ作成する（atomic な単回作成）。
    /// 作成できたら Ok(true)、既に存在（ALREADY_EXISTS / FAILED_PRECONDITION）なら Ok(false)。
    /// jti / nonce の分散リプレイ防止に使う（インスタンス跨ぎで単回を保証）。
    pub async fn create_if_absent(&self, col: &str, id: &str, fields: Value) -> Result<bool, String> {
        let tok = self.token().await?;
        let r = self
            .http
            .patch(self.doc_url(col, id))
            .query(&[("currentDocument.exists", "false")])
            .bearer_auth(tok)
            .json(&json!({ "fields": fields }))
            .send()
            .await
            .map_err(|e| format!("create_if_absent: {}", e.without_url()))?;
        if r.status().is_success() {
            return Ok(true);
        }
        if r.status() == reqwest::StatusCode::BAD_REQUEST
            || r.status() == reqwest::StatusCode::CONFLICT
            || r.status() == reqwest::StatusCode::PRECONDITION_FAILED
        {
            return Ok(false);
        }
        Err(format!("create_if_absent {}", r.status()))
    }

    /// updateTime が一致するときだけ削除する（compare-and-set 削除）。
    /// 削除できたら Ok(true)、他者が先に更新/削除（FAILED_PRECONDITION / NOT_FOUND）なら Ok(false)。
    /// CIBA poll の「承認の単回消費」を原子的に行うために使う。
    pub async fn delete_doc_if_unchanged(
        &self,
        col: &str,
        id: &str,
        update_time: &str,
    ) -> Result<bool, String> {
        let tok = self.token().await?;
        let r = self
            .http
            .delete(self.doc_url(col, id))
            .query(&[("currentDocument.updateTime", update_time)])
            .bearer_auth(tok)
            .send()
            .await
            .map_err(|e| format!("cas delete: {}", e.without_url()))?;
        if r.status().is_success() {
            return Ok(true);
        }
        if r.status() == reqwest::StatusCode::BAD_REQUEST
            || r.status() == reqwest::StatusCode::CONFLICT
            || r.status() == reqwest::StatusCode::PRECONDITION_FAILED
            || r.status() == reqwest::StatusCode::NOT_FOUND
        {
            return Ok(false);
        }
        Err(format!("cas delete {}", r.status()))
    }

    /// 単一フィールド完全一致のクエリ。各ドキュメントの (id, fields) を返す。
    pub async fn query_eq(
        &self,
        col: &str,
        field: &str,
        value: &str,
    ) -> Result<Vec<(String, Value)>, String> {
        let tok = self.token().await?;
        let url = format!(
            "{}/v1/projects/{}/databases/{}/documents:runQuery",
            self.base_url(),
            self.project,
            self.database
        );
        let body = json!({
            "structuredQuery": {
                "from": [{ "collectionId": col }],
                "where": {
                    "fieldFilter": {
                        "field": { "fieldPath": field },
                        "op": "EQUAL",
                        "value": { "stringValue": value }
                    }
                }
            }
        });
        let r = self
            .http
            .post(url)
            .bearer_auth(tok)
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("query: {e}"))?;
        if !r.status().is_success() {
            return Err(format!("query {}", r.status()));
        }
        let arr: Value = r.json().await.map_err(|e| format!("query json: {e}"))?;
        Ok(arr
            .as_array()
            .map(|rows| {
                rows.iter()
                    .filter_map(|row| {
                        let doc = row.get("document")?;
                        let name = doc.get("name")?.as_str()?;
                        let id = name.rsplit('/').next()?.to_string();
                        let fields = doc.get("fields").cloned().unwrap_or(json!({}));
                        Some((id, fields))
                    })
                    .collect()
            })
            .unwrap_or_default())
    }

    /// Secret Manager の最新バージョンを読む（metadata トークンを流用）。
    /// 存在しない/権限なしは Ok(None)。payload は UTF-8 文字列として返す。
    pub async fn access_secret(&self, name: &str) -> Result<Option<String>, String> {
        let tok = self.token().await?;
        let url = format!(
            "https://secretmanager.googleapis.com/v1/projects/{}/secrets/{}/versions/latest:access",
            self.project, name,
        );
        let r = self
            .http
            .get(url)
            .bearer_auth(tok)
            .send()
            .await
            .map_err(|e| format!("secret: {e}"))?;
        if r.status() == reqwest::StatusCode::NOT_FOUND
            || r.status() == reqwest::StatusCode::FORBIDDEN
        {
            return Ok(None);
        }
        if !r.status().is_success() {
            return Err(format!("secret {}", r.status()));
        }
        let j: Value = r.json().await.map_err(|e| format!("secret json: {e}"))?;
        let data_b64 = j["payload"]["data"]
            .as_str()
            .ok_or("secret: no payload.data")?;
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(data_b64)
            .map_err(|e| format!("secret b64: {e}"))?;
        Ok(Some(String::from_utf8_lossy(&bytes).into_owned()))
    }

    pub async fn delete_doc(&self, col: &str, id: &str) -> Result<(), String> {
        let tok = self.token().await?;
        let r = self
            .http
            .delete(self.doc_url(col, id))
            .bearer_auth(tok)
            .send()
            .await
            .map_err(|e| format!("delete: {}", e.without_url()))?;
        if r.status().is_success() || r.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(format!("delete {}", r.status()))
        }
    }

    /// 指定フィールドのみを部分更新（updateMask 付き PATCH）。他フィールドは保持される。
    /// set_doc は updateMask 無しで全体置換になるため、既存ドキュメントへの追記はこちらを使う。
    pub async fn merge_doc(&self, col: &str, id: &str, fields: Value) -> Result<(), String> {
        let tok = self.token().await?;
        let keys: Vec<String> = fields
            .as_object()
            .map(|o| o.keys().cloned().collect())
            .unwrap_or_default();
        let query: Vec<(&str, &str)> =
            keys.iter().map(|k| ("updateMask.fieldPaths", k.as_str())).collect();
        let r = self
            .http
            .patch(self.doc_url(col, id))
            .query(&query)
            .bearer_auth(tok)
            .json(&json!({ "fields": fields }))
            .send()
            .await
            .map_err(|e| format!("merge: {}", e.without_url()))?;
        if r.status().is_success() {
            Ok(())
        } else {
            Err(format!("merge {} {}", r.status(), r.text().await.unwrap_or_default()))
        }
    }
}

/// fields から文字列値を取り出す。
pub fn field_str<'a>(fields: &'a Value, name: &str) -> Option<&'a str> {
    fields.get(name)?.get("stringValue")?.as_str()
}

/// firestore.rs / fcm.rs のクライアント側ロジック（プリコンディションの送信・レスポンス解釈・
/// 送信先ホストの切替）を検証するための最小フェイクサーバ。`firestore::tests` と `fcm::tests`
/// の双方から再利用するため、`mod tests` の外に置く。
///
/// なぜ実 Firestore エミュレータを使わないか: 手元の Firestore エミュレータは
/// `currentDocument.updateTime` による楽観ロック CAS を正しく実装していない
/// （RFC3339 文字列を数値バージョンとして誤解釈し、常に FAILED_PRECONDITION になる。
/// `currentDocument.exists=false` の CAS は正常動作することを curl で確認済み）。
/// CIBA 承認・リフレッシュトークンのローテーション検知・RAR mandate の単回消費など、
/// この「先勝ち」機構に依存するコードの安全性は本番の生 Firestore が正しく実装している
/// 前提に立っており、その前提自体はここでは検証しない（Google の REST API 契約として
/// 別途信頼する）。ここで検証するのは「クライアント側(このクレート)がプリコンディションを
/// 正しく送り、勝敗のレスポンスを正しく解釈するか」「fcm.rs が Firestore とは別ホストへ
/// 正しく POST するか」という、実際にこのコードベースがバグを混入しうる部分に限定する。
#[cfg(test)]
pub(crate) mod fake_firestore {
    use axum::extract::{Path, Query, State};
    use axum::http::StatusCode;
    use axum::response::{IntoResponse, Response};
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use serde_json::{json, Value};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    struct Doc {
        fields: Value,
        update_time: u64,
    }

    #[derive(Default)]
    pub struct FakeState {
        docs: Mutex<HashMap<(String, String), Doc>>,
        next_version: Mutex<u64>,
        /// fcm.rs の send() が投げた message body をそのまま記録する（identifier 一貫性の検証用）。
        fcm_sent: Mutex<Vec<Value>>,
    }

    impl FakeState {
        fn next(&self) -> u64 {
            let mut n = self.next_version.lock().unwrap();
            *n += 1;
            *n
        }

        pub fn fcm_sent_messages(&self) -> Vec<Value> {
            self.fcm_sent.lock().unwrap().clone()
        }
    }

    fn version_str(v: u64) -> String {
        format!("v{v}")
    }

    #[derive(serde::Deserialize, Default)]
    struct Precondition {
        #[serde(rename = "currentDocument.updateTime")]
        update_time: Option<String>,
        #[serde(rename = "currentDocument.exists")]
        exists: Option<String>,
        /// Firestore::update_field が使う部分更新。実装が単一フィールドしか送らないため
        /// Vec ではなく単一値として受ける（複数フィールドのマスクは今のところ未使用）。
        #[serde(rename = "updateMask.fieldPaths")]
        update_mask_field: Option<String>,
    }

    async fn get_doc(
        State(st): State<Arc<FakeState>>,
        Path((_project, col, id)): Path<(String, String, String)>,
    ) -> Response {
        let docs = st.docs.lock().unwrap();
        match docs.get(&(col, id)) {
            Some(d) => {
                Json(json!({ "fields": d.fields, "updateTime": version_str(d.update_time) }))
                    .into_response()
            }
            None => StatusCode::NOT_FOUND.into_response(),
        }
    }

    async fn patch_doc(
        State(st): State<Arc<FakeState>>,
        Path((_project, col, id)): Path<(String, String, String)>,
        Query(pre): Query<Precondition>,
        Json(body): Json<Value>,
    ) -> Response {
        let mut docs = st.docs.lock().unwrap();
        let key = (col, id);
        if let Some(want) = &pre.exists {
            let want_exists = want == "true";
            if docs.contains_key(&key) != want_exists {
                return (StatusCode::CONFLICT, "precondition failed: exists").into_response();
            }
        }
        if let Some(want_ut) = &pre.update_time {
            match docs.get(&key) {
                Some(d) if version_str(d.update_time) == *want_ut => {}
                _ => {
                    return (StatusCode::BAD_REQUEST, "precondition failed: updateTime")
                        .into_response()
                }
            }
        }
        let fields = body.get("fields").cloned().unwrap_or_else(|| json!({}));
        let v = st.next();
        // updateMask 指定時は、既存ドキュメントの他フィールドを残したまま該当フィールドだけ
        // 差し替える(部分更新)。指定が無ければ従来通り全体置換。
        let merged = if let Some(field) = &pre.update_mask_field {
            let mut base = docs.get(&key).map(|d| d.fields.clone()).unwrap_or_else(|| json!({}));
            if let Some(obj) = base.as_object_mut() {
                if let Some(new_val) = fields.get(field) {
                    obj.insert(field.clone(), new_val.clone());
                }
            }
            base
        } else {
            fields
        };
        docs.insert(key, Doc { fields: merged.clone(), update_time: v });
        Json(json!({ "fields": merged, "updateTime": version_str(v) })).into_response()
    }

    async fn delete_doc(
        State(st): State<Arc<FakeState>>,
        Path((_project, col, id)): Path<(String, String, String)>,
        Query(pre): Query<Precondition>,
    ) -> Response {
        let mut docs = st.docs.lock().unwrap();
        let key = (col, id);
        if let Some(want_ut) = &pre.update_time {
            match docs.get(&key) {
                Some(d) if version_str(d.update_time) == *want_ut => {}
                _ => {
                    return (StatusCode::BAD_REQUEST, "precondition failed: updateTime")
                        .into_response()
                }
            }
        }
        docs.remove(&key);
        StatusCode::OK.into_response()
    }

    /// fcm.rs::send() が叩く `POST /v1/projects/{project}/messages:send` を模す。
    /// 実際に外部へは送らず、message body を記録して 200 を返すだけ。
    async fn fcm_send(
        State(st): State<Arc<FakeState>>,
        Json(body): Json<Value>,
    ) -> Response {
        st.fcm_sent.lock().unwrap().push(body);
        Json(json!({ "name": "projects/fake/messages/1" })).into_response()
    }

    /// `Firestore::query_eq` が叩く `POST .../documents:runQuery` を模す。単一の
    /// fieldFilter(EQUAL, stringValue) のみサポート（実装側が送るのはこの形だけ）。
    async fn run_query(
        State(st): State<Arc<FakeState>>,
        Path(_project): Path<String>,
        Json(body): Json<Value>,
    ) -> Response {
        let sq = &body["structuredQuery"];
        let col = sq["from"][0]["collectionId"].as_str().unwrap_or("").to_string();
        let field = sq["where"]["fieldFilter"]["field"]["fieldPath"].as_str().unwrap_or("").to_string();
        let want = sq["where"]["fieldFilter"]["value"]["stringValue"].as_str().unwrap_or("").to_string();
        let docs = st.docs.lock().unwrap();
        let rows: Vec<Value> = docs
            .iter()
            .filter(|((c, _id), _)| *c == col)
            .filter(|(_, d)| {
                d.fields.get(&field).and_then(|v| v.get("stringValue")).and_then(|v| v.as_str())
                    == Some(want.as_str())
            })
            .map(|((c, id), d)| {
                json!({ "document": { "name": format!("projects/fake/databases/(default)/documents/{c}/{id}"), "fields": d.fields } })
            })
            .collect();
        Json(rows).into_response()
    }

    /// ランダムな空きポートで起動し `(host:port, 状態ハンドル)` を返す。プロセス終了まで
    /// 生き続ける（テストプロセス全体で共有されるわけではなく、テストごとに専用サーバを1つ立てる）。
    pub async fn spawn() -> (String, Arc<FakeState>) {
        let state = Arc::new(FakeState::default());
        let app = Router::new()
            .route(
                "/v1/projects/{project}/databases/(default)/documents/{col}/{id}",
                get(get_doc).patch(patch_doc).delete(delete_doc),
            )
            .route("/v1/projects/{project}/messages:send", post(fcm_send))
            .route(
                "/v1/projects/{project}/databases/(default)/documents:runQuery",
                post(run_query),
            )
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (format!("127.0.0.1:{}", addr.port()), state)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_database_falls_back_on_missing_or_empty() {
        assert_eq!(resolve_database(Err(std::env::VarError::NotPresent)), "(default)");
        assert_eq!(resolve_database(Ok(String::new())), "(default)");
        assert_eq!(resolve_database(Ok("staging".into())), "staging");
    }

    #[test]
    fn base_url_defaults_to_real_firestore_when_env_unset() {
        // このファイル内の他テストは new_for_test に統一済みで env を set しないため、
        // remove_var だけなら並行実行される他テストと競合しない。
        std::env::remove_var("FIRESTORE_EMULATOR_HOST");
        let real = Firestore::new("proj");
        assert_eq!(real.base_url(), "https://firestore.googleapis.com");
        assert!(real.emulator_host.is_none());
    }

    #[test]
    fn base_url_switches_to_emulator_host() {
        // new_for_test はプロセス全体のグローバル状態(環境変数)を触らないので、
        // 他の並行実行テストと競合しない。
        let emu = Firestore::new_for_test("proj", "127.0.0.1:8180");
        assert_eq!(emu.base_url(), "http://127.0.0.1:8180");
    }

    #[tokio::test]
    async fn emulator_token_is_dummy_and_skips_metadata_server() {
        let fs = Firestore::new_for_test("proj", "127.0.0.1:8180");
        // metadata サーバ(http://metadata.google.internal)へは到達不能な環境でも
        // エミュレータ経路なら即座に固定トークンが返る(到達を試みていないことの間接証拠)。
        let tok = fs.token().await.unwrap();
        assert_eq!(tok, "owner");
    }

    /// 実際に `firebase emulators:start --only firestore` を起動した状態で
    /// `FIRESTORE_EMULATOR_HOST=127.0.0.1:<port> cargo test -- --ignored` で実行する。
    /// 通常の `cargo test` では走らない（エミュレータ常駐を前提にしないため）。
    #[tokio::test]
    #[ignore]
    async fn emulator_roundtrip_set_get_delete() {
        let host = std::env::var("FIRESTORE_EMULATOR_HOST")
            .expect("set FIRESTORE_EMULATOR_HOST to run this test, e.g. 127.0.0.1:8180");
        let _ = host;
        let fs = Firestore::new("test-emu-probe");
        fs.set_doc("probeCol", "doc1", json!({ "hello": s("world") })).await.unwrap();
        let got = fs.get_doc("probeCol", "doc1").await.unwrap().unwrap();
        assert_eq!(field_str(&got, "hello"), Some("world"));
        fs.delete_doc("probeCol", "doc1").await.unwrap();
        assert!(fs.get_doc("probeCol", "doc1").await.unwrap().is_none());
    }

    // ドキュメント URL に埋まる ID（accounts/profiles では email = PII）が送受信エラーの
    // ログ文字列へ漏れないことを固定する。without_url を {e} に戻すと落ちる回帰ロック。
    #[tokio::test]
    async fn transport_error_strips_url_with_pii_id() {
        // 閉じたポート(127.0.0.1:1)への接続失敗で URL 付きの reqwest エラーを得る（ネットワーク非依存）。
        let err = reqwest::Client::new()
            .get("http://127.0.0.1:1/v1/documents/accounts/a%40b.com")
            .send()
            .await
            .unwrap_err();
        // 前提の確認: 素の Display は URL（= percent-encode した email）を含む。
        assert!(format!("{err}").contains("a%40b.com"), "precondition: raw error leaks the id");
        // without_url 後は email を一切含まない（%40 も生 @ も）。
        let scrubbed = format!("get: {}", err.without_url());
        assert!(!scrubbed.contains("a%40b.com"), "scrubbed leaked %40 form: {scrubbed}");
        assert!(!scrubbed.contains("a@b.com"), "scrubbed leaked raw form: {scrubbed}");
    }

    #[tokio::test]
    async fn set_doc_if_unchanged_wins_on_match_and_loses_on_stale_update_time() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        fs.set_doc("col", "id1", json!({ "v": int(1) })).await.unwrap();
        let (_, update_time) = fs.get_doc_with_update_time("col", "id1").await.unwrap().unwrap();

        let won = fs
            .set_doc_if_unchanged("col", "id1", json!({ "v": int(2) }), &update_time)
            .await
            .unwrap();
        assert!(won, "matching updateTime should win the CAS");
        let (fields, _) = fs.get_doc_with_update_time("col", "id1").await.unwrap().unwrap();
        assert_eq!(field_u64(&fields, "v"), Some(2));

        // update_time は既に古い(上の書き込みで進んだ)ので、同じ値で再挑戦すると負ける。
        let lost = fs
            .set_doc_if_unchanged("col", "id1", json!({ "v": int(3) }), &update_time)
            .await
            .unwrap();
        assert!(!lost, "stale updateTime should lose the CAS");
        let (fields, _) = fs.get_doc_with_update_time("col", "id1").await.unwrap().unwrap();
        assert_eq!(field_u64(&fields, "v"), Some(2), "loser must not overwrite the winner's value");
    }

    #[tokio::test]
    async fn create_if_absent_succeeds_once_then_loses_race() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        let first = fs.create_if_absent("col", "id2", json!({ "v": int(1) })).await.unwrap();
        assert!(first);
        let second = fs.create_if_absent("col", "id2", json!({ "v": int(99) })).await.unwrap();
        assert!(!second, "create_if_absent on an existing doc must lose");
        let (fields, _) = fs.get_doc_with_update_time("col", "id2").await.unwrap().unwrap();
        assert_eq!(field_u64(&fields, "v"), Some(1), "loser must not overwrite");
    }

    #[tokio::test]
    async fn delete_doc_if_unchanged_wins_on_match_and_loses_on_stale_update_time() {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);
        fs.set_doc("col", "id3", json!({ "v": int(1) })).await.unwrap();
        let (_, stale_update_time) = fs.get_doc_with_update_time("col", "id3").await.unwrap().unwrap();
        // 間に別の書き込みが割り込み updateTime が進む状況を模す
        // (CIBA の承認と拒否が競合するケースなど)。
        fs.set_doc("col", "id3", json!({ "v": int(2) })).await.unwrap();

        let lost = fs.delete_doc_if_unchanged("col", "id3", &stale_update_time).await.unwrap();
        assert!(!lost, "stale updateTime must lose the delete CAS");
        assert!(fs.get_doc("col", "id3").await.unwrap().is_some(), "doc must survive a lost CAS delete");

        let (_, fresh_update_time) = fs.get_doc_with_update_time("col", "id3").await.unwrap().unwrap();
        let won = fs.delete_doc_if_unchanged("col", "id3", &fresh_update_time).await.unwrap();
        assert!(won, "matching updateTime must win the delete CAS");
        assert!(fs.get_doc("col", "id3").await.unwrap().is_none());
    }
}
