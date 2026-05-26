//! Firestore 最小クライアント（REST + metadata サーバのアクセストークン）。
//! Cloud Run のデフォルト SA で 1 ドキュメント単位の set/get/delete のみ提供する。

use base64::Engine;
use serde_json::{json, Value};
use std::sync::Mutex;
use std::time::{Duration, Instant};

pub struct Firestore {
    project: String,
    http: reqwest::Client,
    token: Mutex<Option<(String, Instant)>>,
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

impl Firestore {
    pub fn new(project: impl Into<String>) -> Self {
        Self {
            project: project.into(),
            http: reqwest::Client::new(),
            token: Mutex::new(None),
        }
    }

    pub(crate) fn project(&self) -> &str {
        &self.project
    }

    pub(crate) async fn token(&self) -> Result<String, String> {
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

    fn doc_url(&self, col: &str, id: &str) -> String {
        format!(
            "https://firestore.googleapis.com/v1/projects/{}/databases/(default)/documents/{}/{}",
            self.project,
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
            .map_err(|e| format!("set: {e}"))?;
        if r.status().is_success() {
            Ok(())
        } else {
            Err(format!("set {} {}", r.status(), r.text().await.unwrap_or_default()))
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
            .map_err(|e| format!("get: {e}"))?;
        if r.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !r.status().is_success() {
            return Err(format!("get {}", r.status()));
        }
        let j: Value = r.json().await.map_err(|e| format!("get json: {e}"))?;
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
            .map_err(|e| format!("get: {e}"))?;
        if r.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !r.status().is_success() {
            return Err(format!("get {}", r.status()));
        }
        let j: Value = r.json().await.map_err(|e| format!("get json: {e}"))?;
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
            .map_err(|e| format!("cas: {e}"))?;
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
            .map_err(|e| format!("cas delete: {e}"))?;
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
            "https://firestore.googleapis.com/v1/projects/{}/databases/(default)/documents:runQuery",
            self.project
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
            .map_err(|e| format!("delete: {e}"))?;
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
            .map_err(|e| format!("merge: {e}"))?;
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
