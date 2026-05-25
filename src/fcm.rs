//! Firebase Cloud Messaging HTTP v1。CIBA 承認要求を iPhone(fido2demo)に通知する。
//! token は fcmTokens/{email} に単一保存（シングルデバイス前提。複数端末では
//! 最後に登録した token だけが生存する）。送信は metadata トークンで v1 を直叩き。

use crate::firestore::{self, Firestore};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

const COL: &str = "fcmTokens";

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

pub async fn save_token(fs: &Firestore, email: &str, token: &str, platform: &str) -> Result<(), String> {
    fs.set_doc(
        COL,
        email,
        json!({
            "token": firestore::s(token),
            "platform": firestore::s(platform),
            "updatedAt": firestore::ts(&firestore::rfc3339(now())),
        }),
    )
    .await
}

async fn get_token(fs: &Firestore, email: &str) -> Result<Option<String>, String> {
    match fs.get_doc(COL, email).await? {
        Some(f) => Ok(firestore::field_str(&f, "token").map(|s| s.to_string())),
        None => Ok(None),
    }
}

/// CIBA 承認要求の data メッセージを送る。token 未登録なら no-op（Web 承認に委ねる）。
/// Cloud Run の suspend を避けるため呼び出し側で .await すること。
pub async fn send_ciba_request(
    fs: &Firestore,
    email: &str,
    client_id: &str,
    scope: &str,
    binding: &str,
    auth_req_id: &str,
) -> Result<(), String> {
    let token = match get_token(fs, email).await? {
        Some(t) => t,
        None => return Ok(()),
    };
    let message = json!({
        "token": token,
        "notification": {
            "title": "ログインの承認",
            "body": format!("{client_id} からのログイン要求があります"),
        },
        "data": {
            "type": "ciba_request",
            "auth_req_id": auth_req_id,
            "client_name": client_id,
            "scope": scope,
            "binding_message": binding,
        },
        "apns": { "payload": { "aps": { "sound": "default", "mutable-content": 1 } } },
    });
    send(fs, message).await
}

async fn send(fs: &Firestore, message: Value) -> Result<(), String> {
    let access = fs.token().await?;
    let url = format!(
        "https://fcm.googleapis.com/v1/projects/{}/messages:send",
        fs.project()
    );
    let r = reqwest::Client::new()
        .post(url)
        .bearer_auth(access)
        .json(&json!({ "message": message }))
        .send()
        .await
        .map_err(|e| format!("fcm: {e}"))?;
    if r.status().is_success() {
        Ok(())
    } else {
        Err(format!("fcm {} {}", r.status(), r.text().await.unwrap_or_default()))
    }
}
