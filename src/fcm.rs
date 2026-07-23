//! Firebase Cloud Messaging HTTP v1。CIBA 承認要求を iPhone(fido2demo)に通知する。
//! token は fcmTokens/{account_id} に単一保存（シングルデバイス前提。複数端末では
//! 最後に登録した token だけが生存する）。送信は metadata トークンで v1 を直叩き。

use crate::firestore::{self, Firestore};
use serde_json::{json, Value};
use std::time::{SystemTime, UNIX_EPOCH};

const COL: &str = "fcmTokens";

fn now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

pub async fn save_token(fs: &Firestore, account_id: &str, token: &str, platform: &str) -> Result<(), String> {
    fs.set_doc(
        COL,
        account_id,
        json!({
            "token": firestore::s(token),
            "platform": firestore::s(platform),
            "updatedAt": firestore::ts(&firestore::rfc3339(now())),
        }),
    )
    .await
}

async fn get_token(fs: &Firestore, account_id: &str) -> Result<Option<String>, String> {
    match fs.get_doc(COL, account_id).await? {
        Some(f) => Ok(firestore::field_str(&f, "token").map(|s| s.to_string())),
        None => Ok(None),
    }
}

/// CIBA 承認要求の data メッセージを送る。token 未登録なら no-op（Web 承認に委ねる）。
/// Cloud Run の suspend を避けるため呼び出し側で .await すること。
pub async fn send_ciba_request(
    fs: &Firestore,
    account_id: &str,
    client_id: &str,
    scope: &str,
    binding: &str,
    auth_req_id: &str,
    authorization_details: Option<&str>,
) -> Result<(), String> {
    let token = match get_token(fs, account_id).await? {
        Some(t) => t,
        None => return Ok(()),
    };
    // FCM data は string-only。authorization_details は JSON 文字列をそのまま渡す。
    // fido2demo 側で jsonDecode してから構造化表示する（Mandate を端末で確認できる）。
    let mut data = serde_json::Map::new();
    data.insert("type".into(), json!("ciba_request"));
    data.insert("auth_req_id".into(), json!(auth_req_id));
    data.insert("client_name".into(), json!(client_id));
    data.insert("scope".into(), json!(scope));
    data.insert("binding_message".into(), json!(binding));
    if let Some(ad) = authorization_details {
        data.insert("authorization_details".into(), json!(ad));
    }
    let message = json!({
        "token": token,
        "notification": {
            "title": "ログインの承認",
            "body": format!("{client_id} からのログイン要求があります"),
        },
        "data": data,
        "apns": { "payload": { "aps": { "sound": "default", "mutable-content": 1 } } },
    });
    send(fs, message).await
}

async fn send(fs: &Firestore, message: Value) -> Result<(), String> {
    let access = fs.token().await?;
    let url = format!(
        "{}/v1/projects/{}/messages:send",
        fs.base_url_or("fcm.googleapis.com"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firestore::fake_firestore;

    #[tokio::test]
    async fn send_ciba_request_finds_token_saved_under_same_account_id() {
        let (host, state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);

        // save_token は account_id をキーに保存し、send_ciba_request は同じキーで引く。
        // 別々の場所で同じ識別子(account_id)を渡し続けられているかを検証する
        // (かつて login_hint/email との取り違えでこのキーがズレていたクラスのバグを防ぐ)。
        save_token(&fs, "acct-123", "tok-abc", "ios").await.unwrap();
        send_ciba_request(&fs, "acct-123", "client-1", "openid", "承認してください", "req-1", None)
            .await
            .unwrap();

        let sent = state.fcm_sent_messages();
        assert_eq!(sent.len(), 1, "同じ account_id で保存した token 宛にちょうど1通送られる");
        assert_eq!(sent[0]["message"]["token"], json!("tok-abc"));
        assert_eq!(sent[0]["message"]["data"]["auth_req_id"], json!("req-1"));
    }

    #[tokio::test]
    async fn send_ciba_request_is_noop_when_identifier_does_not_match_saved_token() {
        let (host, state) = fake_firestore::spawn().await;
        let fs = Firestore::new_for_test("proj", host);

        save_token(&fs, "acct-123", "tok-abc", "ios").await.unwrap();
        // account_id ではなく email 等、違う識別子系列で呼ばれた場合を模す。
        // 現状の契約は「見つからなければ静かに no-op」であり、エラーにはならない
        // (呼び出し側のキー取り違えを検知する仕組みは無いことの記録でもある)。
        send_ciba_request(&fs, "someone@example.com", "client-1", "openid", "", "req-2", None)
            .await
            .unwrap();

        assert!(
            state.fcm_sent_messages().is_empty(),
            "識別子が一致しない場合は送信されない(静かな no-op)"
        );
    }
}
