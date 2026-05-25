//! メール送信の概念トレイトと Resend 実装。
//! ローカル用に送らず URL をログに出す LogMailer も用意する。

use async_trait::async_trait;
use serde_json::json;

#[async_trait]
pub trait Mailer: Send + Sync {
    /// 確認 URL 付きのメールを送る。
    async fn send_verification(&self, to: &str, verify_url: &str) -> Result<(), String>;
    /// 既登録ユーザーへの案内（メール列挙対策で本文を分岐）。
    async fn send_already_registered(&self, to: &str) -> Result<(), String>;
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

pub struct ResendMailer {
    api_key: String,
    from: String,
    http: reqwest::Client,
}

impl ResendMailer {
    pub fn new(api_key: String) -> Self {
        Self {
            api_key,
            from: "rust-op <noreply@sonrisa.co.jp>".into(),
            http: reqwest::Client::new(),
        }
    }

    async fn send(&self, to: &str, subject: &str, html: String) -> Result<(), String> {
        let r = self
            .http
            .post("https://api.resend.com/emails")
            .bearer_auth(&self.api_key)
            .json(&json!({ "from": self.from, "to": to, "subject": subject, "html": html }))
            .send()
            .await
            .map_err(|e| format!("resend: {e}"))?;
        if r.status().is_success() {
            Ok(())
        } else {
            Err(format!("resend {} {}", r.status(), r.text().await.unwrap_or_default()))
        }
    }
}

#[async_trait]
impl Mailer for ResendMailer {
    async fn send_verification(&self, to: &str, verify_url: &str) -> Result<(), String> {
        let html = format!(
            r#"<div style="font-family:-apple-system,Helvetica,Arial,sans-serif;color:#222;max-width:560px;margin:auto;padding:24px">
<h2 style="margin:0 0 16px">メールアドレス確認</h2>
<p>登録を完了するには、以下のボタンからパスワードを設定してください。有効期限は15分です。</p>
<p style="margin:24px 0"><a href="{url}" style="display:inline-block;background:#3367d6;color:#fff;padding:14px 24px;border-radius:8px;text-decoration:none;font-weight:600">パスワードを設定して登録</a></p>
<p style="font-size:13px;color:#666">心当たりがない場合はこのメールを無視してください。</p>
</div>"#,
            url = escape(verify_url)
        );
        self.send(to, "【rust-op】メールアドレス確認 / Verify your email", html).await
    }

    async fn send_already_registered(&self, to: &str) -> Result<(), String> {
        let html = format!(
            r#"<div style="font-family:-apple-system,Helvetica,Arial,sans-serif;color:#222;max-width:560px;margin:auto;padding:24px">
<h2 style="margin:0 0 16px">既に登録済みです</h2>
<p>このメールアドレス (<strong>{email}</strong>) は既に登録されています。新規登録ではなくサインインをご利用ください。</p>
<p style="font-size:13px;color:#666">心当たりがない場合はこのメールを無視してください。</p>
</div>"#,
            email = escape(to)
        );
        self.send(to, "【rust-op】既に登録済みのアカウントがあります", html).await
    }
}

/// ローカル用。送信せず確認 URL をログに出すだけ。
pub struct LogMailer;

#[async_trait]
impl Mailer for LogMailer {
    async fn send_verification(&self, to: &str, verify_url: &str) -> Result<(), String> {
        tracing::info!("[LogMailer] verify {to}: {verify_url}");
        Ok(())
    }
    async fn send_already_registered(&self, to: &str) -> Result<(), String> {
        tracing::info!("[LogMailer] already-registered notice to {to}");
        Ok(())
    }
}
