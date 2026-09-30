//! 人に見せる文言の言語切り替え。
//!
//! テンプレートの文言は英語で書き、`[[English text]]` の印で囲む。`localize` が印を
//! 英語ならそのまま、日本語なら `CATALOG` の訳に置き換え、`__LANG__` を言語コードにする。
//! 印の置き換えは `CATALOG` に在る鍵だけに限る（利用者の値に `[[...]]` が紛れても崩さない）。
//! 鍵と訳には HTML・JS の文字列を抜け出せる文字を入れない（`catalog_text_is_safe_everywhere`）。

use axum::http::{header, HeaderMap};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Lang {
    En,
    Ja,
}

impl Lang {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Lang::En => "en",
            Lang::Ja => "ja",
        }
    }

    pub(crate) fn from_headers(headers: &HeaderMap) -> Lang {
        headers
            .get(header::ACCEPT_LANGUAGE)
            .and_then(|v| v.to_str().ok())
            .map(Lang::from_accept_language)
            .unwrap_or(Lang::En)
    }

    /// q 値の高い順（同じ q なら書かれた順）に見て、最初に対応している言語を返す。
    /// q=0 は「受け付けない」。対応言語が無ければ英語。
    pub(crate) fn from_accept_language(value: &str) -> Lang {
        let mut ranges: Vec<(u32, Lang)> = value
            .split(',')
            .filter_map(|item| {
                let mut parts = item.split(';');
                let tag = parts.next()?.trim();
                let primary = tag.split('-').next()?.to_ascii_lowercase();
                let lang = match primary.as_str() {
                    "en" => Lang::En,
                    "ja" => Lang::Ja,
                    _ => return None,
                };
                let mut q = 1000;
                for param in parts {
                    if let Some(v) = param.trim().strip_prefix("q=") {
                        q = parse_q(v.trim())?;
                    }
                }
                (q > 0).then_some((q, lang))
            })
            .collect();
        ranges.sort_by(|a, b| b.0.cmp(&a.0));
        ranges.first().map(|r| r.1).unwrap_or(Lang::En)
    }
}

/// RFC 9110 の qvalue（0〜1、小数 3 桁まで）を千分率で返す。
fn parse_q(v: &str) -> Option<u32> {
    let (int, frac) = v.split_once('.').unwrap_or((v, ""));
    if frac.len() > 3 || !frac.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let milli = match int {
        "0" => format!("{frac:0<3}").parse().ok()?,
        "1" if frac.bytes().all(|b| b == b'0') => 1000,
        _ => return None,
    };
    Some(milli)
}

pub(crate) fn localize(template: &str, lang: Lang) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("[[") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("]]") else {
            rest = &rest[start..];
            break;
        };
        let key = &after[..end];
        match translate(key) {
            Some(ja) => out.push_str(if lang == Lang::Ja { ja } else { key }),
            None => {
                out.push_str("[[");
                rest = after;
                continue;
            }
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    out.replace("__LANG__", lang.code())
}

/// 言語が分からない宛先（メール・push）向け。日本語の後に英語を並べる。
pub(crate) fn bilingual(template: &str) -> String {
    format!(
        "{} / {}",
        localize(template, Lang::Ja),
        localize(template, Lang::En)
    )
}

fn translate(key: &str) -> Option<&'static str> {
    CATALOG.iter().find(|(en, _)| *en == key).map(|(_, ja)| *ja)
}

pub(crate) const CATALOG: &[(&str, &str)] = &[
    // login.rs / pages.rs
    ("Log in", "ログイン"),
    ("Sign in", "サインイン"),
    ("Sign in with a passkey", "Passkey でサインイン"),
    ("Email address (optional)", "メールアドレス（任意）"),
    ("Sign up with email", "新規登録 (メアドで)"),
    ("Cancel", "キャンセル"),
    (
        "This browser does not support passkeys. Open this page in the standard Safari or Chrome app.",
        "このブラウザは passkey 非対応です（標準の Safari / Chrome アプリで開いてください）。",
    ),
    (
        "Could not start the passkey. Open this page in the standard Safari or Chrome app (in-app browsers are not supported).",
        "passkey を起動できませんでした。標準の Safari / Chrome アプリで開いてください（アプリ内ブラウザでは使えません）。",
    ),
    ("Signing in…", "サインイン処理中…"),
    ("Male", "男性"),
    ("Female", "女性"),
    ("Other", "その他"),
    ("Not set", "未設定"),
    ("Profile", "プロフィール"),
    ("Name", "氏名"),
    ("Nickname", "ニックネーム"),
    ("Gender", "性別"),
    ("Birthday", "誕生日"),
    ("Time zone", "タイムゾーン"),
    ("Locale", "ロケール"),
    ("Edit", "編集"),
    ("Log out", "ログアウト"),
    ("Token info (debug)", "トークン情報 (デバッグ)"),
    ("Edit profile", "プロフィール編集"),
    ("Gender (male/female/other)", "性別 (male/female/other)"),
    ("Birthday (YYYY-MM-DD)", "誕生日 (YYYY-MM-DD)"),
    ("Save", "保存"),
    ("Your session has expired", "セッションが切れました"),
    ("Failed to save", "保存に失敗しました"),
    ("Sign-in approval request", "ログイン承認の依頼"),
    ("Approve (passkey)", "承認 (passkey)"),
    ("Reject", "拒否"),
    ("Error", "エラー"),
    ("Your session has expired. Please sign in again.", "セッションが切れました。再度サインインしてください。"),
    // register.rs
    ("Sign up", "登録"),
    ("Create an account", "ユーザー登録"),
    ("We will send a confirmation link to your email address.", "メールアドレスに確認リンクを送ります。"),
    ("Send confirmation email", "確認メールを送信"),
    ("Sent", "送信しました"),
    ("Confirmation email sent", "確認メールを送信しました"),
    (
        "Open the link in the email and create a passkey to finish signing up (the link expires in 15 minutes).",
        "メール内のリンクから passkey を作成して登録を完了してください（有効期限15分）。",
    ),
    ("Invitation expired", "招待の期限切れ"),
    ("This invitation cannot be used", "この招待は使えません"),
    (
        "It has expired or has already been used. Ask the person who invited you to send it again.",
        "期限が切れたか、既に使われています。招待した方に、もう一度送ってもらってください。",
    ),
    ("Passkey registration", "passkey 登録"),
    ("Create a passkey", "passkey を作成"),
    ("Name (required)", "氏名（必須）"),
    ("Name (optional)", "氏名（任意）"),
    ("Register securely with the fido2demo app.", "fido2demo アプリで安全に登録します。"),
    ("Open in the app", "アプリで開く"),
    (
        "If the app is installed, it opens automatically. If it does not, continue on the web with the button below.",
        "インストール済みなら自動で開きます。開かない場合は下のボタンから Web で続行できます。",
    ),
    (
        "If you open the app, the name above is not saved. It is saved if you continue on the web.",
        "アプリで開くと、上の氏名は保存されません。Web で登録を続けると保存されます。",
    ),
    ("Continue on the web", "Web で登録を続ける"),
    ("It is created as a synced passkey (for example in iCloud Keychain).", "同期 passkey（iCloud Keychain 等）として作成されます。"),
    (
        "Create a passkey with this device (for example with biometrics) to finish signing up.",
        "このデバイスの生体認証等で passkey を作成し、登録を完了します。",
    ),
    ("Create a passkey and sign up", "passkey を作成して登録"),
    ("Enter your name", "氏名を入力してください"),
    ("Working…", "処理中…"),
    ("Registration complete. Taking you to sign in…", "登録が完了しました。サインインの画面へ移ります…"),
    ("Registration complete.", "登録が完了しました。"),
    ("Go to log in", "ログインへ"),
    // oidc.rs
    ("You have logged out", "ログアウトしました"),
    ("Go to sign in", "サインインへ"),
    // ciba.rs
    ("You need to log in to approve.", "承認するにはログインが必要です。"),
    ("CIBA approval", "CIBA 承認"),
    ("There are no pending requests.", "保留中の要求はありません。"),
    // admin.rs
    ("Admin console", "管理コンソール"),
    ("Choose an action from the navigation above.", "上のナビゲーションから操作を選んでください。"),
    ("Status", "状態"),
    ("Registered", "登録日"),
    ("Admins cannot be deleted (revoke admin first).", "管理者は削除できません（先に管理者を剥奪）。"),
    (
        "Delete this account permanently? Its passkey, profile, and notification registration are also removed, and this cannot be undone (the CIBA approval history is kept).",
        "このアカウントを完全に削除しますか？passkey・プロフィール・通知の登録も消え、元に戻せません（CIBA の承認の履歴は残ります）。",
    ),
    ("Delete", "削除(delete)"),
    ("Enable", "凍結解除(enable)"),
    ("You cannot disable yourself (your session would end immediately).", "自分自身は凍結できません（セッションが即座に失効するため）。"),
    ("Disable this account? Its sessions and tokens are also revoked.", "このアカウントを凍結しますか？セッション・トークンも失効します。"),
    ("Disable", "凍結(disable)"),
    ("Revoke your own admin rights?", "自分自身の管理者権限を剥奪しますか？"),
    ("Revoke admin rights?", "管理者権限を剥奪しますか？"),
    ("Revoke admin", "管理者を剥奪"),
    ("Make admin", "管理者に任命"),
    ("No history.", "操作履歴はありません。"),
    ("Time", "日時"),
    ("Actor", "実行者"),
    ("Action", "操作"),
    ("Details", "詳細"),
    ("Target", "対象"),
    ("Role", "管理者"),
    ("History", "操作履歴"),
    ("Back to the list", "一覧へ戻る"),
    ("Disabled", "凍結中"),
    ("Active", "有効"),
    ("Admin", "管理者"),
    ("Regular user", "一般"),
    ("You cannot disable yourself", "自分自身は凍結できません"),
    ("Admins cannot be deleted. Revoke admin first", "管理者は削除できません。先に管理者を剥奪してください"),
    (
        "An account that is not disabled cannot be deleted. Disable it first",
        "凍結していないアカウントは削除できません。先に凍結してください",
    ),
    ("This conflicted with another change. Please try again", "他の書き込みと競合しました。もう一度お試しください"),
    ("You gave up admin rights", "管理者権限を放棄しました"),
    ("You can no longer access the admin console.", "これ以降、管理コンソールにはアクセスできません。"),
    ("The last admin cannot be revoked", "最後の管理者は剥奪できません"),
    ("Audit log (latest {n})", "監査ログ（直近{n}件）"),
    ("Auth method", "認証方式"),
    ("(none)", "(なし)"),
    (
        "(none — this client has no return address after sign-out)",
        "(なし — この client はサインアウト後の戻り先を持ちません)",
    ),
    (
        "post_logout_redirect_uris (one per line; leave empty for no return address)",
        "post_logout_redirect_uris（1 行に 1 つ。空にすると戻り先なし）",
    ),
    ("Save return addresses", "戻り先を保存"),
    ("Revoke this client? This cannot be undone.", "このクライアントを失効させますか？取り消せません。"),
    ("Set", "設定済み"),
    ("None", "なし"),
    (
        "This client was changed by another update. Reopen it and try again.",
        "この client は別の更新で変わりました。開き直してからやり直してください。",
    ),
    ("Unused IATs", "未消費のIAT"),
    ("New mint", "新規mint"),
    ("Discard this IAT?", "このIATを破棄しますか？"),
    ("Mint a new IAT", "新規IATをmint"),
    ("Client profile", "プロファイル"),
    ("Confidential Key (private_key_jwt, FAPI2 equivalent)", "Confidential Key（private_key_jwt、FAPI2相当）"),
    ("Confidential Secret (client_secret_basic)", "Confidential Secret（client_secret_basic）"),
    ("Public (none)", "Public（none）"),
    (
        "Allowed redirect hosts (one per line or comma-separated; at least one required)",
        "許可する redirect host（改行またはカンマ区切り、1つ以上必須）",
    ),
    ("Allowed grant_type (default: authorization_code, refresh_token)", "許可する grant_type（省略時: authorization_code, refresh_token）"),
    ("Expires in (hours)", "有効期限（時間）"),
    ("Specify at least one redirect host", "redirect host を最低1つ指定してください"),
    ("ttl_hours must be between 1 and {max} (365 days)", "ttl_hours は1〜{max}(365日)の範囲で指定してください"),
    ("ttl_hours is too large", "ttl_hours が大きすぎます"),
    (
        "The IAT was issued (hash={hash}), but the raw token cannot be shown because saving it for display failed.",
        "IATの発行自体は成功しました（hash={hash}）が、表示用の一時保存に失敗したため生トークンは表示できません。",
    ),
    ("Already shown", "表示済みです"),
    ("This token was already shown or has expired. Mint a new one.", "このトークンは既に表示済み、または期限切れです。再度mintしてください。"),
    ("Expired", "期限切れです"),
    ("It took too long to show it. Mint a new one.", "表示までに時間がかかりすぎました。再度mintしてください。"),
    ("IAT issued", "IATを発行しました"),
    ("This screen is shown only once. Copy the token now.", "この画面は一度しか表示されません。今すぐコピーしてください。"),
    ("IAT issuance complete", "IAT発行完了"),
    // mailer.rs
    ("[rust-op] Verify your email", "【rust-op】メールアドレス確認"),
    ("Verify your email address", "メールアドレス確認"),
    (
        "To finish signing up, create your passkey with the button below. The link expires in 15 minutes.",
        "登録を完了するには、以下のボタンからパスワードを設定してください。有効期限は15分です。",
    ),
    ("Sign up with a passkey", "パスワードを設定して登録"),
    ("If you did not request this, ignore this email.", "心当たりがない場合はこのメールを無視してください。"),
    ("[rust-op] An account already exists", "【rust-op】既に登録済みのアカウントがあります"),
    ("Already registered", "既に登録済みです"),
    ("This email address", "このメールアドレス"),
    (
        "is already registered. Please sign in instead of signing up.",
        "は既に登録されています。新規登録ではなくサインインをご利用ください。",
    ),
    // fcm.rs
    ("Sign-in approval", "ログインの承認"),
    ("Sign-in request from {client}", "{client} からのログイン要求があります"),
];

#[cfg(test)]
pub(crate) fn has_japanese(s: &str) -> bool {
    s.chars()
        .any(|c| matches!(c, '\u{3040}'..='\u{30FF}' | '\u{4E00}'..='\u{9FFF}'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    const OPEN: &str = concat!("[", "[");
    const CLOSE: &str = concat!("]", "]");

    /// 印を探す範囲。人に見せる文言を持つ file は全部ここに並べる。
    const SOURCES: &[(&str, &str)] = &[
        ("web/login.rs", include_str!("login.rs")),
        ("web/pages.rs", include_str!("pages.rs")),
        ("web/register.rs", include_str!("register.rs")),
        ("web/oidc.rs", include_str!("oidc.rs")),
        ("web/ciba.rs", include_str!("ciba.rs")),
        ("web/admin.rs", include_str!("admin.rs")),
        ("web/mod.rs", include_str!("mod.rs")),
        ("mailer.rs", include_str!("../mailer.rs")),
        ("fcm.rs", include_str!("../fcm.rs")),
    ];

    fn markers_in(src: &str) -> Vec<String> {
        let mut out = Vec::new();
        let mut rest = src;
        while let Some(start) = rest.find(OPEN) {
            let after = &rest[start + 2..];
            let end = after.find(CLOSE).expect("閉じていない印");
            out.push(after[..end].to_string());
            rest = &after[end + 2..];
        }
        out
    }

    #[test]
    fn every_marker_has_a_translation_and_every_translation_is_used() {
        let used: BTreeSet<String> = SOURCES
            .iter()
            .flat_map(|(_, src)| markers_in(src))
            .collect();
        let keys: BTreeSet<String> = CATALOG.iter().map(|(en, _)| en.to_string()).collect();
        let missing: Vec<&String> = used.difference(&keys).collect();
        let unused: Vec<&String> = keys.difference(&used).collect();
        assert!(missing.is_empty(), "訳の無い印: {missing:?}");
        assert!(
            unused.is_empty(),
            "どのテンプレートも使わない訳: {unused:?}"
        );
        assert_eq!(keys.len(), CATALOG.len(), "同じ鍵が二度ある");
    }

    #[test]
    fn catalog_text_is_safe_everywhere() {
        for (en, ja) in CATALOG {
            for s in [en, ja] {
                assert!(!s.is_empty() && s.trim() == *s, "前後の空白: {s:?}");
                assert!(
                    !s.chars()
                        .any(|c| "<>&\"'`\\$".contains(c) || c.is_control()),
                    "HTML の属性や JS の文字列を抜け出せる文字: {s:?}"
                );
                assert!(
                    ![OPEN, CLOSE, "__"].iter().any(|m| s.contains(m)),
                    "印や差し込み口と紛れる: {s:?}"
                );
            }
            let holes = |s: &str| -> BTreeSet<String> {
                s.split('{')
                    .skip(1)
                    .filter_map(|p| p.split_once('}'))
                    .map(|(h, _)| h.to_string())
                    .collect()
            };
            assert_eq!(holes(en), holes(ja), "差し込み口が訳とずれる: {en}");
            assert!(!has_japanese(en), "英語の鍵に日本語: {en}");
        }
    }

    #[test]
    fn localize_replaces_only_known_markers() {
        let t = format!(
            "<html lang=\"__LANG__\">{OPEN}Sign in{CLOSE} {OPEN}not a key{CLOSE} {OPEN}open"
        );
        assert_eq!(
            localize(&t, Lang::En),
            format!("<html lang=\"en\">Sign in {OPEN}not a key{CLOSE} {OPEN}open")
        );
        assert_eq!(
            localize(&t, Lang::Ja),
            format!("<html lang=\"ja\">サインイン {OPEN}not a key{CLOSE} {OPEN}open")
        );
        assert_eq!(
            bilingual(&format!("{OPEN}Sign-in approval{CLOSE}")),
            "ログインの承認 / Sign-in approval"
        );
    }

    #[test]
    fn a_stray_opening_marker_in_a_value_does_not_stop_the_markers_after_it() {
        let t = format!("<td>{OPEN}</td><button>{OPEN}Sign in{CLOSE}</button>");
        assert_eq!(
            localize(&t, Lang::Ja),
            format!("<td>{OPEN}</td><button>サインイン</button>")
        );
        assert_eq!(
            localize(&t, Lang::En),
            format!("<td>{OPEN}</td><button>Sign in</button>")
        );
    }

    #[test]
    fn picks_the_first_supported_language_by_q_value() {
        let cases = [
            ("", Lang::En),
            ("ja", Lang::Ja),
            ("ja-JP", Lang::Ja),
            ("JA-jp", Lang::Ja),
            ("en", Lang::En),
            ("en-US,ja;q=0.5", Lang::En),
            ("ja,en;q=0.8", Lang::Ja),
            ("en;q=0.5,ja;q=0.9", Lang::Ja),
            ("ja;q=0.5,en;q=0.5", Lang::Ja),
            ("fr", Lang::En),
            ("fr-FR,ja;q=0.7,en;q=0.3", Lang::Ja),
            ("de,fr;q=0.9", Lang::En),
            ("ja;q=0,en;q=0.1", Lang::En),
            ("ja;q=0", Lang::En),
            ("*", Lang::En),
            ("ja;q=abc", Lang::En),
            ("ja;q=1.5", Lang::En),
            ("ja;q=0.0001,en;q=0", Lang::En),
            (";;,,,", Lang::En),
            ("日本語", Lang::En),
            ("ja ; q=0.8 , en ; q=0.2", Lang::Ja),
        ];
        for (value, want) in cases {
            assert_eq!(Lang::from_accept_language(value), want, "{value:?}");
        }
        let mut h = HeaderMap::new();
        assert_eq!(Lang::from_headers(&h), Lang::En, "ヘッダが無ければ英語");
        h.insert(header::ACCEPT_LANGUAGE, "ja-JP,ja;q=0.9".parse().unwrap());
        assert_eq!(Lang::from_headers(&h), Lang::Ja);
        h.insert(
            header::ACCEPT_LANGUAGE,
            axum::http::HeaderValue::from_bytes(b"ja\xff").unwrap(),
        );
        assert_eq!(
            Lang::from_headers(&h),
            Lang::En,
            "ASCII でない値は読めないので英語"
        );
        assert_eq!(Lang::En.code(), "en");
        assert_eq!(Lang::Ja.code(), "ja");
    }
}
