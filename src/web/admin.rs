use super::*;

/// ログイン済セッションが管理者か確認する。未ログインは 401、非管理者は 403、
/// Firestore 未接続（ローカル既定構成）は 503 で fail-closed にする。
pub(super) async fn require_admin(p: &Provider, jar: &CookieJar) -> Result<String, Response> {
    let account_id = session_account(p, jar)
        .await
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, "login required").into_response())?;
    let fs = p
        .firestore
        .as_ref()
        .ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "admin console unavailable").into_response())?;
    match crate::admin_store::is_admin(fs, &account_id).await {
        Ok(true) => Ok(account_id),
        Ok(false) => Err((StatusCode::FORBIDDEN, "admin only").into_response()),
        Err(e) => {
            tracing::error!("require_admin: is_admin check failed for {account_id}: {e}");
            Err((StatusCode::SERVICE_UNAVAILABLE, "admin check failed").into_response())
        }
    }
}

/// require_admin を通した上で &Firestore も返す（ほぼ全ハンドラが両方必要とする共通パターン）。
/// require_admin が Ok を返した時点で p.firestore は必ず Some（内部で確認済み）。
async fn require_admin_fs<'p>(
    p: &'p Provider,
    jar: &CookieJar,
) -> Result<(String, &'p std::sync::Arc<crate::firestore::Firestore>), Response> {
    let account_id = require_admin(p, jar).await?;
    let fs = p.firestore.as_ref().expect("require_admin already confirmed firestore is configured");
    Ok((account_id, fs))
}

/// 疎通確認用: 自分が管理者として認識されているかを返す。
pub(super) async fn whoami(State(p): State<Arc<Provider>>, jar: CookieJar) -> Response {
    match require_admin(&p, &jar).await {
        Ok(account_id) => Json(serde_json::json!({ "account_id": account_id })).into_response(),
        Err(r) => r,
    }
}

/* ===== 共有レンダリングヘルパー ===== */

/// HTML本文・属性値の両方で安全なエスケープ（&<>"'）。
/// mailer.rs::escape は &<> のみで引用符を含まないため属性値には不十分——ここでは別に持つ。
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

fn nav(p: &Provider) -> String {
    format!(
        r#"<nav><a href="{home}">Admin</a><a href="{users}">Users</a><a href="{clients}">Clients</a><a href="{iats}">IATs</a><a href="{audit}">Audit</a><a href="{logout}">Sign out</a></nav>"#,
        home = p.path("/admin"),
        users = p.path("/admin/users"),
        clients = p.path("/admin/clients"),
        iats = p.path("/admin/iats"),
        audit = p.path("/admin/audit"),
        logout = p.path("/end-session"),
    )
}

/// register.rs::page と同じ骨格に管理者ナビを追加した共有レイアウト。
fn page(p: &Provider, title: &str, body: &str) -> Html<String> {
    Html(format!(
        r#"<!doctype html><html lang="ja"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title>
<style>
:root{{--indigo:#3f51b5;--indigo-d:#303f9f;--bg:#fafafa;--border:#e0e0e0}}
body{{font-family:-apple-system,'Helvetica Neue',sans-serif;max-width:960px;margin:0 auto;padding:24px 16px;line-height:1.6;color:#1a1a1a}}
nav{{margin-bottom:24px;padding-bottom:12px;border-bottom:1px solid var(--border)}}
nav a{{margin-right:16px;color:var(--indigo);text-decoration:none;font-weight:500}}
nav a:hover{{text-decoration:underline}}
h1{{font-size:1.4rem}}
table{{width:100%;border-collapse:collapse;margin:16px 0}}
th,td{{text-align:left;padding:8px 12px;border-bottom:1px solid var(--border);font-size:14px;vertical-align:top}}
th{{color:#666;font-weight:600}}
tr:hover{{background:var(--bg)}}
.badge{{display:inline-block;padding:2px 8px;border-radius:10px;font-size:12px;font-weight:600}}
.badge-warn{{background:#fce8e6;color:#c5221f}}
.badge-ok{{background:#e6f4ea;color:#137333}}
.btn{{display:inline-block;padding:8px 16px;font-size:14px;font-weight:500;background:var(--indigo);color:#fff;border:0;border-radius:6px;cursor:pointer;text-decoration:none}}
.btn:hover{{background:var(--indigo-d)}}
.btn-danger{{background:#c5221f}}
.btn-danger:hover{{background:#a3170f}}
form.inline{{display:inline-block;margin-right:8px}}
input,textarea{{display:block;width:100%;box-sizing:border-box;padding:8px;margin:6px 0 14px;font-size:14px;border:1px solid var(--border);border-radius:4px;font-family:inherit}}
label{{display:block;font-size:13px;color:#666;font-weight:600;margin-top:10px}}
code{{background:var(--bg);padding:2px 6px;border-radius:4px;font-size:13px}}
</style>
</head><body>{nav}{body}</body></html>"#,
        nav = nav(p),
    ))
}

fn redirect(p: &Provider, path: &str) -> Response {
    Redirect::to(&p.path(path)).into_response()
}

fn server_error(context: &str, e: &str) -> Response {
    tracing::error!("{context}: {e}");
    (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
}

/* ===== ホーム ===== */

pub(super) async fn admin_home(State(p): State<Arc<Provider>>, jar: CookieJar) -> Response {
    if let Err(r) = require_admin(&p, &jar).await {
        return r;
    }
    page(
        &p,
        "管理コンソール",
        "<h1>管理コンソール</h1><p>上のナビゲーションから操作を選んでください。</p>",
    )
    .into_response()
}

/* ===== ユーザー管理 ===== */

pub(super) async fn users_list(State(p): State<Arc<Provider>>, jar: CookieJar) -> Response {
    let (_viewer, fs) = match require_admin_fs(&p, &jar).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    // list_accounts と list_admins は互いに依存しないため並行に投げる。
    let (accounts_result, admins_result) =
        tokio::join!(crate::registration::list_accounts(fs), crate::admin_store::list_admins(fs));
    let mut accounts = match accounts_result {
        Ok(a) => a,
        Err(e) => return server_error("users_list", &e),
    };
    accounts.sort_by(|a, b| a.email.cmp(&b.email));
    let admins: std::collections::HashSet<String> = match admins_result {
        Ok(v) => v.into_iter().collect(),
        Err(e) => {
            tracing::error!("users_list: list_admins: {e}");
            Default::default()
        }
    };

    let rows: String = accounts
        .iter()
        .map(|a| {
            let status = if a.disabled {
                r#"<span class="badge badge-warn">disabled</span>"#
            } else {
                r#"<span class="badge badge-ok">active</span>"#
            };
            let admin_badge = if admins.contains(&a.account_id) {
                r#" <span class="badge badge-ok">admin</span>"#
            } else {
                ""
            };
            format!(
                r#"<tr><td><a href="{href}">{email}</a>{admin_badge}</td><td>{status}</td><td>{sign_count}</td><td>{created_at}</td></tr>"#,
                href = esc(&p.path(&format!("/admin/users/{}", a.account_id))),
                email = esc(&a.email),
                sign_count = a.sign_count,
                created_at = esc(&crate::firestore::rfc3339(a.created_at)),
            )
        })
        .collect();

    let body = format!(
        "<h1>Users ({n})</h1><table><tr><th>Email</th><th>状態</th><th>sign_count</th><th>登録日</th></tr>{rows}</table>",
        n = accounts.len(),
    );
    page(&p, "Users", &body).into_response()
}

pub(super) async fn user_detail(
    State(p): State<Arc<Provider>>,
    jar: CookieJar,
    Path(account_id): Path<String>,
) -> Response {
    let (viewer, fs) = match require_admin_fs(&p, &jar).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    // find_email/is_admin/list_for_target はいずれも account_id だけで開始できるため並行に
    // 投げる。get_credential だけは email 解決後でないと呼べないので後続で直列にする。
    let (email_result, is_admin_result, audit) = tokio::join!(
        crate::registration::find_email_by_account_id(fs, &account_id),
        crate::admin_store::is_admin(fs, &account_id),
        async { crate::audit_log::list_for_target(fs, &account_id).await.unwrap_or_default() },
    );
    let email = match email_result {
        Ok(Some(e)) => e,
        Ok(None) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => return server_error("user_detail: find_email", &e),
    };
    let cred = match crate::registration::get_credential(fs, &email).await {
        Ok(Some(c)) => c,
        Ok(None) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => return server_error("user_detail: get_credential", &e),
    };
    let is_admin_user = match is_admin_result {
        Ok(b) => b,
        Err(e) => return server_error("user_detail: is_admin", &e),
    };
    let is_self = account_id == viewer;

    let disable_control = if cred.disabled {
        format!(
            r#"<form class="inline" method="post" action="{action}"><button class="btn" type="submit">凍結解除(enable)</button></form>"#,
            action = esc(&p.path(&format!("/admin/users/{account_id}/enable"))),
        )
    } else if is_self {
        r#"<span style="color:#666;font-size:13px">自分自身は凍結できません（セッションが即座に失効するため）。</span>"#.to_string()
    } else {
        format!(
            r#"<form class="inline" method="post" action="{action}" onsubmit="return confirm('このアカウントを凍結しますか？セッション・トークンも失効します。')"><button class="btn btn-danger" type="submit">凍結(disable)</button></form>"#,
            action = esc(&p.path(&format!("/admin/users/{account_id}/disable"))),
        )
    };

    let admin_control = if is_admin_user {
        let msg = if is_self {
            "自分自身の管理者権限を剥奪しますか？"
        } else {
            "管理者権限を剥奪しますか？"
        };
        format!(
            r#"<form class="inline" method="post" action="{action}" onsubmit="return confirm('{msg}')"><button class="btn btn-danger" type="submit">管理者を剥奪</button></form>"#,
            action = esc(&p.path(&format!("/admin/users/{account_id}/revoke-admin"))),
        )
    } else {
        format!(
            r#"<form class="inline" method="post" action="{action}"><button class="btn" type="submit">管理者に任命</button></form>"#,
            action = esc(&p.path(&format!("/admin/users/{account_id}/grant-admin"))),
        )
    };

    let audit_rows: String = audit
        .iter()
        .map(|e| {
            format!(
                "<tr><td>{at}</td><td>{actor}</td><td>{action}</td><td>{detail}</td></tr>",
                at = esc(&crate::firestore::rfc3339(e.at)),
                actor = esc(&e.actor),
                action = esc(&e.action),
                detail = esc(&e.detail),
            )
        })
        .collect();
    let audit_table = if audit.is_empty() {
        "<p>操作履歴はありません。</p>".to_string()
    } else {
        format!(
            "<table><tr><th>日時</th><th>実行者</th><th>操作</th><th>詳細</th></tr>{audit_rows}</table>"
        )
    };

    let body = format!(
        r#"<h1>{email}</h1>
<p>account_id: <code>{account_id}</code></p>
<p>credential_id: <code>{credential_id}</code></p>
<p>sign_count: {sign_count}</p>
<p>状態: {status} / 管理者: {admin_status}</p>
<p>{disable_control} {admin_control}</p>
<h2>操作履歴</h2>
{audit_table}
<p><a href="{back}">&larr; 一覧へ戻る</a></p>"#,
        email = esc(&email),
        account_id = esc(&account_id),
        credential_id = esc(&cred.credential_id),
        sign_count = cred.sign_count,
        status = if cred.disabled { "凍結中" } else { "有効" },
        admin_status = if is_admin_user { "管理者" } else { "一般" },
        back = esc(&p.path("/admin/users")),
    );
    page(&p, &format!("User: {}", esc(&email)), &body).into_response()
}

pub(super) async fn user_disable(
    State(p): State<Arc<Provider>>,
    jar: CookieJar,
    Path(account_id): Path<String>,
) -> Response {
    let (viewer, fs) = match require_admin_fs(&p, &jar).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    // 表示上はボタンを隠すだけなので、直接POSTされた場合に備えここでも再チェックする。
    if account_id == viewer {
        return (StatusCode::FORBIDDEN, "自分自身は凍結できません").into_response();
    }
    let email = match crate::registration::find_email_by_account_id(fs, &account_id).await {
        Ok(Some(e)) => e,
        Ok(None) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => return server_error("user_disable: find_email", &e),
    };
    if let Err(e) = crate::account_admin::disable_account(fs, &viewer, &email).await {
        return server_error("user_disable", &e);
    }
    redirect(&p, &format!("/admin/users/{account_id}"))
}

pub(super) async fn user_enable(
    State(p): State<Arc<Provider>>,
    jar: CookieJar,
    Path(account_id): Path<String>,
) -> Response {
    let (viewer, fs) = match require_admin_fs(&p, &jar).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let email = match crate::registration::find_email_by_account_id(fs, &account_id).await {
        Ok(Some(e)) => e,
        Ok(None) => return (StatusCode::NOT_FOUND, "user not found").into_response(),
        Err(e) => return server_error("user_enable: find_email", &e),
    };
    if let Err(e) = crate::account_admin::enable_account(fs, &viewer, &email).await {
        return server_error("user_enable", &e);
    }
    redirect(&p, &format!("/admin/users/{account_id}"))
}

pub(super) async fn user_grant_admin(
    State(p): State<Arc<Provider>>,
    jar: CookieJar,
    Path(account_id): Path<String>,
) -> Response {
    let (viewer, fs) = match require_admin_fs(&p, &jar).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    match crate::admin_store::grant_admin(fs, &account_id, &viewer).await {
        Ok(crate::admin_store::GrantAdminResult::Granted) => {
            crate::audit_log::record(fs, &viewer, "grant_admin", &account_id, "").await;
            redirect(&p, &format!("/admin/users/{account_id}"))
        }
        Ok(crate::admin_store::GrantAdminResult::AlreadyAdmin) => {
            redirect(&p, &format!("/admin/users/{account_id}"))
        }
        Ok(crate::admin_store::GrantAdminResult::Conflict) => {
            (StatusCode::CONFLICT, "他の書き込みと競合しました。もう一度お試しください").into_response()
        }
        Err(e) => server_error("user_grant_admin", &e),
    }
}

pub(super) async fn user_revoke_admin(
    State(p): State<Arc<Provider>>,
    jar: CookieJar,
    Path(account_id): Path<String>,
) -> Response {
    let (viewer, fs) = match require_admin_fs(&p, &jar).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    match crate::admin_store::revoke_admin(fs, &account_id).await {
        Ok(crate::admin_store::RevokeAdminResult::Revoked) => {
            crate::audit_log::record(fs, &viewer, "revoke_admin", &account_id, "").await;
            if account_id == viewer {
                // 自分自身を剥奪した直後は require_admin が以降のアクセスを全て弾くため、
                // 管理画面内へリダイレクトすると即403になる。管理画面外の完了表示で終える。
                return page(
                    &p,
                    "管理者権限を放棄しました",
                    "<h1>管理者権限を放棄しました</h1><p>これ以降、管理コンソールにはアクセスできません。</p>",
                )
                .into_response();
            }
            redirect(&p, &format!("/admin/users/{account_id}"))
        }
        Ok(crate::admin_store::RevokeAdminResult::NotAdmin) => {
            redirect(&p, &format!("/admin/users/{account_id}"))
        }
        Ok(crate::admin_store::RevokeAdminResult::LastAdminGuard) => {
            (StatusCode::CONFLICT, "最後の管理者は剥奪できません").into_response()
        }
        Ok(crate::admin_store::RevokeAdminResult::Conflict) => {
            (StatusCode::CONFLICT, "他の書き込みと競合しました。もう一度お試しください").into_response()
        }
        Err(e) => server_error("user_revoke_admin", &e),
    }
}

pub(super) async fn audit_list(State(p): State<Arc<Provider>>, jar: CookieJar) -> Response {
    let (_viewer, fs) = match require_admin_fs(&p, &jar).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let entries = match crate::audit_log::list_recent(fs, 200).await {
        Ok(e) => e,
        Err(e) => return server_error("audit_list", &e),
    };
    let rows: String = entries
        .iter()
        .map(|e| {
            format!(
                "<tr><td>{at}</td><td>{actor}</td><td>{action}</td><td>{target}</td><td>{detail}</td></tr>",
                at = esc(&crate::firestore::rfc3339(e.at)),
                actor = esc(&e.actor),
                action = esc(&e.action),
                target = esc(&e.target),
                detail = esc(&e.detail),
            )
        })
        .collect();
    let body = format!(
        "<h1>監査ログ（直近{n}件）</h1><table><tr><th>日時</th><th>実行者</th><th>操作</th><th>対象</th><th>詳細</th></tr>{rows}</table>",
        n = entries.len(),
    );
    page(&p, "Audit Log", &body).into_response()
}

/* ===== クライアント管理 ===== */

pub(super) async fn clients_list(State(p): State<Arc<Provider>>, jar: CookieJar) -> Response {
    let (_viewer, fs) = match require_admin_fs(&p, &jar).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let mut clients = match crate::dcr_store::list_clients(fs).await {
        Ok(c) => c,
        Err(e) => return server_error("clients_list", &e),
    };
    clients.sort_by(|a, b| a.client_id.cmp(&b.client_id));
    let rows: String = clients
        .iter()
        .map(|c| {
            format!(
                r#"<tr><td><a href="{href}">{id}</a></td><td>{auth}</td><td>{grants}</td></tr>"#,
                href = esc(&p.path(&format!("/admin/clients/{}", c.client_id))),
                id = esc(&c.client_id),
                auth = esc(&c.token_endpoint_auth_method),
                grants = esc(&c.grant_types.join(", ")),
            )
        })
        .collect();
    let body = format!(
        "<h1>Clients ({n})</h1><table><tr><th>client_id</th><th>認証方式</th><th>grant_types</th></tr>{rows}</table>",
        n = clients.len(),
    );
    page(&p, "Clients", &body).into_response()
}

pub(super) async fn client_detail(
    State(p): State<Arc<Provider>>,
    jar: CookieJar,
    Path(client_id): Path<String>,
) -> Response {
    let (_viewer, fs) = match require_admin_fs(&p, &jar).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let c = match crate::dcr_store::load_client(fs, &client_id).await {
        Some(c) => c,
        None => return (StatusCode::NOT_FOUND, "client not found").into_response(),
    };

    let redirect_uris: String = if c.redirect_uris.is_empty() {
        "<li>(なし)</li>".to_string()
    } else {
        c.redirect_uris.iter().map(|u| format!("<li><code>{}</code></li>", esc(u))).collect()
    };
    let jwks: String = if c.jwks.is_empty() {
        "<li>(なし)</li>".to_string()
    } else {
        c.jwks.iter().map(|k| format!("<li>kid=<code>{}</code></li>", esc(&k.kid))).collect()
    };

    let body = format!(
        r#"<h1>{id}</h1>
<p>token_endpoint_auth_method: <code>{auth}</code></p>
<p>client_secret: {secret}</p>
<p>grant_types: {grants}</p>
<p>redirect_uris:</p><ul>{redirect_uris}</ul>
<p>jwks_uri: {jwks_uri}</p>
<p>jwks kids:</p><ul>{jwks}</ul>
<p>require_par: {par} / require_pkce: {pkce} / dpop_bound: {dpop}</p>
<form method="post" action="{revoke_action}" onsubmit="return confirm('このクライアントを失効させますか？取り消せません。')"><button class="btn btn-danger" type="submit">Revoke</button></form>
<p><a href="{back}">&larr; 一覧へ戻る</a></p>"#,
        id = esc(&c.client_id),
        auth = esc(&c.token_endpoint_auth_method),
        secret = if c.client_secret.is_some() { "設定済み" } else { "なし" },
        grants = esc(&c.grant_types.join(", ")),
        jwks_uri = c.jwks_uri.as_deref().map(esc).unwrap_or_else(|| "なし".into()),
        par = c.require_par,
        pkce = c.require_pkce,
        dpop = c.dpop_bound,
        revoke_action = esc(&p.path(&format!("/admin/clients/{}/revoke", c.client_id))),
        back = esc(&p.path("/admin/clients")),
    );
    page(&p, &format!("Client: {}", esc(&c.client_id)), &body).into_response()
}

pub(super) async fn client_revoke(
    State(p): State<Arc<Provider>>,
    jar: CookieJar,
    Path(client_id): Path<String>,
) -> Response {
    let (viewer, fs) = match require_admin_fs(&p, &jar).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    match crate::dcr_store::revoke_client(fs, &client_id).await {
        Ok(true) => {
            crate::audit_log::record(fs, &viewer, "revoke_client", &client_id, "").await;
        }
        Ok(false) => {}
        Err(e) => return server_error("client_revoke", &e),
    }
    redirect(&p, "/admin/clients")
}

/* ===== IAT管理 ===== */

pub(super) async fn iats_pending_list(State(p): State<Arc<Provider>>, jar: CookieJar) -> Response {
    let (_viewer, fs) = match require_admin_fs(&p, &jar).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    let mut iats = match crate::dcr_store::list_pending_iats(fs).await {
        Ok(i) => i,
        Err(e) => return server_error("iats_pending_list", &e),
    };
    iats.sort_by(|a, b| b.expires_at.cmp(&a.expires_at));
    let now_secs = now();

    let rows: String = iats
        .iter()
        .map(|iat| {
            let expired = iat.expires_at < now_secs;
            let badge = if expired {
                r#"<span class="badge badge-warn">expired</span>"#
            } else {
                r#"<span class="badge badge-ok">pending</span>"#
            };
            format!(
                r#"<tr><td><code>{hash}&hellip;</code></td><td>{profile}</td><td>{hosts}</td><td>{grants}</td><td>{badge}{reusable}</td>
<td><form method="post" action="{revoke}" onsubmit="return confirm('このIATを破棄しますか？')">
<input type="hidden" name="update_time" value="{update_time}">
<button class="btn btn-danger" type="submit">Revoke</button></form></td></tr>"#,
                hash = esc(&iat.hash[..iat.hash.len().min(16)]),
                profile = profile_label(iat.constraints.profile),
                hosts = esc(&iat.constraints.allowed_redirect_hosts.join(", ")),
                grants = esc(&iat.constraints.allowed_grant_types.join(", ")),
                reusable = if iat.reusable { " <span class=\"badge\">reusable</span>" } else { "" },
                revoke = esc(&p.path(&format!("/admin/iats/{}/revoke", iat.hash))),
                update_time = esc(&iat.update_time),
            )
        })
        .collect();

    let body = format!(
        r#"<h1>未消費のIAT ({n})</h1><p><a class="btn" href="{mint_link}">+ 新規mint</a></p>
<table><tr><th>hash</th><th>profile</th><th>redirect hosts</th><th>grant types</th><th>状態</th><th></th></tr>{rows}</table>"#,
        n = iats.len(),
        mint_link = esc(&p.path("/admin/iats/new")),
    );
    page(&p, "Pending IATs", &body).into_response()
}

fn profile_label(profile: crate::dcr::ClientProfile) -> &'static str {
    match profile {
        crate::dcr::ClientProfile::Public => "public",
        crate::dcr::ClientProfile::ConfidentialSecret => "confidential-secret",
        crate::dcr::ClientProfile::ConfidentialKey => "confidential-key",
    }
}

#[derive(serde::Deserialize)]
pub(super) struct IatRevokeForm {
    /// 一覧表示(list_pending_iats)が返した updateTime をそのまま隠しフィールド経由で受け取る。
    /// ここで peek_iat による再取得はしない(CASに使うだけの不透明な値であり、一覧表示後に
    /// 別操作で更新されていれば単に consume_iat が false を返すだけで安全に失敗する)。
    update_time: String,
}

pub(super) async fn iat_revoke(
    State(p): State<Arc<Provider>>,
    jar: CookieJar,
    Path(hash): Path<String>,
    Form(form): Form<IatRevokeForm>,
) -> Response {
    let (viewer, fs) = match require_admin_fs(&p, &jar).await {
        Ok(x) => x,
        Err(r) => return r,
    };
    match crate::dcr_store::consume_iat(fs, &hash, &form.update_time).await {
        Ok(true) => {
            crate::audit_log::record(fs, &viewer, "revoke_iat", &hash, "").await;
        }
        // 既に消費/失効済み、または一覧表示後に別操作で更新された。冪等に成功扱いでよい。
        Ok(false) => {}
        Err(e) => return server_error("iat_revoke: consume", &e),
    }
    redirect(&p, "/admin/iats")
}

pub(super) async fn iat_mint_form(State(p): State<Arc<Provider>>, jar: CookieJar) -> Response {
    if let Err(r) = require_admin(&p, &jar).await {
        return r;
    }
    let action = esc(&p.path("/admin/iats/new"));
    let body = format!(
        r#"<h1>新規IATをmint</h1>
<form method="post" action="{action}">
<label>プロファイル</label>
<label style="font-weight:normal"><input type="radio" name="profile" value="confidential-key" checked> Confidential Key（private_key_jwt、FAPI2相当）</label>
<label style="font-weight:normal"><input type="radio" name="profile" value="confidential-secret"> Confidential Secret（client_secret_basic）</label>
<label style="font-weight:normal"><input type="radio" name="profile" value="public"> Public（none）</label>
<label>許可する redirect host（改行またはカンマ区切り、1つ以上必須）</label>
<textarea name="redirect_hosts" rows="3" required placeholder="rp.example.com"></textarea>
<label>許可する grant_type（省略時: authorization_code, refresh_token）</label>
<input name="grant_types" placeholder="authorization_code, refresh_token">
<label>有効期限（時間）</label>
<input name="ttl_hours" type="number" value="24" min="1">
<button class="btn" type="submit">Mint</button>
</form>"#,
    );
    page(&p, "Mint IAT", &body).into_response()
}

#[derive(serde::Deserialize)]
pub(super) struct IatMintForm {
    profile: String,
    redirect_hosts: String,
    #[serde(default)]
    grant_types: String,
    ttl_hours: u64,
}

pub(super) async fn iat_mint_submit(
    State(p): State<Arc<Provider>>,
    jar: CookieJar,
    Form(form): Form<IatMintForm>,
) -> Response {
    let (viewer, fs) = match require_admin_fs(&p, &jar).await {
        Ok(x) => x,
        Err(r) => return r,
    };

    let profile = match form.profile.as_str() {
        "public" => crate::dcr::ClientProfile::Public,
        "confidential-secret" => crate::dcr::ClientProfile::ConfidentialSecret,
        "confidential-key" => crate::dcr::ClientProfile::ConfidentialKey,
        _ => return (StatusCode::BAD_REQUEST, "invalid profile").into_response(),
    };
    let hosts: Vec<String> = form
        .redirect_hosts
        .split([',', '\n', '\r'])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if hosts.is_empty() {
        return (StatusCode::BAD_REQUEST, "redirect host を最低1つ指定してください").into_response();
    }
    let mut grants: Vec<String> = form
        .grant_types
        .split([',', '\n', '\r', ' '])
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if grants.is_empty() {
        grants = vec!["authorization_code".into(), "refresh_token".into()];
    }
    // 365日を超える値やu64乗算がオーバーフローしうる極端な値を弾く(下のcheckedはその防波堤)。
    const MAX_TTL_HOURS: u64 = 24 * 365;
    if form.ttl_hours == 0 || form.ttl_hours > MAX_TTL_HOURS {
        return (
            StatusCode::BAD_REQUEST,
            format!("ttl_hours は1〜{MAX_TTL_HOURS}(365日)の範囲で指定してください"),
        )
            .into_response();
    }

    let constraints = crate::dcr::IatConstraints {
        allowed_redirect_hosts: hosts.clone(),
        allowed_grant_types: grants.clone(),
        profile,
    };
    let (raw, hash) = crate::dcr::gen_random_token();
    let expires_at = match form.ttl_hours.checked_mul(3600).and_then(|secs| now().checked_add(secs)) {
        Some(v) => v,
        None => return (StatusCode::BAD_REQUEST, "ttl_hours が大きすぎます").into_response(),
    };
    if let Err(e) = crate::dcr_store::put_iat(fs, &hash, &constraints, expires_at, false).await {
        return server_error("iat_mint_submit: put_iat", &e);
    }
    crate::audit_log::record(
        fs,
        &viewer,
        "mint_iat",
        &hash,
        &format!(
            "profile={} hosts={} grants={} ttl_hours={}",
            profile_label(profile),
            hosts.join(","),
            grants.join(","),
            form.ttl_hours,
        ),
    )
    .await;

    // 生トークンはURL(クエリ含む)に一切載せず、一時Firestoreドキュメント経由で一度だけ表示する
    // （ブラウザ履歴・アクセスログ・Refererに残さないため）。flash_id はトークンのハッシュとは
    // 無関係な別のCSPRNG値（gen_random_tokenの「生」側を流用し、対応するハッシュは捨てる）。
    let (flash_id, _unused_hash) = crate::dcr::gen_random_token();
    let flash_expires_at = now() + 300;
    if let Err(e) = fs
        .set_doc(
            "adminIatFlash",
            &flash_id,
            serde_json::json!({
                "raw_token": crate::firestore::s(&raw),
                "expires_at": crate::firestore::int(flash_expires_at),
            }),
        )
        .await
    {
        tracing::error!("iat_mint_submit: flash write failed: {e}");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!(
                "IATの発行自体は成功しました（hash={hash}）が、表示用の一時保存に失敗したため生トークンは表示できません。"
            ),
        )
            .into_response();
    }
    redirect(&p, &format!("/admin/iats/flash/{flash_id}"))
}

pub(super) async fn iat_show_once(
    State(p): State<Arc<Provider>>,
    jar: CookieJar,
    Path(flash_id): Path<String>,
) -> Response {
    let (_viewer, fs) = match require_admin_fs(&p, &jar).await {
        Ok(x) => x,
        Err(r) => return r,
    };

    let fields = match fs.get_doc("adminIatFlash", &flash_id).await {
        Ok(Some(f)) => f,
        Ok(None) => {
            return page(
                &p,
                "IAT",
                "<h1>表示済みです</h1><p>このトークンは既に表示済み、または期限切れです。再度mintしてください。</p>",
            )
            .into_response()
        }
        Err(e) => return server_error("iat_show_once", &e),
    };
    // ベストエフォートで削除する（一度だけ表示。多重タブでの低頻度な競合は許容する。
    // registration.rs の consume_email_challenge と同じ read-then-delete の idiom）。
    let _ = fs.delete_doc("adminIatFlash", &flash_id).await;

    let expires_at = crate::firestore::field_u64(&fields, "expires_at").unwrap_or(0);
    if expires_at < now() {
        return page(
            &p,
            "IAT",
            "<h1>期限切れです</h1><p>表示までに時間がかかりすぎました。再度mintしてください。</p>",
        )
        .into_response();
    }
    let raw = crate::firestore::field_str(&fields, "raw_token").unwrap_or("");
    let body = format!(
        r#"<h1>IATを発行しました</h1>
<p style="color:#c5221f;font-weight:600">この画面は一度しか表示されません。今すぐコピーしてください。</p>
<input type="text" readonly value="{raw}" onclick="this.select()" style="font-family:monospace">
<p><a href="{iats}">&larr; 一覧へ戻る</a></p>"#,
        raw = esc(raw),
        iats = esc(&p.path("/admin/iats")),
    );
    page(&p, "IAT発行完了", &body).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::firestore::fake_firestore;
    use crate::model::Session;

    /// Firestore(fake) + FirestoreStore を配線した Provider。require_admin は
    /// session_account(Store経由)とadmin_store(Firestore経由)の両方を必要とするため、
    /// MemoryStoreのままでは admins/{account_id} を検証できない。
    async fn provider_with_firestore() -> (Provider, std::sync::Arc<crate::firestore::Firestore>) {
        let (host, _state) = fake_firestore::spawn().await;
        let fs = std::sync::Arc::new(crate::firestore::Firestore::new_for_test("proj", host));
        let p = Provider::new("http://localhost:8080".to_string())
            .with_firestore(fs.clone())
            .with_store(std::sync::Arc::new(crate::firestore_store::FirestoreStore::new(fs.clone())));
        (p, fs)
    }

    async fn login_as(p: &Provider, account_id: &str) -> CookieJar {
        let sid = uuid::Uuid::new_v4().to_string();
        p.store
            .save_session(Session { sid: sid.clone(), account_id: account_id.to_string(), auth_time: 0 })
            .await;
        CookieJar::default().add(Cookie::new(SID_COOKIE, sid))
    }

    #[tokio::test]
    async fn require_admin_401_when_not_logged_in() {
        let (p, _fs) = provider_with_firestore().await;
        let err = require_admin(&p, &CookieJar::default()).await.unwrap_err();
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn require_admin_403_when_logged_in_but_not_admin() {
        let (p, _fs) = provider_with_firestore().await;
        let jar = login_as(&p, "acc-nonadmin").await;
        let err = require_admin(&p, &jar).await.unwrap_err();
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn require_admin_ok_when_admin() {
        let (p, fs) = provider_with_firestore().await;
        crate::admin_store::grant_admin(&fs, "acc-admin", "cli").await.unwrap();
        let jar = login_as(&p, "acc-admin").await;
        let account_id = require_admin(&p, &jar).await.unwrap();
        assert_eq!(account_id, "acc-admin");
    }

    #[tokio::test]
    async fn require_admin_503_when_firestore_not_configured() {
        // firestore を配線しない Provider::new の既定(MemoryStore)にセッションだけ張る。
        // session_account自体はStore経由で成立するため、この場合だけ確実に
        // firestore=Noneの分岐(503)を踏む(セッション自体が無ければ401で先に落ちてしまう)。
        let p = Provider::new("http://localhost:8080".to_string());
        let jar = login_as(&p, "acc-x").await;
        let err = require_admin(&p, &jar).await.unwrap_err();
        assert_eq!(err.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    // 実 Firestore エミュレータの updateTime CAS は壊れており(admin_store::grant_admin/
    // revoke_admin は CAS で書く)、emulator_tests.rs 側では検証できない。fake_firestore は
    // CAS を正しく実装しているため、ここで直接ハンドラを叩いて検証する。
    #[tokio::test]
    async fn user_revoke_admin_self_returns_completion_page_instead_of_redirect_that_would_403() {
        let (p, fs) = provider_with_firestore().await;
        crate::admin_store::grant_admin(&fs, "acc-self", "cli").await.unwrap();
        crate::admin_store::grant_admin(&fs, "acc-other", "cli").await.unwrap();
        let jar = login_as(&p, "acc-self").await;
        let p = Arc::new(p);
        let resp =
            user_revoke_admin(State(p.clone()), jar, Path("acc-self".to_string())).await;
        // /admin/users/{account_id} へ303リダイレクトすると、直後の require_admin が
        // 403で弾く(自分はもう管理者ではない)。管理画面外の200完了ページで終える。
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(!crate::admin_store::is_admin(&fs, "acc-self").await.unwrap());
    }

    #[tokio::test]
    async fn user_revoke_admin_other_still_redirects_to_detail_page() {
        let (p, fs) = provider_with_firestore().await;
        crate::admin_store::grant_admin(&fs, "acc-self", "cli").await.unwrap();
        crate::admin_store::grant_admin(&fs, "acc-other", "cli").await.unwrap();
        let jar = login_as(&p, "acc-self").await;
        let p = Arc::new(p);
        let resp =
            user_revoke_admin(State(p.clone()), jar, Path("acc-other".to_string())).await;
        assert!(resp.status().is_redirection());
    }
}
