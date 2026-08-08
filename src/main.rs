// ピュア Rust 方針の明文化: 本番・テストビルドでは unsafe を全面禁止する。
// 例外は Kani 証明ハーネス（kani_harness.rs）のみ——シンボリック入力のモデル化に
// from_utf8_unchecked を使うため、cargo kani 時だけ forbid を外す。
#![cfg_attr(not(kani), forbid(unsafe_code))]

mod account_admin;
mod admin_store;
mod audit_log;
mod auth_checks;
mod ciba;
mod claims;
mod client_auth;
mod context;
mod dcr;
mod dcr_store;
#[cfg(test)]
mod diff_tests;
mod dpop;
mod error;
mod es256;
#[cfg(test)]
mod fuzz_tests;
mod fcm;
mod fido;
mod firestore;
mod firestore_store;
mod grants;
mod interaction_policy;
mod jwks_resolver;
mod jws;
#[cfg(kani)]
mod kani_harness;
mod kms;
mod mailer;
mod model;
mod nonce;
mod par;
mod provider;
mod registration;
mod request_object;
mod response_mode;
mod sig;
mod step_up;
mod store;
mod web;
mod webauthn;

use model::Client;
use provider::Provider;

#[tokio::main]
async fn main() {
    // ログ: Cloud Run では構造化 JSON（Cloud Logging がフィールド解析→log-based metric/alert）。
    // ローカルは人間可読のまま。管理者サブコマンドの分岐より前に初期化する:
    // 以前はサーバ起動パスの直前で初期化していたため、サブコマンド(mint/disable-account等)
    // 内の tracing::error!/warn! がサブスクライバ未設置のまま呼ばれ、実行時に完全に
    // 握りつぶされていた(server起動パスの request handler には影響しない——そちらは
    // 元々この初期化より後にしか到達しないため)。
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info".into());
    if std::env::var("K_SERVICE").is_ok() {
        tracing_subscriber::fmt().json().with_env_filter(env_filter).init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }

    // 管理者用サブコマンド（out-of-band）。サーバ起動前に分岐する。
    let argv: Vec<String> = std::env::args().collect();
    match argv.get(1).map(String::as_str) {
        Some("mint") => {
            mint_iat(&argv[2..]).await;
            return;
        }
        Some("revoke-client") => {
            revoke_client(&argv[2..]).await;
            return;
        }
        Some("grant-admin") => {
            grant_admin_cmd(&argv[2..]).await;
            return;
        }
        Some("revoke-admin") => {
            revoke_admin_cmd(&argv[2..]).await;
            return;
        }
        Some("disable-account") => {
            disable_account_cmd(&argv[2..]).await;
            return;
        }
        Some("enable-account") => {
            enable_account_cmd(&argv[2..]).await;
            return;
        }
        Some("migrate-static-clients") => {
            migrate_static_clients_cmd(&argv[2..]).await;
            return;
        }
        _ => {}
    }

    // ORIGIN = スキーム+ホスト（例 https://oidc.sonrisa.co.jp）。
    // BASE_PATH = Hosting rewrite のパス接頭辞（例 /roidc）。issuer = ORIGIN + BASE_PATH。
    let origin = std::env::var("ORIGIN").unwrap_or_else(|_| "http://localhost:8080".into());
    let base_path = std::env::var("BASE_PATH").unwrap_or_default();
    let issuer = format!("{origin}{base_path}");

    // demo-rp / mobile-rp / ciba-rp / qm-rp は Step5 の移行(migrate-static-clients)で
    // Firestore(clients/)へ移り、resolve_client の静的Map→Firestoreフォールバック経由で
    // 解決される（static_app_clients は移行コマンド専用の定義源として main.rs 側に残す）。
    // このため Firestore が未配線のローカル実行(FIRESTORE_EMULATOR_HOST 未設定)では
    // これらのクライアントは解決できない点に注意（demo-rp 等の動作確認には
    // FIRESTORE_EMULATOR_HOST を設定し migrate-static-clients を流し込んでおくこと）。
    let mut provider = Provider::new(issuer.clone()).with_base_path(base_path.clone());

    // FAPI2 conformance 用の静的クライアント（fapi-1 = client / fapi-2 = client2）。
    // FAPI 認定スイートは動的登録 variant を持たず静的クライアント専用なので、認定時のみ
    // env で公開鍵（FAPI{1,2}_X/Y/KID）を与えて登録する。env 未設定の本番では登録されない
    // （= パラメータ切替: 鍵 env を入れれば ON、外せば OFF）。private_key_jwt + PAR + PKCE + DPoP。
    for (id, prefix) in [("fapi-1", "FAPI1"), ("fapi-2", "FAPI2")] {
        if let Some(client) = fapi_client_from_env(id, prefix) {
            tracing::info!("registered FAPI conformance client {id} from env");
            provider = provider.with_client(client);
        }
    }

    // Cloud Run 上 (K_SERVICE あり) では Firestore + KMS/Secret Manager + Resend を有効化。
    // ローカルで FIRESTORE_EMULATOR_HOST のみ設定されている場合は、Firestore 関連の配線
    // （Store/CibaStore/DPoP/private_key_jwt/registration 直叩き）だけをエミュレータへ向けて
    // 有効化する。KMS・Secret Manager・Resend は実 GCP 前提なので K_SERVICE 限定のまま
    // （ローカルは Provider::new の既定 ephemeral 鍵 + LogMailer で動かす）。
    let use_firestore =
        std::env::var("K_SERVICE").is_ok() || std::env::var("FIRESTORE_EMULATOR_HOST").is_ok();
    if use_firestore {
        let fs = std::sync::Arc::new(firestore::Firestore::new(resolve_project()));
        if std::env::var("K_SERVICE").is_ok() {
        // 署名鍵 ES256: KMS_ES256_KEY があれば Cloud KMS（秘密鍵をプロセスに展開しない）、
        // 無ければ Secret Manager の固定鍵。本番(K_SERVICE)ではどちらからも正規鍵を
        // ロードできなければ起動を中止する（起動ごとの一時鍵での縮退運用を禁止）。
        let es_kms: Option<std::sync::Arc<dyn jws::JwsSigner>> = match std::env::var("KMS_ES256_KEY") {
            Ok(key) => match kms::KmsSigner::es256(fs.clone(), &key).await {
                Ok(s) => {
                    tracing::info!("ES256 signing via Cloud KMS");
                    Some(std::sync::Arc::new(s))
                }
                Err(e) => {
                    tracing::error!("KMS ES256 init failed ({e}); falling back to Secret Manager");
                    None
                }
            },
            Err(_) => None,
        };
        let es_loaded = if let Some(s) = es_kms {
            provider = provider.with_signer(s);
            true
        } else {
            match fs.access_secret("oidc-signing-key-es256").await {
                Ok(Some(scalar)) => match jws::Es256Signer::from_scalar_b64(&scalar) {
                    Ok(signer) => {
                        tracing::info!("loaded ES256 signing key from Secret Manager");
                        provider = provider.with_signer(std::sync::Arc::new(signer));
                        true
                    }
                    Err(e) => {
                        tracing::error!("ES256 key from Secret Manager invalid: {e}");
                        false
                    }
                },
                Ok(None) => {
                    tracing::error!("ES256 signing key not found in KMS or Secret Manager");
                    false
                }
                Err(e) => {
                    tracing::error!("ES256 secret access failed: {e}");
                    false
                }
            }
        };
        if !es_loaded {
            tracing::error!(
                "FATAL: no production ES256 signing key available; refusing to start with an ephemeral key"
            );
            std::process::exit(1);
        }
        // RS256（OIDC Core §15.1 必須）: KMS_RS256_KEY 優先、無ければ Secret Manager。
        // ES256 と同じく、本番では正規鍵をロードできなければ起動を中止する。
        let rs_kms: Option<std::sync::Arc<dyn jws::JwsSigner>> = match std::env::var("KMS_RS256_KEY") {
            Ok(key) => match kms::KmsSigner::rs256(fs.clone(), &key).await {
                Ok(s) => {
                    tracing::info!("RS256 signing via Cloud KMS");
                    Some(std::sync::Arc::new(s))
                }
                Err(e) => {
                    tracing::error!("KMS RS256 init failed ({e}); falling back to Secret Manager");
                    None
                }
            },
            Err(_) => None,
        };
        let rs_loaded = if let Some(s) = rs_kms {
            provider = provider.add_signer(s);
            true
        } else {
            match fs.access_secret("oidc-signing-key-rs256").await {
                Ok(Some(pem)) => match jws::Rs256Signer::from_pkcs8_pem(&pem) {
                    Ok(signer) => {
                        tracing::info!("loaded RS256 signing key from Secret Manager");
                        provider = provider.add_signer(std::sync::Arc::new(signer));
                        true
                    }
                    Err(e) => {
                        tracing::error!("RS256 key from Secret Manager invalid: {e}");
                        false
                    }
                },
                Ok(None) => {
                    tracing::error!("RS256 signing key not found in KMS or Secret Manager");
                    false
                }
                Err(e) => {
                    tracing::error!("RS256 secret access failed: {e}");
                    false
                }
            }
        };
        if !rs_loaded {
            tracing::error!(
                "FATAL: no production RS256 signing key available; refusing to start with an ephemeral key"
            );
            std::process::exit(1);
        }
        } // K_SERVICE 限定(KMS/Secret Manager 署名鍵)ここまで。

        // jti リプレイ防止を Firestore に分散化（インスタンス跨ぎで単回を保証）。
        // ここから下は use_firestore（K_SERVICE または FIRESTORE_EMULATOR_HOST）で共通。
        provider =
            provider.with_dpop(std::sync::Arc::new(dpop::Es256Dpop::with_store(fs.clone())));
        provider.client_auth.insert(
            "private_key_jwt".into(),
            std::sync::Arc::new(client_auth::PrivateKeyJwt::with_store(fs.clone())),
        );
        // セッション/コード/トークンも Firestore に永続化（インスタンス跨ぎ）。
        provider = provider
            .with_store(std::sync::Arc::new(firestore_store::FirestoreStore::new(fs.clone())))
            .with_ciba(std::sync::Arc::new(ciba::FirestoreCibaStore::new(fs.clone())))
            .with_firestore(fs);
        if let Ok(key) = std::env::var("RESEND_API_KEY") {
            provider = provider.with_mailer(std::sync::Arc::new(mailer::ResendMailer::new(key)));
        }
    }

    let app = web::router(provider);

    if std::env::var("K_SERVICE").is_ok() {
        // Cloud Run は $PORT を 0.0.0.0 で待ち受ける。
        let port = std::env::var("PORT").unwrap_or_else(|_| "8080".into());
        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await.unwrap();
        tracing::info!("rust-op listening on 0.0.0.0:{port} (issuer={issuer})");
        axum::serve(listener, app).await.unwrap();
    } else {
        // ローカルは IPv4/IPv6 ループバック両方で待つ。Conformance Tool(Chromium)が
        // localhost を ::1 に解決しても届くようにする（127.0.0.1 だけだと Failed to fetch）。
        let port = std::env::var("ADDR")
            .ok()
            .and_then(|a| a.rsplit(':').next().map(|s| s.to_string()))
            .or_else(|| std::env::var("PORT").ok())
            .unwrap_or_else(|| "8080".into());
        let v4 = tokio::net::TcpListener::bind(format!("127.0.0.1:{port}")).await.unwrap();
        let app2 = app.clone();
        tracing::info!("rust-op local listening on 127.0.0.1:{port} and [::1]:{port} (issuer={issuer})");
        match tokio::net::TcpListener::bind(format!("[::1]:{port}")).await {
            Ok(v6) => {
                let _ = tokio::join!(
                    axum::serve(v4, app),
                    axum::serve(v6, app2),
                );
            }
            Err(e) => {
                tracing::warn!("IPv6 loopback bind failed ({e}); IPv4 only");
                axum::serve(v4, app).await.unwrap();
            }
        }
    }
}

/// 管理者用 Initial Access Token 発行（制御つき DCR）。
///
/// `rust-op mint --redirect-host <host> [--redirect-host ...] [--grant <gt> ...]
///     [--profile public|confidential-secret|confidential-key] [--ttl-hours N]`
///
/// --profile は発行するクライアントの認証方式を固定する（省略時 confidential-key = 従来唯一の
/// 挙動、private_key_jwt/FAPI2相当）。RP 側がリクエストで選ぶものではない——弱いプロファイルへの
/// 自己ダウングレードを防ぐため、管理者が mint 時に決める（[`dcr::ClientProfile`] 参照）。
///
/// Firestore へは Cloud Run のメタデータ SA で書くため **GCP 内（Cloud Run job 等）での実行を前提**
/// にする。生 IAT は stdout に一度だけ出すが、**この出力は実行ジョブのログ(Cloud Logging)に残る**。
/// 安全性は「Log Viewer 権限 + 短い TTL + 単回利用」に依存する（生は DB にはハッシュしか残さない）。
async fn mint_iat(args: &[String]) {
    let mut hosts: Vec<String> = vec![];
    let mut grants: Vec<String> = vec![];
    let mut ttl_hours: u64 = 24;
    let mut reusable = false;
    let mut profile = dcr::ClientProfile::ConfidentialKey;
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--redirect-host" => match it.next() {
                Some(v) => hosts.push(v.clone()),
                None => fail("--redirect-host needs a value"),
            },
            "--grant" => match it.next() {
                Some(v) => grants.push(v.clone()),
                None => fail("--grant needs a value"),
            },
            "--profile" => match it.next().map(String::as_str) {
                Some("public") => profile = dcr::ClientProfile::Public,
                Some("confidential-secret") => profile = dcr::ClientProfile::ConfidentialSecret,
                Some("confidential-key") => profile = dcr::ClientProfile::ConfidentialKey,
                _ => fail("--profile needs one of: public, confidential-secret, confidential-key"),
            },
            "--ttl-hours" => match it.next().and_then(|v| v.parse().ok()) {
                Some(n) => ttl_hours = n,
                None => fail("--ttl-hours needs a positive integer"),
            },
            // conformance 専用: 期限内は単回消費しない（スイートがモジュール毎に多数登録するため）。
            // 短い TTL（例 2h）と組み合わせて使うこと。
            "--reusable" => reusable = true,
            other => fail(&format!("unknown arg {other}")),
        }
    }
    if hosts.is_empty() {
        fail("--redirect-host <host> を最低 1 つ指定してください");
    }
    if grants.is_empty() {
        grants = vec!["authorization_code".into(), "refresh_token".into()];
    }

    let fs = firestore::Firestore::new(resolve_project());
    let constraints = dcr::IatConstraints {
        allowed_redirect_hosts: hosts.clone(),
        allowed_grant_types: grants.clone(),
        profile,
    };
    let (raw, hash) = dcr::gen_random_token();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expires_at = now + ttl_hours * 3600;
    if let Err(e) = dcr_store::put_iat(&fs, &hash, &constraints, expires_at, reusable).await {
        eprintln!("mint: IAT 保存に失敗: {e}");
        std::process::exit(1);
    }
    println!("initial_access_token:   {raw}");
    println!("token_hash:             {hash}");
    println!("profile:                {profile:?}");
    println!("allowed_redirect_hosts: {}", hosts.join(", "));
    println!("allowed_grant_types:    {}", grants.join(", "));
    println!("expires_at:             {expires_at} (epoch, +{ttl_hours}h)");
    println!("reusable:               {reusable}");
    eprintln!("注意: 生トークンの表示は一度だけ。この出力は Cloud Logging に残ります。");
}

/// demo-rp/mobile-rp/ciba-rp/qm-rp の定義。Step5 完了により main() はこれを直接使わなく
/// なり（resolve_client の Firestore フォールバックで解決する）、migrate_static_clients_cmd
/// 専用の定義源として残る（再移行・検証時にここを見れば「あるべき姿」がわかる）。
/// ciba_rp_secret_hash/qm_rp_secret_hash は既にハッシュ済み（dcr::hash_token通過後）の
/// 値を渡すこと（ここでは平文を一切扱わない）。
fn static_app_clients(issuer: &str, ciba_rp_secret_hash: String, qm_rp_secret_hash: String) -> Vec<Client> {
    vec![
        // demo-rp: public client + PKCE。redirect_uri は内蔵コールバックページ。
        Client {
            client_id: "demo-rp".into(),
            redirect_uris: vec![format!("{issuer}/callback")],
            post_logout_redirect_uris: vec![format!("{issuer}/")],
            token_endpoint_auth_method: "none".into(),
            client_secret: None,
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            dpop_bound: true,
            jwks: vec![],
            jwks_uri: None,
            require_par: false,
            require_pkce: false,
            id_token_signed_response_alg: None,
        },
        // Flutter ネイティブアプリ fido2demo（public + PKCE, custom scheme, DPoP）。
        Client {
            client_id: "mobile-rp".into(),
            redirect_uris: vec!["jp.co.sonrisa.fido2demo://callback".into()],
            post_logout_redirect_uris: vec!["jp.co.sonrisa.fido2demo://logout".into()],
            token_endpoint_auth_method: "none".into(),
            client_secret: None,
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            dpop_bound: true,
            jwks: vec![],
            jwks_uri: None,
            require_par: false,
            require_pkce: false,
            id_token_signed_response_alg: None,
        },
        // CIBA Consumption Device 用クライアント（poll, client_secret_basic）。
        Client {
            client_id: "ciba-rp".into(),
            redirect_uris: vec![],
            post_logout_redirect_uris: vec![],
            token_endpoint_auth_method: "client_secret_basic".into(),
            client_secret: Some(ciba_rp_secret_hash),
            grant_types: vec!["urn:openid:params:grant-type:ciba".into()],
            dpop_bound: false,
            jwks: vec![],
            jwks_uri: None,
            require_par: false,
            require_pkce: false,
            id_token_signed_response_alg: None,
        },
        // qm-rp: FAPI 2.0 厳格設定を満たせない外部 RP 用の静的クライアント
        // （client_secret_basic + PKCE のみ。PAR/DPoP は非対応）。
        Client {
            client_id: "qm-rp".into(),
            redirect_uris: vec!["http://127.0.0.1:8082/auth/callback".into()],
            post_logout_redirect_uris: vec!["http://127.0.0.1:8082/".into()],
            token_endpoint_auth_method: "client_secret_basic".into(),
            client_secret: Some(qm_rp_secret_hash),
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            dpop_bound: false,
            jwks: vec![],
            jwks_uri: None,
            require_par: false,
            require_pkce: true, // qm は S256 を送るので有効化できる
            id_token_signed_response_alg: None,
        },
    ]
}

/// FAPI conformance クライアントを env から組む。`{prefix}_X` `{prefix}_Y` `{prefix}_KID`
/// が全て揃っていれば Some。揃っていなければ None（= 本番で未登録）。
/// redirect は認定スイートの alias コールバック固定（`CONFORMANCE_FAPI_CALLBACK` で上書き可）。
fn fapi_client_from_env(client_id: &str, prefix: &str) -> Option<Client> {
    let x = std::env::var(format!("{prefix}_X")).ok()?;
    let y = std::env::var(format!("{prefix}_Y")).ok()?;
    let kid = std::env::var(format!("{prefix}_KID")).ok()?;
    let callback = std::env::var("CONFORMANCE_FAPI_CALLBACK")
        .unwrap_or_else(|_| "https://www.certification.openid.net/test/a/rustop-fapi2/callback".into());
    Some(Client {
        client_id: client_id.into(),
        redirect_uris: vec![callback],
        post_logout_redirect_uris: vec![],
        token_endpoint_auth_method: "private_key_jwt".into(),
        client_secret: None,
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        dpop_bound: true,
        jwks: vec![model::JwkPub { kid, x, y }],
        jwks_uri: None,
        require_par: true,
        require_pkce: true,
        id_token_signed_response_alg: None,
    })
}

fn fail(msg: &str) -> ! {
    eprintln!("mint: {msg}");
    std::process::exit(2);
}

/// 管理者用サブコマンド/Firestore配線が使う GCP プロジェクトIDの解決。
/// GCLOUD_PROJECT → GOOGLE_CLOUD_PROJECT → 既定値("fido2-8b943")の順。
fn resolve_project() -> String {
    std::env::var("GCLOUD_PROJECT")
        .or_else(|_| std::env::var("GOOGLE_CLOUD_PROJECT"))
        .unwrap_or_else(|_| "fido2-8b943".into())
}

/// 管理者用クライアント revoke（制御つき DCR）。
///
/// `rust-op revoke-client <client_id>`
///
/// clients/{client_id} を削除する。失効の意味論は [`dcr_store::revoke_client`] 参照
/// （新規認可・refresh は即停止、発行済み AT は ≤15 分で自然失効）。mint 同様 GCP 内実行前提。
async fn revoke_client(args: &[String]) {
    let client_id = match args.first() {
        Some(id) if !id.starts_with('-') => id.clone(),
        _ => {
            eprintln!("revoke-client: usage: rust-op revoke-client <client_id>");
            std::process::exit(2);
        }
    };
    let fs = firestore::Firestore::new(resolve_project());
    match dcr_store::revoke_client(&fs, &client_id).await {
        Ok(true) => println!("revoked: {client_id}（新規認可・refresh は即停止、発行済み AT は ≤15 分で失効）"),
        Ok(false) => {
            eprintln!("revoke-client: not found: {client_id}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("revoke-client: 失敗: {e}");
            std::process::exit(1);
        }
    }
}

/// --email の値を、accounts コレクションのキー（web/register.rs が signup 時に
/// 適用する trim + to_lowercase）と同じ正規化をかけて返す。ここで揃えないと、大文字/
/// 前後空白混じりのメール指定が accounts/{email} に一致せず「account not found」になる。
fn parse_email_arg(cmd: &str, args: &[String]) -> String {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--email" {
            if let Some(v) = it.next() {
                return v.trim().to_lowercase();
            }
        }
    }
    eprintln!("{cmd}: usage: rust-op {cmd} --email <email>");
    std::process::exit(2);
}

/// 管理者権限の付与（初回シード含む）。
///
/// `rust-op grant-admin --email <email>`
///
/// accounts/{email} から account_id を引いて admins/{account_id} に書く（[`admin_store::grant_admin`]）。
/// 対象は先に passkey 登録済みであること。mint/revoke-client 同様 GCP 内実行前提。
async fn grant_admin_cmd(args: &[String]) {
    let email = parse_email_arg("grant-admin", args);
    let fs = firestore::Firestore::new(resolve_project());
    let account_id = resolve_account_id("grant-admin", &fs, &email).await;
    match admin_store::grant_admin(&fs, &account_id, "cli").await {
        Ok(admin_store::GrantAdminResult::Granted) => {
            audit_log::record(&fs, "cli", "grant_admin", &account_id, &format!("email={email}")).await;
            println!("granted: {email} (account_id={account_id})")
        }
        Ok(admin_store::GrantAdminResult::AlreadyAdmin) => {
            println!("already admin: {email} (account_id={account_id})")
        }
        Ok(admin_store::GrantAdminResult::Conflict) => {
            eprintln!("grant-admin: 他の書き込みと競合しました。もう一度実行してください: {email}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("grant-admin: 失敗: {e}");
            std::process::exit(1);
        }
    }
}

/// email から account_id を引く（grant-admin/revoke-admin 共通）。
/// accountId フィールドが空/欠落の壊れたドキュメントを、空文字列の account_id のまま
/// admin_store へ渡さないようここで弾く（空文字列は他のどのセッションの account_id とも
/// 一致しないはずだが、不正な入力を admin_store 層まで運ばない防御として明示的に検査する）。
async fn resolve_account_id(cmd: &str, fs: &firestore::Firestore, email: &str) -> String {
    let account_id = match registration::get_credential(fs, email).await {
        Ok(Some(c)) => c.account_id,
        Ok(None) => {
            eprintln!("{cmd}: account not found: {email}（先に passkey 登録を済ませてください）");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("{cmd}: account lookup failed: {e}");
            std::process::exit(1);
        }
    };
    if account_id.trim().is_empty() {
        eprintln!("{cmd}: account record for {email} has no accountId (破損データの可能性)");
        std::process::exit(1);
    }
    account_id
}

/// 管理者権限の剥奪。最後の1人は拒否される（[`admin_store::revoke_admin`] 参照）。
///
/// `rust-op revoke-admin --email <email>`
async fn revoke_admin_cmd(args: &[String]) {
    let email = parse_email_arg("revoke-admin", args);
    let fs = firestore::Firestore::new(resolve_project());
    let account_id = resolve_account_id("revoke-admin", &fs, &email).await;
    match admin_store::revoke_admin(&fs, &account_id).await {
        Ok(admin_store::RevokeAdminResult::Revoked) => {
            audit_log::record(&fs, "cli", "revoke_admin", &account_id, &format!("email={email}")).await;
            println!("revoked: {email} (account_id={account_id})")
        }
        Ok(admin_store::RevokeAdminResult::NotAdmin) => {
            eprintln!("revoke-admin: not an admin: {email}");
            std::process::exit(1);
        }
        Ok(admin_store::RevokeAdminResult::LastAdminGuard) => {
            eprintln!("revoke-admin: 拒否: 最後の管理者は剥奪できません: {email}");
            std::process::exit(1);
        }
        Ok(admin_store::RevokeAdminResult::Conflict) => {
            eprintln!("revoke-admin: 他の書き込みと競合しました。もう一度実行してください: {email}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("revoke-admin: 失敗: {e}");
            std::process::exit(1);
        }
    }
}

/// アカウントの凍結。新規ログイン/CIBA承認を拒否し、既存の SSO セッションを破棄する
/// （access/refresh token は対象外。TTL が短くローテーションするため。
/// [`account_admin::disable_account`] 参照）。
///
/// `rust-op disable-account --email <email>`
async fn disable_account_cmd(args: &[String]) {
    let email = parse_email_arg("disable-account", args);
    let fs = firestore::Firestore::new(resolve_project());
    let report = |label: &str, counts: &account_admin::RevocationCounts| {
        println!(
            "{label}: {email} (sessions={} access_tokens={} refresh_tokens={})",
            counts.sessions, counts.access_tokens, counts.refresh_tokens
        );
        if !counts.query_errors.is_empty() {
            // disabled フラグ自体は既に立っているので新規ログインは止まるが、失効できたか
            // 不明なセッション/トークンが残っている可能性がある旨を明示し、exit(1) で
            // 「完全ではない」ことを気付けるようにする(disable自体は成立している)。
            eprintln!(
                "WARNING: 以下は検索自体に失敗し、失効できたか不明です（存在しない=0件、ではありません）: {:?}",
                counts.query_errors
            );
            std::process::exit(1);
        }
    };
    match account_admin::disable_account(&fs, "cli", &email).await {
        Ok(account_admin::DisableOutcome::Disabled(counts)) => report("disabled", &counts),
        Ok(account_admin::DisableOutcome::AlreadyDisabled(counts)) => {
            report("already disabled", &counts)
        }
        Ok(account_admin::DisableOutcome::NotFound) => {
            eprintln!("disable-account: account not found: {email}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("disable-account: 失敗: {e}");
            std::process::exit(1);
        }
    }
}

/// アカウント凍結の解除。
///
/// `rust-op enable-account --email <email>`
async fn enable_account_cmd(args: &[String]) {
    let email = parse_email_arg("enable-account", args);
    let fs = firestore::Firestore::new(resolve_project());
    match account_admin::enable_account(&fs, "cli", &email).await {
        Ok(account_admin::EnableOutcome::Enabled) => println!("enabled: {email}"),
        Ok(account_admin::EnableOutcome::AlreadyEnabled) => println!("already enabled: {email}"),
        Ok(account_admin::EnableOutcome::NotFound) => {
            eprintln!("enable-account: account not found: {email}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("enable-account: 失敗: {e}");
            std::process::exit(1);
        }
    }
}

/// 環境変数を必須として取得する。未設定/空でもフォールバックしない
/// （migrate_static_clients_cmd 専用。ORIGIN が未設定のまま実行すると、
/// main() 自体はローカル開発向けに `http://localhost:8080` へ静かにフォールバックするが、
/// 移行コマンドでこれをやると誤った redirect_uris を本番Firestoreへ永続化してしまう。
/// dcr_store::save_client は create_if_absent のため、後から静かに上書き修正することもできず
/// 手動削除が要る事故になる。フォールバックせず即座に失敗させ、正しい値を明示させる）。
fn require_env(name: &str) -> String {
    match std::env::var(name) {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            eprintln!(
                "migrate-static-clients: 環境変数 {name} が必要です（未設定時のフォールバックは行いません）"
            );
            std::process::exit(2);
        }
    }
}

/// Secret Manager から取得したclient_secretをハッシュ化する。取得できた値がたまたま
/// 同名の環境変数にも設定されていれば一致を確認する: 本コマンドはSecret Managerを直接
/// 読む唯一の経路（Step5完了によりmain()はCIBA_RP_SECRET/QM_RP_SECRETを一切読まなくなり、
/// これらのclient_secretはFirestoreに保存済みのハッシュのみを唯一の正とする）。それでも
/// 念のため、たまたま同名の環境変数が設定されていれば一致を確認する（食い違いに気づかず
/// 誤ったハッシュをFirestoreへ書き込むと、save_client が create_if_absent のため事後修正も
/// 手動削除が要る）。ローカル実行では通常env var未設定なので、その場合はSecret Manager
/// の値をそのまま信頼する。
async fn secret_hash_from_manager_verified(fs: &firestore::Firestore, name: &'static str) -> String {
    let raw = match fs.access_secret(name).await {
        Ok(Some(v)) => v,
        Ok(None) => {
            eprintln!("migrate-static-clients: Secret Manager に {name} が見つかりません");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("migrate-static-clients: {name} の取得に失敗: {e}");
            std::process::exit(1);
        }
    };
    if let Ok(env_val) = std::env::var(name) {
        if env_val != raw {
            eprintln!(
                "migrate-static-clients: 環境変数 {name} と Secret Manager の値が一致しません。どちらが正か確認してください。"
            );
            std::process::exit(1);
        }
    }
    dcr::hash_token(&raw)
}

/// demo-rp/mobile-rp/ciba-rp/qm-rp を Firestore(clients/)へ一度きり移行する(Step5)。
/// main() は既にこれらの静的登録(.with_client)を持たず、resolve_client の Firestore
/// フォールバックのみで解決する。**そのため、このコマンドを対象のFirestoreデータベースへ
/// 実行し終える前に新しいバイナリをデプロイすると、そのデータベースを向いているサービスは
/// これら4クライアントを一切解決できなくなる**（本番/stagingでそれぞれ別のFirestore
/// データベースを使う構成では、両方に対して実行すること。デプロイ順序を守るための
/// 自動チェックはコード側にもCI/CD側にも無いため、運用上の手順として徹底する必要がある）。
///
/// client_secret は Secret Manager の CIBA_RP_SECRET/QM_RP_SECRET の**現在値**をハッシュ化して
/// 保存する（新規生成しない。既存の外部RP統合(QM等)のsecretをローテーションさせないため）。
///
/// ドライランは Firestore の現状（各client_idが既にあるか）だけ確認する。Secret Manager
/// へは触れないため、Secret Manager の IAM 権限が無くても事前確認できる
/// （逆に --apply は常に Secret Manager アクセスが要る。FIRESTORE_EMULATOR_HOST を立てた
/// だけのローカル実行では --apply できない）。
///
/// `rust-op migrate-static-clients`          # ドライラン
/// `rust-op migrate-static-clients --apply`  # 実行
///
/// dcr_store::save_client は create_if_absent なので、既に移行済みのclient_idに対する
/// 再実行は上書きせずエラーになる（静かな上書きを防ぐ。再移行したい場合はFirestore側の
/// ドキュメントを先に削除すること）。書き込み後は即座に読み戻して意図通りの内容が
/// 保存されたか検証する。1件でも失敗・不一致があれば exit(1) する
/// （eprintln だけで exit 0 のままだと、これを起点に静的登録を削除する後続作業が
/// 「全件成功した」と誤認して本番の認証を壊しかねない）。
async fn migrate_static_clients_cmd(args: &[String]) {
    let apply = args.iter().any(|a| a == "--apply");
    let fs = firestore::Firestore::new(resolve_project());

    if !apply {
        println!("[dry-run] project={}", fs.project());
        for id in ["demo-rp", "mobile-rp", "ciba-rp", "qm-rp"] {
            let status = if dcr_store::load_client(&fs, id).await.is_some() {
                "既にFirestoreに存在（--apply はこの client_id をエラーにします）"
            } else {
                "未移行（--apply で移行されます）"
            };
            println!("  {id}: {status}");
        }
        return;
    }

    let origin = require_env("ORIGIN");
    let base_path = std::env::var("BASE_PATH").unwrap_or_default();
    let issuer = format!("{origin}{base_path}");
    let ciba_rp_secret_hash = secret_hash_from_manager_verified(&fs, "CIBA_RP_SECRET").await;
    let qm_rp_secret_hash = secret_hash_from_manager_verified(&fs, "QM_RP_SECRET").await;

    let mut had_error = false;
    for c in static_app_clients(&issuer, ciba_rp_secret_hash, qm_rp_secret_hash) {
        let expected_json = serde_json::to_string(&c).unwrap();
        match dcr_store::save_client(&fs, &c).await {
            Ok(()) => match dcr_store::load_client(&fs, &c.client_id).await {
                Some(saved) if serde_json::to_string(&saved).unwrap() == expected_json => {
                    println!("migrated (verified): {}", c.client_id)
                }
                Some(_) => {
                    eprintln!("migrate-static-clients: {}: 書き込み後の読み戻しが一致しません", c.client_id);
                    had_error = true;
                }
                None => {
                    eprintln!("migrate-static-clients: {}: 書き込み後に読み戻せません", c.client_id);
                    had_error = true;
                }
            },
            Err(e) => {
                eprintln!("migrate-static-clients: {}: {e}", c.client_id);
                had_error = true;
            }
        }
    }
    if had_error {
        eprintln!("migrate-static-clients: 一部のクライアントで失敗しました。上記を確認してください。");
        std::process::exit(1);
    }
}
