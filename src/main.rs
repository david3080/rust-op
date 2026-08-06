// ピュア Rust 方針の明文化: 本番・テストビルドでは unsafe を全面禁止する。
// 例外は Kani 証明ハーネス（kani_harness.rs）のみ——シンボリック入力のモデル化に
// from_utf8_unchecked を使うため、cargo kani 時だけ forbid を外す。
#![cfg_attr(not(kani), forbid(unsafe_code))]

mod admin_store;
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
        _ => {}
    }

    // ログ: Cloud Run では構造化 JSON（Cloud Logging がフィールド解析→log-based metric/alert）。
    // ローカルは人間可読のまま。
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| "info".into());
    if std::env::var("K_SERVICE").is_ok() {
        tracing_subscriber::fmt().json().with_env_filter(env_filter).init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }

    // ORIGIN = スキーム+ホスト（例 https://oidc.sonrisa.co.jp）。
    // BASE_PATH = Hosting rewrite のパス接頭辞（例 /roidc）。issuer = ORIGIN + BASE_PATH。
    let origin = std::env::var("ORIGIN").unwrap_or_else(|_| "http://localhost:8080".into());
    let base_path = std::env::var("BASE_PATH").unwrap_or_default();
    let issuer = format!("{origin}{base_path}");

    // 静的 conformance クライアントのシークレットは env から注入する（ソースに平文を残さない）。
    // 未設定時は起動毎のランダム値にフォールバックし、既知シークレットを世に晒さない
    // （= env 未設定の本番では当該クライアントは事実上利用不能になる）。
    let secret_from_env =
        |key: &str| std::env::var(key).unwrap_or_else(|_| uuid::Uuid::new_v4().simple().to_string());

    // demo-rp: public client + PKCE。redirect_uri は内蔵コールバックページ。
    let demo_rp = Client {
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
    };

    // Flutter ネイティブアプリ fido2demo（public + PKCE, custom scheme, DPoP）。
    let mobile_rp = Client {
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
    };

    // CIBA Consumption Device 用クライアント（poll, client_secret_basic）。
    let ciba_rp = Client {
        client_id: "ciba-rp".into(),
        redirect_uris: vec![],
        post_logout_redirect_uris: vec![],
        token_endpoint_auth_method: "client_secret_basic".into(),
        client_secret: Some(secret_from_env("CIBA_RP_SECRET")),
        grant_types: vec!["urn:openid:params:grant-type:ciba".into()],
        dpop_bound: false,
        jwks: vec![],
            jwks_uri: None,
        require_par: false,
        require_pkce: false,
        id_token_signed_response_alg: None,
    };

    // qm-rp: FAPI 2.0 厳格設定を満たせない外部 RP 用の静的クライアント
    // （client_secret_basic + PKCE のみ。PAR/DPoP は非対応）。
    let qm_rp = Client {
        client_id: "qm-rp".into(),
        redirect_uris: vec!["http://127.0.0.1:8082/auth/callback".into()],
        post_logout_redirect_uris: vec!["http://127.0.0.1:8082/".into()],
        token_endpoint_auth_method: "client_secret_basic".into(),
        client_secret: Some(secret_from_env("QM_RP_SECRET")),
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        dpop_bound: false,
        jwks: vec![],
        jwks_uri: None,
        require_par: false,
        require_pkce: true, // qm は S256 を送るので有効化できる
        id_token_signed_response_alg: None,
    };

    // demo-rp / mobile-rp / ciba-rp / qm-rp は実アプリ用で常時登録。
    // ciba-rp は実 CIBA バックエンド（client_secret_basic, DPoP 任意）。
    let mut provider = Provider::new(issuer.clone())
        .with_base_path(base_path.clone())
        .with_client(demo_rp)
        .with_client(mobile_rp)
        .with_client(ciba_rp)
        .with_client(qm_rp);

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
        let project = std::env::var("GCLOUD_PROJECT")
            .or_else(|_| std::env::var("GOOGLE_CLOUD_PROJECT"))
            .unwrap_or_else(|_| "fido2-8b943".into());
        let fs = std::sync::Arc::new(firestore::Firestore::new(project));
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
/// `rust-op mint --redirect-host <host> [--redirect-host ...] [--grant <gt> ...] [--ttl-hours N]`
///
/// Firestore へは Cloud Run のメタデータ SA で書くため **GCP 内（Cloud Run job 等）での実行を前提**
/// にする。生 IAT は stdout に一度だけ出すが、**この出力は実行ジョブのログ(Cloud Logging)に残る**。
/// 安全性は「Log Viewer 権限 + 短い TTL + 単回利用」に依存する（生は DB にはハッシュしか残さない）。
async fn mint_iat(args: &[String]) {
    let mut hosts: Vec<String> = vec![];
    let mut grants: Vec<String> = vec![];
    let mut ttl_hours: u64 = 24;
    let mut reusable = false;
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

    let project = std::env::var("GCLOUD_PROJECT")
        .or_else(|_| std::env::var("GOOGLE_CLOUD_PROJECT"))
        .unwrap_or_else(|_| "fido2-8b943".into());
    let fs = firestore::Firestore::new(project);
    let constraints = dcr::IatConstraints {
        allowed_redirect_hosts: hosts.clone(),
        allowed_grant_types: grants.clone(),
    };
    let (raw, hash) = dcr::gen_initial_access_token();
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
    println!("allowed_redirect_hosts: {}", hosts.join(", "));
    println!("allowed_grant_types:    {}", grants.join(", "));
    println!("expires_at:             {expires_at} (epoch, +{ttl_hours}h)");
    println!("reusable:               {reusable}");
    eprintln!("注意: 生トークンの表示は一度だけ。この出力は Cloud Logging に残ります。");
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
    let project = std::env::var("GCLOUD_PROJECT")
        .or_else(|_| std::env::var("GOOGLE_CLOUD_PROJECT"))
        .unwrap_or_else(|_| "fido2-8b943".into());
    let fs = firestore::Firestore::new(project);
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

fn parse_email_arg(cmd: &str, args: &[String]) -> String {
    let mut it = args.iter();
    while let Some(a) = it.next() {
        if a == "--email" {
            if let Some(v) = it.next() {
                return v.clone();
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
    let project = std::env::var("GCLOUD_PROJECT")
        .or_else(|_| std::env::var("GOOGLE_CLOUD_PROJECT"))
        .unwrap_or_else(|_| "fido2-8b943".into());
    let fs = firestore::Firestore::new(project);
    let account_id = match registration::get_credential(&fs, &email).await {
        Ok(Some(c)) => c.account_id,
        Ok(None) => {
            eprintln!("grant-admin: account not found: {email}（先に passkey 登録を済ませてください）");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("grant-admin: account lookup failed: {e}");
            std::process::exit(1);
        }
    };
    match admin_store::grant_admin(&fs, &account_id, "cli").await {
        Ok(()) => println!("granted: {email} (account_id={account_id})"),
        Err(e) => {
            eprintln!("grant-admin: 失敗: {e}");
            std::process::exit(1);
        }
    }
}

/// 管理者権限の剥奪。最後の1人は拒否される（[`admin_store::revoke_admin`] 参照）。
///
/// `rust-op revoke-admin --email <email>`
async fn revoke_admin_cmd(args: &[String]) {
    let email = parse_email_arg("revoke-admin", args);
    let project = std::env::var("GCLOUD_PROJECT")
        .or_else(|_| std::env::var("GOOGLE_CLOUD_PROJECT"))
        .unwrap_or_else(|_| "fido2-8b943".into());
    let fs = firestore::Firestore::new(project);
    let account_id = match registration::get_credential(&fs, &email).await {
        Ok(Some(c)) => c.account_id,
        Ok(None) => {
            eprintln!("revoke-admin: account not found: {email}");
            std::process::exit(1);
        }
        Err(e) => {
            eprintln!("revoke-admin: account lookup failed: {e}");
            std::process::exit(1);
        }
    };
    match admin_store::revoke_admin(&fs, &account_id).await {
        Ok(admin_store::RevokeAdminResult::Revoked) => {
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
        Err(e) => {
            eprintln!("revoke-admin: 失敗: {e}");
            std::process::exit(1);
        }
    }
}
