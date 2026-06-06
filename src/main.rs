mod auth_checks;
mod ciba;
mod claims;
mod client_auth;
mod context;
mod dcr;
mod dcr_store;
mod dpop;
mod error;
mod es256;
mod fcm;
mod fido;
mod firestore;
mod firestore_store;
mod grants;
mod interaction_policy;
mod jws;
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
    // 管理者用 IAT 発行サブコマンド（out-of-band）。サーバ起動前に分岐する。
    let argv: Vec<String> = std::env::args().collect();
    if argv.get(1).map(String::as_str) == Some("mint") {
        mint_iat(&argv[2..]).await;
        return;
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
        require_par: false,
        require_pkce: false,
        id_token_signed_response_alg: None,
    };

    // OIDF FAPI 2.0 用クライアント 2 つ（private_key_jwt + PAR + PKCE + DPoP）。
    let fapi_alias = "rustop-fapi2";
    let fapi_redirects = vec![
        format!("https://www.certification.openid.net/test/a/{fapi_alias}/callback"),
        format!("https://www.certification.openid.net/test/a/{fapi_alias}/callback?dummy1=lorem&dummy2=ipsum"),
    ];
    let fapi_client = |id: &str, kid: &str, x: &str, y: &str| Client {
        client_id: id.into(),
        redirect_uris: fapi_redirects.clone(),
        post_logout_redirect_uris: vec![],
        token_endpoint_auth_method: "private_key_jwt".into(),
        client_secret: None,
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        dpop_bound: true,
        jwks: vec![model::JwkPub { kid: kid.into(), x: x.into(), y: y.into() }],
        require_par: true,
        require_pkce: true,
        // FAPI2 は ES256 必須（RS256 不可）。既定 ES256 で良いので None。
        id_token_signed_response_alg: None,
    };

    // FAPI-CIBA 用クライアント（private_key_jwt + signed backchannel request, poll）。
    // DPoP/PAR は使わない（FAPI1-CIBA プロファイル）。鍵は fapi-1 を再利用。
    let fapi_ciba = Client {
        client_id: "fapi-ciba".into(),
        redirect_uris: vec![],
        post_logout_redirect_uris: vec![],
        token_endpoint_auth_method: "private_key_jwt".into(),
        client_secret: None,
        grant_types: vec![
            "urn:openid:params:grant-type:ciba".into(),
            "refresh_token".into(),
        ],
        dpop_bound: false,
        jwks: vec![model::JwkPub {
            kid: std::env::var("FAPI1_KID").as_deref().unwrap_or("fapi-1-key").into(),
            x: std::env::var("FAPI1_X").unwrap_or_default(),
            y: std::env::var("FAPI1_Y").unwrap_or_default(),
        }],
        require_par: false,
        require_pkce: false,
        id_token_signed_response_alg: None,
    };

    // demo-rp / mobile-rp / ciba-rp は実アプリ用で常時登録。
    // ciba-rp は実 CIBA バックエンド（client_secret_basic, DPoP 任意）。conformance とは別。
    let mut provider = Provider::new(issuer.clone())
        .with_base_path(base_path.clone())
        .with_client(demo_rp)
        .with_client(mobile_rp)
        .with_client(ciba_rp);
    // FAPI conformance 用の静的クライアント（既知 id・鍵保持）は
    // CONFORMANCE_CLIENTS_ENABLED のときだけ登録する。実ユーザー機では既定で出さない
    // （= test クライアントの攻撃面を本番から排除）。認定時のみ一時的に有効化する。
    let conformance_clients = std::env::var("CONFORMANCE_CLIENTS_ENABLED")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    if conformance_clients {
        provider = provider
            .with_client(fapi_client(
                "fapi-1",
                std::env::var("FAPI1_KID").as_deref().unwrap_or("fapi-1-key"),
                &std::env::var("FAPI1_X").unwrap_or_default(),
                &std::env::var("FAPI1_Y").unwrap_or_default(),
            ))
            .with_client(fapi_client(
                "fapi-2",
                std::env::var("FAPI2_KID").as_deref().unwrap_or("fapi-2-key"),
                &std::env::var("FAPI2_X").unwrap_or_default(),
                &std::env::var("FAPI2_Y").unwrap_or_default(),
            ))
            .with_client(fapi_ciba);
    }

    // Cloud Run 上 (K_SERVICE あり) では Firestore + Resend を有効化。
    // ローカルは metadata 不達なので無効（LogMailer のまま）。
    if std::env::var("K_SERVICE").is_ok() {
        let project = std::env::var("GCLOUD_PROJECT")
            .or_else(|_| std::env::var("GOOGLE_CLOUD_PROJECT"))
            .unwrap_or_else(|_| "fido2-8b943".into());
        let fs = std::sync::Arc::new(firestore::Firestore::new(project));
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
        // jti リプレイ防止を Firestore に分散化（インスタンス跨ぎで単回を保証）。
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
    if let Err(e) = dcr_store::put_iat(&fs, &hash, &constraints, expires_at).await {
        eprintln!("mint: IAT 保存に失敗: {e}");
        std::process::exit(1);
    }
    println!("initial_access_token:   {raw}");
    println!("token_hash:             {hash}");
    println!("allowed_redirect_hosts: {}", hosts.join(", "));
    println!("allowed_grant_types:    {}", grants.join(", "));
    println!("expires_at:             {expires_at} (epoch, +{ttl_hours}h)");
    eprintln!("注意: 生トークンの表示は一度だけ。この出力は Cloud Logging に残ります。");
}

fn fail(msg: &str) -> ! {
    eprintln!("mint: {msg}");
    std::process::exit(2);
}
