mod auth_checks;
mod ciba;
mod claims;
mod client_auth;
mod context;
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
mod mailer;
mod model;
mod par;
mod provider;
mod registration;
mod request_object;
mod response_mode;
mod sig;
mod store;
mod web;
mod webauthn;

use model::Client;
use provider::Provider;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    // ORIGIN = スキーム+ホスト（例 https://oidc.sonrisa.co.jp）。
    // BASE_PATH = Hosting rewrite のパス接頭辞（例 /roidc）。issuer = ORIGIN + BASE_PATH。
    let origin = std::env::var("ORIGIN").unwrap_or_else(|_| "http://localhost:8080".into());
    let base_path = std::env::var("BASE_PATH").unwrap_or_default();
    let issuer = format!("{origin}{base_path}");

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

    // OIDF Conformance Suite (Basic OP) 用の静的クライアント 2 つ。
    // client_secret_basic。redirect_uri は alias=rustop-basic の suite callback
    // と、一部テストが使う dummy クエリ付きの 2 種を登録する。
    let oidf_alias = "rustop-basic";
    let oidf_redirects = vec![
        format!("https://www.certification.openid.net/test/a/{oidf_alias}/callback"),
        format!("https://www.certification.openid.net/test/a/{oidf_alias}/callback?dummy1=lorem&dummy2=ipsum"),
    ];
    let oidf_client = |id: &str, secret: &str| Client {
        client_id: id.into(),
        redirect_uris: oidf_redirects.clone(),
        post_logout_redirect_uris: vec![],
        token_endpoint_auth_method: "client_secret_basic".into(),
        client_secret: Some(secret.into()),
        grant_types: vec!["authorization_code".into(), "refresh_token".into()],
        dpop_bound: false,
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
        client_secret: Some("ciba-rp-secret".into()),
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

    let mut provider = Provider::new(issuer.clone())
        .with_base_path(base_path.clone())
        .with_client(demo_rp)
        .with_client(mobile_rp)
        .with_client(ciba_rp)
        .with_client(oidf_client("oidf-basic-1", "oidf-basic-secret-1"))
        .with_client(oidf_client("oidf-basic-2", "oidf-basic-secret-2"))
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

    // Cloud Run 上 (K_SERVICE あり) では Firestore + Resend を有効化。
    // ローカルは metadata 不達なので無効（LogMailer のまま）。
    if std::env::var("K_SERVICE").is_ok() {
        let project = std::env::var("GCLOUD_PROJECT")
            .or_else(|_| std::env::var("GOOGLE_CLOUD_PROJECT"))
            .unwrap_or_else(|_| "fido2-8b943".into());
        let fs = std::sync::Arc::new(firestore::Firestore::new(project));
        // 署名鍵を Secret Manager から固定（無ければ起動ごとの一時鍵にフォールバック）。
        // インスタンス跨ぎ・再起動で kid を保つために必須。
        match fs.access_secret("oidc-signing-key-es256").await {
            Ok(Some(scalar)) => match jws::Es256Signer::from_scalar_b64(&scalar) {
                Ok(signer) => {
                    tracing::info!("loaded ES256 signing key from Secret Manager");
                    provider = provider.with_signer(std::sync::Arc::new(signer));
                }
                Err(e) => {
                    tracing::error!("signing key from secret invalid ({e}); using ephemeral key")
                }
            },
            Ok(None) => tracing::warn!("signing key secret not found; using ephemeral key"),
            Err(e) => tracing::error!("secret access failed ({e}); using ephemeral key"),
        }
        // RS256 署名鍵（OIDC Core §15.1 で必須）を Secret Manager から固定ロード。
        // 無ければ起動ごとの一時鍵（jwks がインスタンス毎に変わる点に注意）。
        match fs.access_secret("oidc-signing-key-rs256").await {
            Ok(Some(pem)) => match jws::Rs256Signer::from_pkcs8_pem(&pem) {
                Ok(signer) => {
                    tracing::info!("loaded RS256 signing key from Secret Manager");
                    provider = provider.add_signer(std::sync::Arc::new(signer));
                }
                Err(e) => tracing::error!("RS256 key from secret invalid ({e}); skipping RS256"),
            },
            Ok(None) => {
                tracing::warn!("RS256 key secret not found; generating ephemeral RS256 key");
                provider = provider.add_signer(std::sync::Arc::new(jws::Rs256Signer::generate()));
            }
            Err(e) => tracing::error!("RS256 secret access failed ({e}); skipping RS256"),
        }
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
