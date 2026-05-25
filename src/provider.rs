//! Provider 本体。差し替え可能な実装をレジストリに保持する。
//! 新機能 = 新しい trait impl を register するだけ、が拡張の基本方針。

use crate::auth_checks::*;
use crate::client_auth::*;
use crate::dpop::{DpopVerifier, Es256Dpop};
use crate::firestore::Firestore;
use crate::grants::*;
use crate::jws::{Es256Signer, JwsSigner};
use crate::mailer::{LogMailer, Mailer};
use crate::model::Client;
use crate::response_mode::*;
use crate::store::{MemoryStore, Store};
use std::collections::HashMap;
use std::sync::Arc;

pub struct Provider {
    pub issuer: String,
    /// 外部 URL のパス接頭辞（例 "/rust-oidc"）。Hosting rewrite はパスを保持して
    /// 転送するので、内部リダイレクトの Location もこの接頭辞を付ける必要がある。
    pub base_path: String,
    /// 固定ログイン資格情報（PoC）。
    pub demo_user: String,
    pub demo_pass: String,
    pub store: Arc<dyn Store>,
    pub signer: Arc<dyn JwsSigner>,
    /// メール確認登録用（Cloud Run 上でのみ Some）。
    pub firestore: Option<Arc<Firestore>>,
    pub mailer: Arc<dyn Mailer>,
    pub dpop: Arc<dyn DpopVerifier>,
    pub clients: HashMap<String, Client>,
    /// 順序が意味を持つので Vec。
    pub checks: Vec<Arc<dyn AuthorizationCheck>>,
    pub grants: HashMap<String, Arc<dyn GrantHandler>>,
    pub client_auth: HashMap<String, Arc<dyn ClientAuthMethod>>,
    pub response_modes: HashMap<String, Arc<dyn ResponseMode>>,
}

impl Provider {
    pub fn new(issuer: impl Into<String>) -> Self {
        let checks: Vec<Arc<dyn AuthorizationCheck>> = vec![
            Arc::new(CheckClient),
            Arc::new(CheckRedirectUri),
            Arc::new(CheckResponseType),
            Arc::new(CheckScope),
            Arc::new(CheckPkce),
        ];

        let mut grants: HashMap<String, Arc<dyn GrantHandler>> = HashMap::new();
        register_grant(&mut grants, Arc::new(AuthorizationCodeGrant));
        register_grant(&mut grants, Arc::new(RefreshTokenGrant));
        register_grant(&mut grants, Arc::new(CibaGrant));

        let mut client_auth: HashMap<String, Arc<dyn ClientAuthMethod>> = HashMap::new();
        register_auth(&mut client_auth, Arc::new(NoneAuth));
        register_auth(&mut client_auth, Arc::new(ClientSecretBasic));
        register_auth(&mut client_auth, Arc::new(ClientSecretPost));
        register_auth(&mut client_auth, Arc::new(PrivateKeyJwt::default()));

        let mut response_modes: HashMap<String, Arc<dyn ResponseMode>> = HashMap::new();
        let q: Arc<dyn ResponseMode> = Arc::new(QueryMode);
        response_modes.insert(q.name().to_string(), q);

        Self {
            issuer: issuer.into(),
            base_path: String::new(),
            demo_user: "a".into(),
            demo_pass: "a".into(),
            store: Arc::new(MemoryStore::default()),
            signer: Arc::new(Es256Signer::generate()),
            firestore: None,
            mailer: Arc::new(LogMailer),
            dpop: Arc::new(Es256Dpop::default()),
            clients: HashMap::new(),
            checks,
            grants,
            client_auth,
            response_modes,
        }
    }

    pub fn with_client(mut self, c: Client) -> Self {
        self.clients.insert(c.client_id.clone(), c);
        self
    }

    pub fn with_base_path(mut self, base_path: impl Into<String>) -> Self {
        self.base_path = base_path.into();
        self
    }

    pub fn with_firestore(mut self, fs: Arc<Firestore>) -> Self {
        self.firestore = Some(fs);
        self
    }

    pub fn with_store(mut self, store: Arc<dyn Store>) -> Self {
        self.store = store;
        self
    }

    pub fn with_signer(mut self, signer: Arc<dyn JwsSigner>) -> Self {
        self.signer = signer;
        self
    }

    pub fn with_mailer(mut self, m: Arc<dyn Mailer>) -> Self {
        self.mailer = m;
        self
    }

    /// base_path を付けた内部リダイレクト用パス。
    pub fn path(&self, suffix: &str) -> String {
        format!("{}{}", self.base_path, suffix)
    }

    /// WebAuthn origin（scheme://host[:port]、パスなし）。
    pub fn origin(&self) -> String {
        let scheme = self.issuer.split("://").next().unwrap_or("https");
        let after = self.issuer.split("://").nth(1).unwrap_or(&self.issuer);
        let host_port = after.split('/').next().unwrap_or(after);
        format!("{scheme}://{host_port}")
    }

    /// WebAuthn rp_id（ホスト名のみ、ポートなし）。
    pub fn rp_id(&self) -> String {
        let after = self.issuer.split("://").nth(1).unwrap_or(&self.issuer);
        let host_port = after.split('/').next().unwrap_or(after);
        host_port.split(':').next().unwrap_or(host_port).to_string()
    }
}

fn register_grant(m: &mut HashMap<String, Arc<dyn GrantHandler>>, g: Arc<dyn GrantHandler>) {
    m.insert(g.grant_type().to_string(), g);
}
fn register_auth(m: &mut HashMap<String, Arc<dyn ClientAuthMethod>>, a: Arc<dyn ClientAuthMethod>) {
    m.insert(a.method().to_string(), a);
}
