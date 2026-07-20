//! Provider 本体。差し替え可能な実装をレジストリに保持する。
//! 新機能 = 新しい trait impl を register するだけ、が拡張の基本方針。

use crate::auth_checks::*;
use crate::ciba::{CibaRateLimiter, CibaStore, MemoryCibaStore};
use crate::client_auth::*;
use crate::dpop::{DpopVerifier, Es256Dpop};
use crate::error::OAuthError;
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
    pub store: Arc<dyn Store>,
    /// 既定の署名鍵（ES256）。client が alg を指定しない場合に使う。
    pub signer: Arc<dyn JwsSigner>,
    /// 追加の署名鍵（RS256 等）。jwks 公開と alg 選択に使う。
    pub extra_signers: Vec<Arc<dyn JwsSigner>>,
    /// メール確認登録用（Cloud Run 上でのみ Some）。
    pub firestore: Option<Arc<Firestore>>,
    /// CIBA バックチャネル要求の永続化。既定は In-memory、本番は Firestore 実装を注入する。
    pub ciba: Arc<dyn CibaStore>,
    /// CIBA の (client_id, account) ごとレート制限。push スパム抑止のバックストップ。
    pub ciba_rate: Arc<CibaRateLimiter>,
    /// 登録メール送信のレート制限（email / IP ごと）。無認証メール乱用のバックストップ。
    pub register_rate: Arc<CibaRateLimiter>,
    pub mailer: Arc<dyn Mailer>,
    pub dpop: Arc<dyn DpopVerifier>,
    /// JAR (request object) の jti 単回ストア。本番は Firestore（with_firestore で注入）。
    pub jar_jti: crate::nonce::NonceStore,
    pub clients: HashMap<String, Client>,
    /// Phase 1（client 解決 + redirect 検証後）のポリシーチェック群。相互に可換なので
    /// 順序は自由。client 解決と redirect 検証は auth_checks::resolve_addressee に固定。
    pub checks: Vec<Arc<dyn AuthorizationCheck>>,
    pub grants: HashMap<String, Arc<dyn GrantHandler>>,
    pub client_auth: HashMap<String, Arc<dyn ClientAuthMethod>>,
    pub response_modes: HashMap<String, Arc<dyn ResponseMode>>,
    /// private_key_jwt クライアントの jwks_uri から鍵を取得・キャッシュする（鍵ローテーション）。
    pub jwks_resolver: crate::jwks_resolver::JwksResolver,
}

impl Provider {
    pub fn new(issuer: impl Into<String>) -> Self {
        let checks: Vec<Arc<dyn AuthorizationCheck>> = vec![
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
        register_auth(&mut client_auth, Arc::new(PrivateKeyJwt::default()));

        let mut response_modes: HashMap<String, Arc<dyn ResponseMode>> = HashMap::new();
        let q: Arc<dyn ResponseMode> = Arc::new(QueryMode);
        response_modes.insert(q.name().to_string(), q);

        Self {
            issuer: issuer.into(),
            base_path: String::new(),
            store: Arc::new(MemoryStore::default()),
            signer: Arc::new(Es256Signer::generate()),
            extra_signers: Vec::new(),
            firestore: None,
            mailer: Arc::new(LogMailer),
            ciba: Arc::new(MemoryCibaStore::default()),
            ciba_rate: Arc::new(CibaRateLimiter::default()),
            // 1 時間に 5 通まで（同一 email / 同一 IP）。正常な登録では超えない。
            register_rate: Arc::new(CibaRateLimiter::new(std::time::Duration::from_secs(3600), 5)),
            dpop: Arc::new(Es256Dpop::default()),
            jar_jti: crate::nonce::NonceStore::memory(),
            clients: HashMap::new(),
            checks,
            grants,
            client_auth,
            response_modes,
            jwks_resolver: crate::jwks_resolver::JwksResolver::new(),
        }
    }

    pub fn with_client(mut self, c: Client) -> Self {
        self.clients.insert(c.client_id.clone(), c);
        self
    }

    /// client_id を解決する。静的登録(HashMap)を先に見て、無ければ Firestore の
    /// DCR 登録クライアントへフォールバックする。未知なら None。
    ///
    /// 注意: 静的クライアントは HashMap で即解決されるが、未知 id は Firestore への
    /// 1 read を引く。/authorize・/end_session など無認証面でも引かれるため、
    /// 未知 id の point-read 増は許容する前提（攻撃面メモは PR 説明参照）。
    pub async fn resolve_client(&self, id: &str) -> Option<Client> {
        if let Some(c) = self.clients.get(id) {
            return Some(c.clone());
        }
        let fs = self.firestore.as_ref()?;
        crate::dcr_store::load_client(fs, id).await
    }

    pub fn with_base_path(mut self, base_path: impl Into<String>) -> Self {
        self.base_path = base_path.into();
        self
    }

    pub fn with_firestore(mut self, fs: Arc<Firestore>) -> Self {
        // JAR jti もインスタンス跨ぎで単回化する（DPoP / client_assertion と同様）。
        self.jar_jti = crate::nonce::NonceStore::firestore(fs.clone());
        self.firestore = Some(fs);
        self
    }

    pub fn with_ciba(mut self, ciba: Arc<dyn CibaStore>) -> Self {
        self.ciba = ciba;
        self
    }

    pub fn with_store(mut self, store: Arc<dyn Store>) -> Self {
        self.store = store;
        self
    }

    /// DPoP 検証器を差し替える（本番は Firestore 連携で jti を分散単回化）。
    pub fn with_dpop(mut self, dpop: Arc<dyn DpopVerifier>) -> Self {
        self.dpop = dpop;
        self
    }

    /// 追加の署名鍵（RS256 等）を登録する。
    pub fn add_signer(mut self, signer: Arc<dyn JwsSigner>) -> Self {
        self.extra_signers.push(signer);
        self
    }

    /// alg に対応する署名鍵を返す。None（未指定）は既定（ES256）。
    /// 未対応の alg は既定へ黙ってフォールバックせずエラーにする。フォールバックは
    /// switch の default が新種を吸い込むのと同型の暗黙バグで、RP 側の検証失敗として
    /// 遅れて表面化する。登録値と実際の署名 alg の不一致はここで即座に落とす。
    pub fn signer_for(&self, alg: Option<&str>) -> Result<&Arc<dyn JwsSigner>, OAuthError> {
        match alg {
            None => Ok(&self.signer),
            Some(a) if a == self.signer.alg() => Ok(&self.signer),
            Some(a) => self
                .extra_signers
                .iter()
                .find(|s| s.alg() == a)
                .ok_or_else(|| {
                    OAuthError::ServerError(format!("no signer registered for alg {a}"))
                }),
        }
    }

    /// jwks / discovery 用に全署名鍵を列挙する。
    pub fn all_signers(&self) -> impl Iterator<Item = &Arc<dyn JwsSigner>> {
        std::iter::once(&self.signer).chain(self.extra_signers.iter())
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signer_for_rejects_unregistered_alg_instead_of_fallback() {
        let p = Provider::new("https://op");
        // None / 既定 alg は既定署名鍵。
        assert!(p.signer_for(None).is_ok());
        assert!(p.signer_for(Some("ES256")).is_ok());
        // 未登録 alg は黙って ES256 にフォールバックせずエラー。
        assert!(matches!(
            p.signer_for(Some("PS256")),
            Err(crate::error::OAuthError::ServerError(_))
        ));
    }
}
