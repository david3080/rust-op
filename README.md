# rust-op

**ピュア Rust 製の OpenID Provider (OP) + FIDO2 Server。** FAPI 2.0 Security Profile に準拠し、
パスキー（WebAuthn）認証・CIBA・制御付き動的クライアント登録（DCR）を備える。WebAuthn / 署名 /
証明書検証は OpenSSL/ring に依存せず RustCrypto で自作（`openssl = 0`）。Google Cloud Run への
デプロイを想定（issuer はカスタムドメイン + `BASE_PATH`）。

- **OIDF FIDO2 Server Conformance: 155/155 PASS**（全 attestation 形式 + MDS3 + 失効まで網羅）
- **FAPI 2.0 Security Profile**: 実装起因の失敗ゼロ（残りは Cloud Run の TLS 制約のみ）
- 設計思想: **コンセプト駆動のトレイトレジストリ**。新機能 = 新しい trait impl を Provider に register するだけ。

---

## アーキテクチャ

node-oidc-provider の内部分解（actions / grants / client_auth / response_modes / adapters）を
**概念トレイト + 実装群**に写し、`Provider` のレジストリに差し替え可能な形で保持する。

```
リクエスト
   │  axum (web/)
   ▼
Provider ── checks:    Vec<dyn AuthorizationCheck>   （順序が意味を持つ検証ステップ）
         ── grants:    Map<dyn GrantHandler>          （authorization_code / refresh_token / ciba）
         ── client_auth: Map<dyn ClientAuthMethod>    （none / client_secret_basic / private_key_jwt）
         ── response_modes: Map<dyn ResponseMode>     （query …）
         ── signer:    dyn JwsSigner (+ extra_signers) （ES256 既定 / RS256。本番は Cloud KMS）
         ── store:     dyn Store                      （MemoryStore / FirestoreStore）
         ── dpop:      dyn DpopVerifier               （RFC 9449）
         ── ciba:      dyn CibaStore
```

| 拡張点（trait） | 役割 | 実装 |
|---|---|---|
| `AuthorizationCheck` | `/authorize` の検証ステップ | CheckClient / CheckRedirectUri / CheckResponseType / CheckScope / CheckPkce |
| `GrantHandler` | grant_type ごとのトークン発行 | AuthorizationCode / RefreshToken（rotation）/ Ciba |
| `ClientAuthMethod` | token endpoint のクライアント認証 | None / ClientSecretBasic / PrivateKeyJwt（ES256, FAPI） |
| `ResponseMode` | 認可レスポンスの返し方 | Query |
| `JwsSigner` | id_token / JWS 署名 | Es256Signer / Rs256Signer / KmsSigner（Cloud KMS） |
| `Store` | セッション・コード・トークン永続化 | MemoryStore（ローカル）/ FirestoreStore（本番） |
| `DpopVerifier` / `CibaStore` / `Mailer` / `FidoStore` | DPoP / CIBA / メール / FIDO 永続化 | in-memory ↔ Firestore を K_SERVICE で切替 |

---

## 実装済みの標準

### OIDC / OAuth 2.0
- Authorization Code Flow + **PKCE（S256 のみ。plain は拒否）**
- Refresh Token（DPoP 束縛 + ローテーション、系列失効）
- ID Token（**ES256 既定 + RS256**。OIDC Core §15.1 対応）、UserInfo、Introspection、Revocation
- RP-Initiated Logout（`end_session`、post_logout_redirect_uri は登録値のみ許可）
- claims（scope→claim マッピング: profile / email / address / phone）

### FAPI 2.0 Security Profile
- **PAR**（RFC 9126, pushed authorization request、60s 単回）
- **DPoP**（RFC 9449, jti 単回・iat 窓・htu/htm/ath・jkt 束縛）
- **private_key_jwt**（RFC 7523, ES256。jwks_uri 解決 + TTL キャッシュ）
- **JAR**（RFC 9101, 署名済み request object。alg は ES256 固定で `none` 拒否）
- **RFC 9207** authorization response iss
- RAR mandate（authorization_details を opaque token に束縛、`/oauth/mandate/consume` で単回消費）
- Step Up Authentication Challenge（RFC 9470）

### CIBA（バックチャネル認証）
- poll mode、**パスキー承認**（UV 必須・先勝ち CAS）、**FCM プッシュ**で iPhone へ通知
- dedup + レート制限

### 制御付き DCR（RFC 7591）
- **private_key_jwt 専用**（OP に client_secret を持たせない）、jwks 必須、redirect は https + ホスト許可リスト
- Initial Access Token（IAT）必須。`mint` / `revoke-client` 管理サブコマンド
- conformance 用の reusable IAT（短 TTL・期限内多回）

### 認証
- **WebAuthn パスキー**（`webauthn.rs`、ES256 自作検証コア）。本番ログインの主経路
- メール確認登録（Resend）、a/a バイパスは廃止

### FIDO2 Server Conformance（`/fido` 面。本番ログインとは独立）
- 全 attestation 形式: none / packed（self/full）/ fido-u2f / tpm / android-key / apple
- multi-alg: ES256 / RS256 / RS1 / Ed25519
- **MDS3**（メタデータ BLOB の JWS + 証明書チェーン検証、ステータス照合、CRL 失効）

---

## エンドポイント

| 種別 | パス |
|---|---|
| Discovery / JWKS | `GET /.well-known/openid-configuration`, `GET /jwks` |
| 認可 | `GET /authorize`, `GET /authorize/resume`, `POST /par` |
| ログイン（パスキー） | `GET /login/{uid}`, `POST /login/{uid}/passkey/options`, `.../verify` |
| トークン | `POST /token`, `POST /introspect`, `POST /revoke` |
| UserInfo / プロフィール | `GET\|POST /userinfo`, `GET\|PUT /me/profile` |
| ログアウト | `GET /end-session` |
| DCR | `POST /oauth/register` |
| Mandate | `POST /oauth/mandate/consume` |
| CIBA | `POST /backchannel-authentication`, `GET /ciba`, `POST /ciba/{id}/approve\|reject`, `/ciba/fcm-tokens` |
| 登録 | `GET\|POST /signup`, `/signup/verify`, `/signup/passkey/*` |
| デモ | `GET /`, `GET /callback` |
| FIDO Conformance | `POST /fido/attestation/options\|result`, `/fido/assertion/options\|result`, `/fido/mds/config` |

issuer = `ORIGIN + BASE_PATH`（例: `https://<issuer-host>` + `/oidc`）。

---

## 暗号（ピュア Rust）

- 依存: `p256` / `p384` / `rsa` / `ed25519-dalek` / `sha2` / `sha1` / `ciborium` / `x509-cert`（**全て RustCrypto 系・openssl/ring 非依存**）
- 署名は **Cloud KMS**（`KmsSigner`、秘密鍵をプロセスに展開しない）。本番で正規鍵をロードできなければ起動中止
- **alg 混同対策**: DPoP / private_key_jwt / JAR は全て `alg == "ES256"` 固定で `none` 含め拒否
- 署名プリミティブは `es256.rs` / `sig.rs` に集約（署名 vs 検証、DER vs raw を用途別に分離）

---

## ローカル実行

```sh
cargo run                                   # http://localhost:8080
ADDR=127.0.0.1:8099 cargo run               # ポート指定（IPv4/IPv6 両 loopback で待受）
```

ローカルでは Firestore / Resend / KMS は無効（in-memory + LogMailer、起動毎の一時署名鍵）。
本番機能は `K_SERVICE`（Cloud Run）検出時のみ有効化される。

### FIDO2 Conformance をローカルで動かす

```sh
ADDR=127.0.0.1:8099 FIDO_RP_ID=localhost FIDO_ORIGIN=http://localhost:8099 \
  FIDO_CONFORMANCE_ENABLED=1 cargo run
# 公式 Conformance Tool の Server URL = http://localhost:8099/fido
```

---

## テスト / 品質保証

```sh
cargo test                                  # 194 ユニット + fuzz + 差分テスト
PROPTEST_CASES=30000 cargo test fuzz_tests  # 重いファジング（約42万入力）
cargo kani                                  # 9 つの形式証明（cargo-kani 要）
cargo deny check                            # 供給網（RUSTSEC 勧告 / ライセンス）
```

| 種別 | 内容 |
|---|---|
| ユニットテスト | 194 件（各 trait impl / 検証ロジック） |
| **ファジング**（`fuzz_tests.rs`） | proptest で攻撃者入力パーサの **panic 安全性**（authData / COSE / attestation / b64 / 署名） |
| **差分テスト**（`diff_tests.rs`） | 独立実装 `coset` をオラクルに COSE 鍵抽出（ES256 / Ed25519）を突合 |
| **形式検証**（`kani_harness.rs`） | Kani で手書きバイト演算の全入力安全性（pad32 / parse_auth_data / credId 境界 / PKCE no-downgrade / redirect 完全一致 等） |
| 静的 | `#![forbid(unsafe_code)]`（Kani ハーネスのみ例外）、`deny.toml` + CI、clippy 警告ゼロ |
| Conformance | FIDO2 Server 155/155（公式ツール）、FAPI2（実装起因失敗ゼロ） |

---

## 設定（環境変数）

| 変数 | 用途 |
|---|---|
| `ORIGIN` | スキーム+ホスト（例 `https://<issuer-host>`） |
| `BASE_PATH` | パス接頭辞（例 `/oidc`）。issuer = ORIGIN + BASE_PATH |
| `GCLOUD_PROJECT` / `GOOGLE_CLOUD_PROJECT` | Firestore / KMS のプロジェクト |
| `PORT` / `ADDR` | 待受ポート（Cloud Run は PORT、ローカルは ADDR） |
| `KMS_ES256_KEY` / `KMS_RS256_KEY` | Cloud KMS 署名鍵（無ければ Secret Manager にフォールバック） |
| `FIDO_RP_ID` / `FIDO_ORIGIN` / `FIDO_RP_NAME` | FIDO/WebAuthn の RP 設定 |
| `FIDO_CONFORMANCE_ENABLED` | `/fido` conformance 面の有効化 |
| `CIBA_RP_SECRET` | CIBA クライアントの secret |
| `RESEND_API_KEY` | メール送信（Secret Manager） |
| `FAPI1_X/Y/KID` / `FAPI2_X/Y/KID` | FAPI2 conformance 静的クライアント `fapi-1`/`fapi-2` の公開鍵（**設定時のみ登録 = ON/OFF 切替**） |
| `CONFORMANCE_FAPI_CALLBACK` | FAPI conformance の redirect 上書き |
| `LOG_PSEUDONYM_KEY` | ログ内 sub の擬似化キー |

`K_SERVICE` は Cloud Run が自動設定（本番機能の有効化トリガ）。

---

## 静的クライアント

| client_id | 認証方式 | 用途 |
|---|---|---|
| `demo-rp` | public + PKCE + DPoP | 内蔵デモ |
| `mobile-rp` | public + PKCE + DPoP | Flutter モバイルアプリ（custom scheme redirect） |
| `ciba-rp` | client_secret_basic | CIBA Consumption Device |
| `fapi-1` / `fapi-2` | private_key_jwt + PAR + PKCE + DPoP | FAPI2 conformance（env 設定時のみ） |
| `dcr-*` | private_key_jwt | DCR で動的登録（Firestore 永続化） |

---

## デプロイ（Cloud Run）

Firebase Functions は Rust ランタイムを持たないため Cloud Run コンテナとしてデプロイする。
ローカル docker は不要（Cloud Build が Dockerfile をビルド）。env / シークレットは再デプロイで保持される。

```sh
gcloud run deploy <service> --source . --region <region>
```

- デプロイ先: 任意の GCP プロジェクト / region / Cloud Run サービス
- issuer のカスタムドメインは Cloud Run ドメインマッピングで直結。保護対象のリソースサーバ等は別サービスとして分離
- 署名鍵 / Firestore は専用の **runtime サービスアカウント**（`cloudkms.signerVerifier` + `datastore.user`）で利用。本番で正規鍵をロードできなければ起動中止

---

## リポジトリ構成

```
src/
  main.rs            起動・クライアント登録・KMS/Firestore 配線・mint/revoke サブコマンド
  provider.rs        トレイトレジストリ本体
  auth_checks.rs     AuthorizationCheck 群
  grants.rs          GrantHandler 群（code / refresh / ciba）
  client_auth.rs     ClientAuthMethod 群（none / basic / private_key_jwt）
  response_mode.rs   ResponseMode
  par.rs / request_object.rs / dpop.rs / step_up.rs   FAPI2 要素
  ciba.rs / fcm.rs   CIBA + プッシュ
  dcr.rs / dcr_store.rs   制御付き DCR
  webauthn.rs        パスキー検証コア（本番ログイン）
  registration.rs / interaction_policy.rs / claims.rs
  es256.rs / sig.rs / jws.rs / kms.rs   署名・暗号プリミティブ
  store.rs / firestore_store.rs / firestore.rs / nonce.rs / model.rs / error.rs
  jwks_resolver.rs / mailer.rs / context.rs
  fido/              FIDO2 Server Conformance（verify / tpm / mds / store）
  web/               axum エンドポイント（oidc / ciba / login / register / pages）
  fuzz_tests.rs / diff_tests.rs / kani_harness.rs   品質保証（通常ビルド非対象）
```

---

## ライセンス

**MIT License**（[`LICENSE`](./LICENSE)）。

rust-op は独立した Rust 実装で、他プロジェクトのソースコードを複製していません。アーキテクチャの
着想元・検証オラクル（node-oidc-provider / SimpleWebAuthn / webauthn-rs など）への謝辞は
[`CREDITS.md`](./CREDITS.md)、実行時依存 crate の SPDX ライセンス一覧は
[`THIRD-PARTY-LICENSES.md`](./THIRD-PARTY-LICENSES.md) を参照。
