# rust-op

OIDC OP の Rust 実装（authorization code flow + PKCE）。node-oidc-provider の内部分解
（actions / grants / shared / response_modes / adapters）を概念トレイトに写した拡張可能な骨格。

## 構成（概念=トレイト / データ=構造体）

| ファイル | 役割 | 拡張点 |
|---|---|---|
| `auth_checks.rs` | 認可リクエスト検証ステップ | `trait AuthorizationCheck`（順序付き Vec で登録） |
| `grants.rs` | grant_type ごとのトークン発行 | `trait GrantHandler`（refresh_token / ciba を追加） |
| `client_auth.rs` | token endpoint クライアント認証 | `trait ClientAuthMethod`（private_key_jwt 等を追加） |
| `response_mode.rs` | 認可レスポンスの返し方 | `trait ResponseMode`（form_post / jwt を追加） |
| `jws.rs` | 署名（ES256, ピュア Rust p256） | `trait JwsSigner`（RS256 / EdDSA を追加） |
| `store.rs` | 永続化 | `trait Store`（Firestore impl に差し替え） |
| `model.rs` | データ型 | struct / enum |
| `provider.rs` | レジストリ + 配線 | impl を register する起点 |
| `web.rs` | axum エンドポイント | — |

## ローカル実行

```sh
cargo run            # http://localhost:8080
ADDR=0.0.0.0:3000 cargo run
```

## フロー動作確認（PKCE）

discovery / jwks / authorize → interaction → login → resume → token → userinfo が通る。
`curl` での E2E はリポジトリ作成時に確認済み（id_token は ES256 JWS）。

## Cloud Run デプロイ（Firebase Functions は Rust 非対応のため）

Firebase Functions は Rust ランタイムを持たない。現行 TS と同じく **Cloud Run コンテナ**として
デプロイし、Firebase Hosting の rewrite で繋ぐ。ローカル docker は不要（Cloud Build が建てる）。

```sh
gcloud run deploy rust-op \
  --source . \
  --region asia-northeast1 \
  --allow-unauthenticated \
  --set-env-vars ISSUER=https://<your-domain>
```

Firebase Hosting から繋ぐ場合は `firebase.json` の rewrites に Cloud Run サービスを指定:

```json
{
  "hosting": {
    "rewrites": [
      { "source": "/oidc/**", "run": { "serviceId": "rust-op", "region": "asia-northeast1" } }
    ]
  }
}
```

## 次の拡張（trait impl を足すだけ）

- `RefreshTokenGrant` / `CibaGrant` を `GrantHandler` に追加
- `PrivateKeyJwt` を `ClientAuthMethod` に追加（FAPI 2.0）
- DPoP は `AuthorizationCheck`（check_dpop_jkt）+ token 側 binding で
- PAR / request object は authorize 前段の resolver として
