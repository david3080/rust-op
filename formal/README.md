# formal/ — rust-op のプロトコルを Tamarin で検証する

[`docs/security-ladder.md`](../docs/security-ladder.md) の「検証アーキテクチャ」の実体。
**プロトコル論理層**を記号的（Dolev-Yao 攻撃者）に検証し、各性質を支える**前提を表に出す**。
前提（抽象）→ rust-op の担保（具体）への対応づけが、この層の成果物。

## 実行

```sh
brew install tamarin-prover          # maxima/graphviz 等も入る
tamarin-prover --prove formal/oauth_code_pkce.spthy
# 対話GUIで眺める場合:
tamarin-prover interactive formal/oauth_code_pkce.spthy   # → http://127.0.0.1:3001
```

第一版は `sources`/`reuse` 補題が要る場合がある（open-chain や非終了が出たら追加して iterate）。
**「Tamarin が詰まる = 足りない前提が見える」こと自体が収穫**であって、最初から完璧な証明である必要はない。

## モデル #1: 認可コード + PKCE + クライアント認証 → トークン

対象は confidential client（private_key_jwt 相当 = DCR/FAPI クライアント）。フロー:

1. クライアントが `~v`(code_verifier) を生成し、`h(~v)`(code_challenge) を**フロントチャネル**（攻撃者可視）で送る
2. AS が認可コード `~code` を発行し redirect（攻撃者は code を**横取りできる**）
3. クライアントが code + `~v` + 署名(client_assertion) で**トークン要求**
4. AS が **code 単回消費 + クライアント認証 + PKCE(`h(v)=challenge`)** を検査し、トークンを**クライアント鍵へ暗号化(TLS抽象)** して配送

### 検証する性質（lemma）
| lemma | 主張 | 意味 |
|---|---|---|
| `executable` | 正直な実行が完了しうる | モデルが死んでいないことの健全性チェック |
| `code_single_use` | 同じ code から2トークンは出ない | 認可コードの単回性 |
| `token_secrecy` | 攻撃者は honest client のトークンを知り得ない（鍵漏洩がなければ） | 回線支配攻撃者への耐性 |

## 検証結果（Tamarin 1.12.0 / maude 3.5.1, 2026-06-09 実測）

- `tamarin-prover --prove --auto-sources formal/oauth_code_pkce.spthy`
  → **3 lemma すべて verified**（処理 ~0.6s、wellformedness 全合格、追加 sources 補題は不要）。
  = 前提集合 {P-SINGLEUSE, P-VERIFIER, P-CKEY, P-REG, P-TLS} の下で、回線支配攻撃者に対し性質が**十分**に成り立つ。
  `token_secrecy` の証明は「攻撃者がトークンを知る唯一の道はクライアント鍵の Reveal」を示す＝**P-CKEY の必要性**を裏取り。
- **必要性の実験**: `oauth_code_NEG_no_singleuse.spthy`（`AS_Code` を persistent にして単回消費を外した変種）
  → `code_single_use` が **falsified（攻撃トレース発見）**、`token_secrecy` は verified のまま。
  = **原子的単回消費（P-SINGLEUSE）は“必要”**。外すと同一コードから2トークン（トークン要求のリプレイ）。
    単回性の役割は**コード再利用の阻止に特定**される（token_secrecy には影響しない）。
  = 段0「引換券は一度きり」の、**機械検証された必要十分**。
- 注: 本版は confidential client で client認証とPKCEが両方あり（多層防御）。**PKCE の個別の必要性**を示すには
  public client 変種（client認証を外しPKCEのみ）が次。

## 表に出た前提 → rust-op の担保（本層の成果物）

| ID | モデルが要求する前提（抽象） | rust-op の担保（具体） |
|---|---|---|
| P-SINGLEUSE | 認可コードは**原子的に単回消費**される（`AS_Code` が linear） | store の code 消費（単回）。回帰テスト `store::code_reuse_revokes_issued_tokens` |
| P-CODEFRESH | 認可コードは**推測不能**（CSPRNG = Fr） | code 生成（乱数） |
| P-VERIFIER | PKCE の verifier は**秘密**で、`h(verifier)=challenge` を AS が検査 | `CheckPkce`（S256 のみ受理、`auth_checks.rs`） |
| P-CKEY | クライアント秘密鍵は**秘匿**（漏れると token_secrecy が破れる） | private_key_jwt（`client_auth.rs`）。rust-op は**公開鍵のみ保持** |
| P-REG | クライアントは**事前登録**され AS が公開鍵を知る | `with_client` / DCR（`clients` 登録、`resolve_client`） |
| P-TLS | トークン配送路は**機密**で正しいクライアントへ届く（モデルでは鍵への暗号化で抽象化） | TLS（Firebase Hosting / Cloud Run）＋ token endpoint |
| （攻撃者モデル） | In/Out を完全支配する回線攻撃者に耐える | — |

→ 「**`token_secrecy` は、攻撃者X(回線支配)に対し、前提 {P-SINGLEUSE, P-VERIFIER, P-CKEY, P-REG, P-TLS} の下で成り立つ**」。
これが目標「前提の明示」の1行。

## このモデルが示す“設計の洞察”

- **confidential client では、クライアント認証 と PKCE の両方が攻撃を止め、どちらか一方でも交換を阻止できる（多層防御）。**
  PKCE が**主役（必要）になるのは public client（クライアント認証なし）**の場合。→ 次版で public client を別 variant としてモデル化すると「PKCE の必要性」が見える。
- **単回性の必要性**は `token_secrecy` ではなく `code_single_use` に現れる。`AS_Code` を persistent にすると `code_single_use` が破れる（手元で試すと良い）。
- redirect_uri 完全一致は本版では未モデル（code 横取りは前提し、交換を client 認証+PKCE で阻止）。次版で redirect を明示するとコード**配送先**の制御が入る。

## 既知の限界 / 次版（ロードマップ）

- ユーザ認証/同意は抽象化（**WebAuthn は roadmap #4**）。
- public client（client auth 無し・PKCE 主役）は別 variant（次版）。
- TLS は「クライアント鍵への暗号化」で抽象化（実 TLS はサーバ認証）。次版で TLS セッションを明示。
- 第一版の lemma は `sources`/`reuse` 補題が要る場合あり。

ロードマップ（[`docs/security-ladder.md`](../docs/security-ladder.md) の「Tamarin モデリング・ロードマップ」）:
**#1 認可コード+PKCE（本ファイル）→ #2 DPoP 送り主束縛 → #3 CIBA+RAR マンデート → #4 WebAuthn → #5 ID token → #6 合成**。
各モデルが「防げる攻撃＋必要前提」を1セット産み、積むほど rust-op の前提集合が埋まる。
